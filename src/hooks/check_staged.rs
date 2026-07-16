//! `aperion-shield --check-staged` — run the engine over the lines a
//! commit is about to add or modify, refuse the commit if any line
//! trips a Block-severity rule.
//!
//! ## What it inspects
//!
//! Only file extensions that historically generate destructive ops:
//!
//! | Extension                          | Scope mapped to              |
//! |------------------------------------|------------------------------|
//! | `.sql`                             | `execute_sql` tool-call      |
//! | `.sh`, `.bash`, `.zsh`, `Makefile` | `shell` tool-call            |
//! | `Dockerfile`                       | `shell` tool-call (RUN ...)  |
//! | other (`.py`, `.js`, `.ts`, ...)   | `llm_response` text scope    |
//!
//! Files outside this whitelist are skipped; we deliberately do NOT lint
//! every README, every JSON config, every test fixture. The cost of a
//! false positive in a pre-commit hook is *very high* (it stops the
//! developer cold and trains them to `--no-verify`); the cost of a
//! false negative is bounded (the call still has to execute somewhere
//! and Shield's MCP path will catch it). So we err on precision.
//!
//! ## What it skips (intentional)
//!
//! - Removed files & deleted lines. We're protecting against newly
//!   *introduced* destructive code, not historical deletion.
//! - Binary blobs.
//! - Files larger than 256 KB (a heuristic — agent-generated
//!   migrations and shell scripts are tiny; oversize is almost always
//!   data).
//! - Lines that are pure whitespace or pure comments.
//!
//! ## Exit codes
//!
//! Matches the documented hook contract — see `docs/hooks.md`:
//!
//! | Code | Meaning                                                  |
//! |------|----------------------------------------------------------|
//! | 0    | No blocking matches. Commit proceeds.                    |
//! | 1    | At least one Block-severity match. Commit refused.       |
//! | 2    | At least one Approval-severity match (pre-commit can't   |
//! |      | prompt, so we surface this as a refusal with a note).    |
//! | 3    | Operational error (git not on PATH, not in a repo, ...). |
//!
//! `SHIELD_HOOKS_DISABLE=1` short-circuits this entire function to
//! exit 0 before any work happens — handled by the hook script, not
//! here, so the env override is visible in `--check-staged` too (e.g.
//! when invoked manually for debugging).

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use crate::engine::Engine;
use crate::{decide, Adjustments, BurstDetector, Decision, TaintLedger, WorkspaceContext};

const MAX_FILE_SIZE_BYTES: u64 = 256 * 1024;

/// One scanner finding, surfaced to the user in the pre-commit error
/// banner. Kept granular so we can group by rule_id for readability.
#[derive(Debug, Clone)]
pub struct StagedFinding {
    pub file: String,
    pub line_no: usize,
    pub line: String,
    pub rule_id: String,
    pub severity: String,
    pub decision: String,
    pub reason: String,
    pub safer_alternative: Option<String>,
}

/// Aggregate of a `--check-staged` run, returned to the CLI dispatcher.
#[derive(Debug, Default)]
pub struct CheckStagedReport {
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub findings: Vec<StagedFinding>,
    /// Highest decision class we saw (None if nothing matched at all).
    pub worst_decision: Option<Decision>,
}

impl CheckStagedReport {
    /// Decide the process exit code per the table at the top of the
    /// file. Caller maps the `u8` to `std::process::exit`.
    pub fn exit_code(&self) -> u8 {
        match &self.worst_decision {
            Some(d) if d.is_blocking() => 1,
            Some(Decision::Approval { .. }) => 2,
            _ => 0,
        }
    }

    /// Group findings by rule id for the human-facing banner. Keys are
    /// sorted to give a stable display order.
    pub fn group_by_rule(&self) -> BTreeMap<String, Vec<&StagedFinding>> {
        let mut out: BTreeMap<String, Vec<&StagedFinding>> = BTreeMap::new();
        for f in &self.findings {
            out.entry(f.rule_id.clone()).or_default().push(f);
        }
        out
    }
}

/// Top-level entrypoint. Walks the staged diff in `repo_root`, evaluates
/// every added/modified line through `engine`, returns the aggregated
/// report. Runs synchronously — git invocations are cheap and the corpus
/// is small (~hundreds of lines at most for a normal commit).
pub fn run(
    repo_root: &std::path::Path,
    engine: &Engine,
    workspace_root: Option<&std::path::Path>,
    taint: Option<&TaintLedger>,
) -> Result<CheckStagedReport> {
    if !is_inside_git_repo(repo_root)? {
        return Err(anyhow!(
            "--check-staged must be run inside a git repository (got {})",
            repo_root.display()
        ));
    }

    let staged_files = list_staged_files(repo_root)?;

    // Set up the adaptive layer the same way `--check` does so workspace
    // probes and burst detection behave consistently across modes.
    // Decision memory is irrelevant for a one-shot pre-commit run -- we
    // skip allocating it entirely so a developer's stale ~/.aperion-shield
    // state never colours commit-time verdicts.
    let workspace = match workspace_root {
        Some(p) => WorkspaceContext::probe_at(&engine.policy, p),
        None => WorkspaceContext::probe_at(&engine.policy, repo_root),
    };
    let burst = BurstDetector::new(engine.policy.burst_detector.clone());

    let mut report = CheckStagedReport::default();

    for staged in staged_files {
        if !is_inspectable(&staged.path) {
            continue;
        }
        let added = match list_added_lines(repo_root, &staged.path) {
            Ok(v) => v,
            Err(e) => {
                // Don't fail the whole hook because of one unreadable
                // file -- log and continue.
                eprintln!(
                    "[shield-check-staged] skipping {}: {}",
                    staged.path, e
                );
                continue;
            }
        };
        if added.is_empty() {
            continue;
        }
        report.files_scanned += 1;

        let kind = classify_file(&staged.path);

        for AddedLine { line_no, content } in added {
            if content.trim().is_empty() {
                continue;
            }
            if is_pure_comment(&content, kind) {
                continue;
            }
            report.lines_scanned += 1;

            // v1.3 cross-tool taint: check-only against staged diff content.
            // Catches a credential that leaked from an MCP tool result being
            // hard-coded into a commit in the same project.
            let tainted = taint.map(|t| t.check(&content).is_some()).unwrap_or(false);
            let (eval, _scope) = evaluate_line(engine, kind, &content, &workspace, &burst, tainted);
            let decision = decide(&eval);
            match decision {
                Decision::Allow => continue,
                Decision::Warn { .. }
                | Decision::Approval { .. }
                | Decision::Block { .. }
                | Decision::IdentityVerification { .. } => {
                    // Pick the dominant rule match for surfacing.
                    let primary = eval
                        .matches
                        .iter()
                        .max_by(|a, b| {
                            a.severity.cmp(&b.severity).then(a.points.cmp(&b.points))
                        })
                        .cloned();
                    let (rule_id, severity, reason, safer) = match primary {
                        Some(m) => (
                            m.rule_id.clone(),
                            format!("{:?}", m.severity),
                            m.reason.clone(),
                            m.safer_alternative.clone(),
                        ),
                        None => (
                            "shield.unknown".into(),
                            "Medium".into(),
                            "matched without an attributable rule".into(),
                            None,
                        ),
                    };
                    let dec_label = decision.label().to_string();
                    report.findings.push(StagedFinding {
                        file: staged.path.clone(),
                        line_no,
                        line: content,
                        rule_id,
                        severity,
                        decision: dec_label,
                        reason,
                        safer_alternative: safer,
                    });
                    if report
                        .worst_decision
                        .as_ref()
                        .map(|d| (severity_rank(&decision)) > severity_rank(d))
                        .unwrap_or(true)
                    {
                        report.worst_decision = Some(decision.clone());
                    }
                }
            }
        }
    }

    Ok(report)
}

/// Decide whether `path` is one of the file types we lint. Anything
/// outside this list is skipped (see module-level comment for why).
fn is_inspectable(path: &str) -> bool {
    matches!(classify_file(path), FileKind::Sql | FileKind::Shell | FileKind::Code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    Sql,
    Shell,
    /// General code (Python, JS, TS, Rust, ...). Lines pass through
    /// the `llm_response` scope so the `text:` rules in the shieldset
    /// fire on agent-generated comments + obvious destructive snippets.
    Code,
    Other,
}

fn classify_file(path: &str) -> FileKind {
    let lower = path.to_lowercase();
    let basename = std::path::Path::new(&lower)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if lower.ends_with(".sql") {
        return FileKind::Sql;
    }
    if lower.ends_with(".sh")
        || lower.ends_with(".bash")
        || lower.ends_with(".zsh")
        || basename == "makefile"
        || basename.starts_with("dockerfile")
        || basename == "justfile"
    {
        return FileKind::Shell;
    }
    if lower.ends_with(".py")
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".jsx")
        || lower.ends_with(".tsx")
        || lower.ends_with(".rs")
        || lower.ends_with(".go")
        || lower.ends_with(".rb")
        || lower.ends_with(".java")
        || lower.ends_with(".kt")
        || lower.ends_with(".swift")
        || lower.ends_with(".cs")
    {
        return FileKind::Code;
    }
    FileKind::Other
}

fn evaluate_line(
    engine: &Engine,
    kind: FileKind,
    line: &str,
    workspace: &WorkspaceContext,
    burst: &BurstDetector,
    tainted: bool,
) -> (crate::engine::Evaluation, &'static str) {
    let adj = Adjustments {
        workspace_is_prod: workspace.is_prod,
        burst_in_progress: burst.in_burst(),
        tainted_secret_in_flight: tainted,
        ..Default::default()
    };
    match kind {
        FileKind::Sql => {
            let canonical = json!({"name": "execute_sql", "arguments": {"query": line}});
            (
                engine.evaluate("execute_sql", &canonical, adj),
                "tool_call",
            )
        }
        FileKind::Shell => {
            let canonical = json!({"name": "shell", "arguments": {"command": line}});
            (engine.evaluate("shell", &canonical, adj), "tool_call")
        }
        FileKind::Code | FileKind::Other => (engine.evaluate_text(line, adj), "llm_response"),
    }
}

fn is_pure_comment(line: &str, kind: FileKind) -> bool {
    let trimmed = line.trim_start();
    match kind {
        FileKind::Sql => trimmed.starts_with("--"),
        FileKind::Shell => trimmed.starts_with('#'),
        FileKind::Code => {
            trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
        }
        FileKind::Other => false,
    }
}

fn severity_rank(d: &Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Warn { .. } => 1,
        Decision::IdentityVerification { .. } => 2,
        Decision::Approval { .. } => 3,
        Decision::Block { .. } => 4,
    }
}

// ─────────────────────────────────────────────────────────────────────
// git plumbing — shell out and parse, deliberately no libgit2 dep
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct StagedFile {
    /// Repo-root-relative path, forward-slash-separated.
    path: String,
}

#[derive(Debug)]
struct AddedLine {
    line_no: usize,
    content: String,
}

fn is_inside_git_repo(repo_root: &std::path::Path) -> Result<bool> {
    let out = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo_root)
        .output()
        .with_context(|| "couldn't invoke `git rev-parse`; is git installed?")?;
    Ok(out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "true")
}

fn list_staged_files(repo_root: &std::path::Path) -> Result<Vec<StagedFile>> {
    // `--cached` = index vs HEAD, `--diff-filter=AM` = Added + Modified
    // (we skip Deletions, Renames-only, Copies). `--name-only` is the
    // fastest path.
    let out = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--diff-filter=AM",
            "--name-only",
            "-z",
        ])
        .current_dir(repo_root)
        .output()
        .with_context(|| "git diff --cached failed")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git diff --cached exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut staged = Vec::new();
    for chunk in out.stdout.split(|b| *b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(chunk).to_string();
        // Filter on the index's actual blob size; oversize binaries
        // never make it to the engine.
        if blob_oversize(repo_root, &path) {
            continue;
        }
        staged.push(StagedFile { path });
    }
    Ok(staged)
}

fn blob_oversize(repo_root: &std::path::Path, rel_path: &str) -> bool {
    let on_disk = PathBuf::from(rel_path);
    let full = repo_root.join(&on_disk);
    full.metadata()
        .map(|m| m.len() > MAX_FILE_SIZE_BYTES)
        .unwrap_or(false)
}

/// Walk `git diff --cached -U0 -- <path>` and yield every line that
/// starts with `+` (but not `+++` -- that's the header) along with its
/// post-image line number.
fn list_added_lines(
    repo_root: &std::path::Path,
    rel_path: &str,
) -> Result<Vec<AddedLine>> {
    let out = Command::new("git")
        .args([
            "diff",
            "--cached",
            "-U0",
            "--no-color",
            "--",
            rel_path,
        ])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("git diff --cached -U0 -- {} failed", rel_path))?;
    if !out.status.success() {
        return Err(anyhow!(
            "git diff for {} exited {}: {}",
            rel_path,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(parse_unified_diff_added(&text))
}

/// Pure-string parser so this is unit-testable without spawning git.
/// Handles standard unified diff hunks of the form
/// `@@ -<a>,<b> +<c>,<d> @@` (with the comma+count optional).
fn parse_unified_diff_added(diff: &str) -> Vec<AddedLine> {
    let mut out = Vec::new();
    let mut cur_line_no: usize = 0;
    let mut in_hunk = false;
    for raw in diff.lines() {
        if raw.starts_with("@@ ") {
            in_hunk = false;
            if let Some(plus) = extract_plus_start(raw) {
                cur_line_no = plus;
                in_hunk = true;
            }
            continue;
        }
        if !in_hunk {
            continue;
        }
        if raw.starts_with("+++") || raw.starts_with("---") {
            continue;
        }
        if let Some(rest) = raw.strip_prefix('+') {
            out.push(AddedLine {
                line_no: cur_line_no,
                content: rest.to_string(),
            });
            cur_line_no += 1;
        } else if raw.starts_with(' ') {
            cur_line_no += 1;
        }
        // '-' lines: don't advance the post-image counter.
    }
    out
}

/// Pull the post-image start line number out of a `@@ -X,Y +A,B @@` header.
fn extract_plus_start(header: &str) -> Option<usize> {
    let plus = header.find('+')?;
    let after = &header[plus + 1..];
    let end = after.find(|c: char| !(c.is_ascii_digit() || c == ',')).unwrap_or(after.len());
    let nums = &after[..end];
    let first = nums.split(',').next()?;
    first.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_file_extensions_correctly() {
        assert_eq!(classify_file("migrations/2026.sql"), FileKind::Sql);
        assert_eq!(classify_file("scripts/cleanup.sh"), FileKind::Shell);
        assert_eq!(classify_file("Makefile"), FileKind::Shell);
        assert_eq!(classify_file("Dockerfile"), FileKind::Shell);
        assert_eq!(classify_file("dockerfile.prod"), FileKind::Shell);
        assert_eq!(classify_file("src/main.py"), FileKind::Code);
        assert_eq!(classify_file("README.md"), FileKind::Other);
        assert_eq!(classify_file("data/dump.json"), FileKind::Other);
    }

    #[test]
    fn comment_filter_respects_language() {
        assert!(is_pure_comment("-- drop table users", FileKind::Sql));
        assert!(!is_pure_comment("# drop table users", FileKind::Sql)); // not a SQL comment
        assert!(is_pure_comment("# rm -rf /", FileKind::Shell));
        assert!(is_pure_comment("// rm -rf /", FileKind::Code));
        assert!(!is_pure_comment("rm -rf /", FileKind::Shell));
    }

    #[test]
    fn diff_parser_extracts_added_lines_with_correct_numbers() {
        let diff = r#"diff --git a/x.sql b/x.sql
--- a/x.sql
+++ b/x.sql
@@ -0,0 +1,3 @@
+DROP DATABASE prod;
+TRUNCATE users;
+SELECT 1;
@@ -10,1 +10,2 @@
-old line
+new line A
+new line B
"#;
        let lines = parse_unified_diff_added(diff);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[0].content, "DROP DATABASE prod;");
        assert_eq!(lines[1].line_no, 2);
        assert_eq!(lines[2].line_no, 3);
        assert_eq!(lines[3].line_no, 10);
        assert_eq!(lines[3].content, "new line A");
        assert_eq!(lines[4].line_no, 11);
    }

    #[test]
    fn diff_parser_ignores_headers_and_minus_lines() {
        let diff = r#"diff --git a/y.sh b/y.sh
--- /dev/null
+++ b/y.sh
@@ -0,0 +1,1 @@
+rm -rf /
"#;
        let lines = parse_unified_diff_added(diff);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].content, "rm -rf /");
        assert_eq!(lines[0].line_no, 1);
    }

    #[test]
    fn plus_start_handles_both_short_and_long_headers() {
        assert_eq!(extract_plus_start("@@ -0,0 +1,3 @@"), Some(1));
        assert_eq!(extract_plus_start("@@ -10 +10 @@"), Some(10));
        assert_eq!(extract_plus_start("@@ -0,0 +42 @@ context"), Some(42));
    }
}

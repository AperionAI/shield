//! `aperion-shield --check-pushed-refs` — reads git's standard pre-push
//! stdin and refuses destructive ref updates against protected branches.
//!
//! ## Why a separate mode (vs running the engine on the whole commit range)
//!
//! Linting the lines that *moved* between `<remote_sha>..<local_sha>`
//! would just be a rerun of `--check-staged` on each commit -- valuable,
//! but a 100-commit branch turns the pre-push hook into a 10-second
//! wait. What we actually want at push time is the structural check
//! the file-content scanner can't see: **is this a force-push, and is
//! it landing on a branch that should be append-only?**
//!
//! That's what this module does.
//!
//! ## What it refuses
//!
//! For each ref line on stdin (format documented by `man githooks`):
//!
//!   `<local_ref> <local_sha> <remote_ref> <remote_sha>`
//!
//! we refuse the push (exit 1) if:
//!
//!   * `local_sha == 0000000000000000000000000000000000000000` AND
//!     `<remote_ref>` matches a protected pattern. (= **branch
//!     deletion** of a protected branch.)
//!
//!   * `<remote_ref>` matches a protected pattern AND `<remote_sha>` is
//!     not an ancestor of `<local_sha>`. (= **force-push** that
//!     rewrites history on a protected branch.)
//!
//! All other pushes pass through unchanged.
//!
//! ## Protected-branch pattern
//!
//! Default list:
//!
//!   * `main`, `master`, `prod`, `production`, `release`
//!   * `release/*`, `prod/*`, `hotfix/*`
//!
//! Overridable via `SHIELD_PROTECTED_BRANCHES` (comma-separated). Matches
//! are computed against the ref's short name (`main`, not
//! `refs/heads/main`).
//!
//! ## Exit codes
//!
//! Same convention as `--check-staged` (see `check_staged.rs`):
//!
//! | Code | Meaning                                                |
//! |------|--------------------------------------------------------|
//! | 0    | All refs OK.                                           |
//! | 1    | At least one destructive ref update was refused.       |
//! | 3    | Operational error (couldn't shell out to git, etc.).   |

use anyhow::{anyhow, Context, Result};
use std::io::BufRead;
use std::path::Path;
use std::process::Command;

const NULL_SHA: &str = "0000000000000000000000000000000000000000";

const DEFAULT_PROTECTED_BRANCHES: &[&str] = &[
    "main",
    "master",
    "prod",
    "production",
    "release",
    "release/*",
    "prod/*",
    "hotfix/*",
];

/// One stdin ref update line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub local_ref: String,
    pub local_sha: String,
    pub remote_ref: String,
    pub remote_sha: String,
}

#[derive(Debug, Clone)]
pub enum PushVerdict {
    Ok,
    Deletion {
        protected_branch: String,
    },
    ForcePush {
        protected_branch: String,
        remote_sha: String,
        local_sha: String,
    },
}

#[derive(Debug, Default)]
pub struct CheckPushedReport {
    pub refs_inspected: usize,
    pub violations: Vec<(RefUpdate, PushVerdict)>,
}

impl CheckPushedReport {
    pub fn exit_code(&self) -> u8 {
        if self.violations.is_empty() {
            0
        } else {
            1
        }
    }
}

/// Parse a single line of git's pre-push stdin protocol. Returns `None`
/// for empty lines so callers can skip them silently.
pub fn parse_line(line: &str) -> Option<RefUpdate> {
    let mut iter = line.split_whitespace();
    let local_ref = iter.next()?.to_string();
    let local_sha = iter.next()?.to_string();
    let remote_ref = iter.next()?.to_string();
    let remote_sha = iter.next()?.to_string();
    Some(RefUpdate {
        local_ref,
        local_sha,
        remote_ref,
        remote_sha,
    })
}

/// Resolve which patterns to consider protected. Honours the env var.
pub fn protected_patterns() -> Vec<String> {
    if let Ok(raw) = std::env::var("SHIELD_PROTECTED_BRANCHES") {
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        DEFAULT_PROTECTED_BRANCHES
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }
}

/// Match a short branch name like `release/2026-05` against a pattern
/// like `release/*` (only `*` glob, only at the end of a component).
pub fn pattern_matches(pattern: &str, short_name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return short_name.starts_with(&format!("{}/", prefix));
    }
    pattern == short_name
}

/// Reduce a full ref (`refs/heads/main`) to its short name (`main`).
fn short_name(full_ref: &str) -> &str {
    full_ref.strip_prefix("refs/heads/").unwrap_or(full_ref)
}

/// Test whether `short_name(remote_ref)` is in the protected set.
pub fn is_protected(remote_ref: &str, patterns: &[String]) -> Option<String> {
    let s = short_name(remote_ref);
    for p in patterns {
        if pattern_matches(p, s) {
            return Some(s.to_string());
        }
    }
    None
}

/// Ask git whether `ancestor_sha` is an ancestor of `descendant_sha`.
/// Returns `Ok(true)` for a normal fast-forward push, `Ok(false)` for
/// any history rewrite (= force-push).
fn is_ancestor(
    repo_root: &Path,
    ancestor_sha: &str,
    descendant_sha: &str,
) -> Result<bool> {
    if ancestor_sha == NULL_SHA {
        // Branch is being created -- there's nothing to rewrite, so
        // it's NOT a force-push.
        return Ok(true);
    }
    let status = Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            ancestor_sha,
            descendant_sha,
        ])
        .current_dir(repo_root)
        .status()
        .with_context(|| {
            "git merge-base --is-ancestor failed (is git installed?)"
        })?;
    // Exit 0 = is ancestor, exit 1 = not ancestor. Anything else =
    // error (e.g. unknown sha) and we treat as suspicious (not
    // ancestor) — fail closed.
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(code) => Err(anyhow!(
            "git merge-base exited unexpectedly with code {} for {}..{}",
            code,
            ancestor_sha,
            descendant_sha
        )),
        None => Err(anyhow!(
            "git merge-base was killed by signal during {}..{}",
            ancestor_sha,
            descendant_sha
        )),
    }
}

/// Verdict for a single ref update.
pub fn verdict(repo_root: &Path, upd: &RefUpdate, patterns: &[String]) -> Result<PushVerdict> {
    let protected = match is_protected(&upd.remote_ref, patterns) {
        Some(name) => name,
        None => return Ok(PushVerdict::Ok),
    };

    // Deletion?
    if upd.local_sha == NULL_SHA {
        return Ok(PushVerdict::Deletion {
            protected_branch: protected,
        });
    }

    // Branch is being CREATED on the remote (remote_sha is NULL) →
    // not a force-push, allow.
    if upd.remote_sha == NULL_SHA {
        return Ok(PushVerdict::Ok);
    }

    // Force-push detection: remote_sha must be an ancestor of local_sha.
    if !is_ancestor(repo_root, &upd.remote_sha, &upd.local_sha)? {
        return Ok(PushVerdict::ForcePush {
            protected_branch: protected,
            remote_sha: upd.remote_sha.clone(),
            local_sha: upd.local_sha.clone(),
        });
    }

    Ok(PushVerdict::Ok)
}

/// Top-level entrypoint. Reads stdin line by line, returns a report.
pub fn run(repo_root: &Path, stdin: impl BufRead) -> Result<CheckPushedReport> {
    let patterns = protected_patterns();
    let mut report = CheckPushedReport::default();

    for line in stdin.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let upd = match parse_line(&line) {
            Some(u) => u,
            None => continue,
        };
        report.refs_inspected += 1;
        let v = verdict(repo_root, &upd, &patterns)?;
        if !matches!(v, PushVerdict::Ok) {
            report.violations.push((upd, v));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // cargo runs lib tests in parallel within a single binary. The two
    // tests that mutate `SHIELD_PROTECTED_BRANCHES` would otherwise
    // race each other (one sets, the other reads default, fails). We
    // serialise only those two via a module-local lock -- no new
    // dependency, no impact on the other tests in this module.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_well_formed_stdin_line() {
        let l = "refs/heads/feat/foo 1111 refs/heads/main 2222";
        let u = parse_line(l).unwrap();
        assert_eq!(u.local_ref, "refs/heads/feat/foo");
        assert_eq!(u.local_sha, "1111");
        assert_eq!(u.remote_ref, "refs/heads/main");
        assert_eq!(u.remote_sha, "2222");
    }

    #[test]
    fn parse_line_handles_short_input() {
        assert!(parse_line("").is_none());
        assert!(parse_line("only one field").is_none());
    }

    #[test]
    fn pattern_matches_exact_and_globbed() {
        assert!(pattern_matches("main", "main"));
        assert!(!pattern_matches("main", "develop"));
        assert!(pattern_matches("release/*", "release/2026-05"));
        assert!(pattern_matches("release/*", "release/foo/bar")); // first component matches
        assert!(!pattern_matches("release/*", "release"));
        assert!(!pattern_matches("release/*", "feature/release/x"));
    }

    // NB: tests that touch `SHIELD_PROTECTED_BRANCHES` are written
    // defensively — each one explicitly removes the var at the top
    // and reads via the documented default-resolution path. We do NOT
    // rely on `serial_test` or a mutex because cargo runs lib tests
    // in parallel by default and one stray leak would flake any test
    // that calls `protected_patterns()` (= every protected-branch test).

    #[test]
    fn is_protected_recognises_default_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SHIELD_PROTECTED_BRANCHES");
        let pats = protected_patterns();
        assert_eq!(is_protected("refs/heads/main", &pats).as_deref(), Some("main"));
        assert_eq!(is_protected("refs/heads/master", &pats).as_deref(), Some("master"));
        assert_eq!(
            is_protected("refs/heads/release/2026-05", &pats).as_deref(),
            Some("release/2026-05")
        );
        assert_eq!(is_protected("refs/heads/develop", &pats), None);
    }

    #[test]
    fn env_override_protected_branches() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHIELD_PROTECTED_BRANCHES", "trunk, deploy/*");
        let pats = protected_patterns();
        assert!(is_protected("refs/heads/trunk", &pats).is_some());
        assert!(is_protected("refs/heads/deploy/prod", &pats).is_some());
        assert!(is_protected("refs/heads/main", &pats).is_none());
        std::env::remove_var("SHIELD_PROTECTED_BRANCHES");
    }

    #[test]
    fn empty_stdin_yields_clean_report() {
        let tmp = tempfile::tempdir().unwrap();
        let report = run(tmp.path(), std::io::Cursor::new(b"")).expect("run");
        assert_eq!(report.refs_inspected, 0);
        assert!(report.violations.is_empty());
        assert_eq!(report.exit_code(), 0);
    }
}

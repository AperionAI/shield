//! I/O offload gate (v1.7).
//!
//! Most of what a coding agent spends tokens on is not reasoning. It is
//! loading files into the frontier model's context: `Read` a 4,000-line
//! source file to answer one question, `cat` a log to find one line.
//! This gate refuses that read at the `PreToolUse` seam and tells the
//! agent to get a summary from the cheap model instead
//! (`aperion-shield --summarize`). Enforced by the hook Shield already
//! owns; no second plugin to install.
//!
//! What passes untouched:
//!
//!   * targeted reads (`offset` / `limit` / `start_line` / `end_line`)
//!   * piped or redirected shell reads (`cat f | grep x`, `cat f > out`)
//!   * `head` / `tail` without a large `-n`
//!   * files under the threshold, missing files, unreadable files
//!
//! Opt-in. Off unless `shieldset.policy.io_offload.min_lines` (published
//! to a policy group, or set in a `--rules` file) or the per-machine
//! override `APERION_SHIELD_OFFLOAD_MIN_LINES` is a positive integer.
//! Shield is a security tool first; a customer who upgrades should not
//! suddenly find their agent's reads refused.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::agent::{extract_command, extract_path, is_read_tool, is_shell_tool};
use crate::engine::Policy;

/// Rule id stamped on the audit record and the deny reason.
pub const RULE_ID: &str = "io.offload_large_read";

/// Per-machine override for the threshold. Wins over the shieldset value.
/// `0` disables; unset or garbage = fall back to the shieldset.
pub const MIN_LINES_ENV: &str = "APERION_SHIELD_OFFLOAD_MIN_LINES";

/// Suggested default when an operator asks. Around this size a cheap
/// summarizer round-trip costs less than the frontier model reading the
/// file, and the summary is still specific enough to act on.
pub const SUGGESTED_MIN_LINES: usize = 350;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadConfig {
    /// Full reads of files with more lines than this are refused.
    /// `0` disables the gate.
    pub min_lines: usize,
}

impl OffloadConfig {
    pub fn disabled() -> Self {
        Self { min_lines: 0 }
    }

    /// Env only (no shieldset). Kept for callers without an engine.
    pub fn from_env() -> Self {
        Self {
            min_lines: env_min_lines().unwrap_or(0),
        }
    }

    /// Env override first, then the shieldset `policy.io_offload` block.
    pub fn resolve(policy: &Policy) -> Self {
        Self {
            min_lines: env_min_lines().unwrap_or(policy.io_offload.min_lines),
        }
    }

    pub fn enabled(&self) -> bool {
        self.min_lines > 0
    }
}

fn env_min_lines() -> Option<usize> {
    std::env::var(MIN_LINES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffloadVerdict {
    Pass,
    Block {
        path: String,
        lines: usize,
        reason: String,
    },
}

impl OffloadVerdict {
    pub fn is_block(&self) -> bool {
        matches!(self, OffloadVerdict::Block { .. })
    }
}

/// Decide whether this tool call is an unbounded read of a large file.
pub fn check(cfg: &OffloadConfig, tool_name: &str, input: &Value, cwd: &Path) -> OffloadVerdict {
    if !cfg.enabled() {
        return OffloadVerdict::Pass;
    }
    let lower = tool_name.to_ascii_lowercase();

    if is_read_tool(&lower) {
        if has_range(input) {
            return OffloadVerdict::Pass;
        }
        let path = extract_path(input);
        if path.is_empty() {
            return OffloadVerdict::Pass;
        }
        return match count_lines(&resolve(&path, cwd)) {
            Some(lines) if lines > cfg.min_lines => block(&path, lines, cfg.min_lines),
            _ => OffloadVerdict::Pass,
        };
    }

    if is_shell_tool(&lower) {
        let cmd = extract_command(input);
        return check_shell(cfg, &cmd, cwd);
    }

    OffloadVerdict::Pass
}

/// The agent already narrowed the read; let it through.
fn has_range(input: &Value) -> bool {
    const KEYS: &[&str] = &[
        "offset",
        "limit",
        "start_line",
        "end_line",
        "startLine",
        "endLine",
        "start_line_one_indexed",
        "end_line_one_indexed_inclusive",
        "range",
        "lines",
    ];
    KEYS.iter().any(|k| {
        input
            .get(k)
            .map(|v| !v.is_null() && v.as_str().map(|s| !s.is_empty()).unwrap_or(true))
            .unwrap_or(false)
    })
}

fn check_shell(cfg: &OffloadConfig, cmd: &str, cwd: &Path) -> OffloadVerdict {
    // A pipe or redirect means the output is being filtered or written,
    // not dumped into the model. Let it go.
    if cmd.contains('|') || cmd.contains('>') || cmd.contains("<<") {
        return OffloadVerdict::Pass;
    }
    // Evaluate each simple command in `a && b ; c` separately.
    for seg in cmd.split("&&").flat_map(|s| s.split(';')) {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        if let v @ OffloadVerdict::Block { .. } = check_simple(cfg, seg, cwd) {
            return v;
        }
    }
    OffloadVerdict::Pass
}

fn check_simple(cfg: &OffloadConfig, seg: &str, cwd: &Path) -> OffloadVerdict {
    let toks: Vec<&str> = seg.split_whitespace().collect();
    let mut i = 0;
    // Skip `sudo`, `env`, and FOO=bar assignments.
    while i < toks.len() && (toks[i] == "sudo" || toks[i] == "env" || toks[i].contains('=')) {
        i += 1;
    }
    let Some(&verb) = toks.get(i) else {
        return OffloadVerdict::Pass;
    };
    let verb = verb.rsplit('/').next().unwrap_or(verb);
    let args = &toks[i + 1..];

    match verb {
        "cat" | "less" | "more" | "bat" | "batcat" => {
            for a in args.iter().filter(|a| !a.starts_with('-')) {
                let path = unquote(a);
                if let Some(lines) = count_lines(&resolve(&path, cwd)) {
                    if lines > cfg.min_lines {
                        return block(&path, lines, cfg.min_lines);
                    }
                }
            }
            OffloadVerdict::Pass
        }
        "head" | "tail" => {
            // Default is 10 lines: targeted. Only a big explicit -n is a dump.
            let Some(n) = head_tail_count(args) else {
                return OffloadVerdict::Pass;
            };
            if n <= cfg.min_lines {
                return OffloadVerdict::Pass;
            }
            for a in args
                .iter()
                .filter(|a| !a.starts_with('-') && a.parse::<usize>().is_err())
            {
                let path = unquote(a);
                if let Some(lines) = count_lines(&resolve(&path, cwd)) {
                    if lines.min(n) > cfg.min_lines {
                        return block(&path, lines, cfg.min_lines);
                    }
                }
            }
            OffloadVerdict::Pass
        }
        _ => OffloadVerdict::Pass,
    }
}

/// `-n 500`, `-n500`, `--lines=500`, `-500`.
fn head_tail_count(args: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == "-n" || a == "--lines" {
            return args
                .get(i + 1)
                .and_then(|v| v.trim_start_matches(['+', '-']).parse().ok());
        }
        if let Some(v) = a.strip_prefix("--lines=") {
            return v.trim_start_matches(['+', '-']).parse().ok();
        }
        if let Some(v) = a.strip_prefix("-n") {
            if let Ok(n) = v.trim_start_matches(['+', '-']).parse() {
                return Some(n);
            }
        }
        if let Some(v) = a.strip_prefix('-') {
            if let Ok(n) = v.parse::<usize>() {
                return Some(n);
            }
        }
        i += 1;
    }
    None
}

fn unquote(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'').to_string()
}

fn resolve(path: &str, cwd: &Path) -> PathBuf {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| PathBuf::from(path))
    } else {
        PathBuf::from(path)
    };
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

/// Line count, or `None` when we can't or shouldn't look (missing,
/// directory, binary-ish, too big to bother reading).
fn count_lines(path: &Path) -> Option<usize> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    // 32 MiB ceiling: past that it isn't a source file anyone should Read.
    if meta.len() > 32 * 1024 * 1024 {
        return Some(usize::MAX);
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(4096).any(|&b| b == 0) {
        return None; // binary
    }
    let mut n = bytes.iter().filter(|&&b| b == b'\n').count();
    if !bytes.is_empty() && *bytes.last().unwrap() != b'\n' {
        n += 1;
    }
    Some(n)
}

fn block(path: &str, lines: usize, min: usize) -> OffloadVerdict {
    let shown = if lines == usize::MAX {
        "very large".to_string()
    } else {
        format!("{lines} lines")
    };
    let reason = format!(
        "aperion-shield: full read of {path} ({shown}) refused; over the {min}-line offload \
threshold. Do not load large files into context. Read a targeted range (offset/limit) if you \
need exact text to edit, or summarize it on the governed cheap model: \
`aperion-shield --summarize --question \"<what you need to know>\" {path}`. \
The summary comes back as bullets with names and line numbers."
    );
    OffloadVerdict::Block {
        path: path.to_string(),
        lines,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn cfg() -> OffloadConfig {
        OffloadConfig { min_lines: 20 }
    }

    fn file_with_lines(dir: &Path, name: &str, n: usize) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        for i in 0..n {
            writeln!(f, "line {i}").unwrap();
        }
        p
    }

    #[test]
    fn disabled_passes_everything() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.rs", 500);
        let v = check(
            &OffloadConfig::disabled(),
            "Read",
            &json!({"file_path": big}),
            dir.path(),
        );
        assert_eq!(v, OffloadVerdict::Pass);
    }

    #[test]
    fn read_large_file_blocks_with_summarize_hint() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.rs", 500);
        let v = check(&cfg(), "Read", &json!({"file_path": big}), dir.path());
        match v {
            OffloadVerdict::Block { lines, reason, .. } => {
                assert_eq!(lines, 500);
                assert!(reason.contains("--summarize"), "{reason}");
                assert!(reason.contains("big.rs"));
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn read_small_file_passes() {
        let dir = tempfile::tempdir().unwrap();
        let small = file_with_lines(dir.path(), "small.rs", 5);
        let v = check(&cfg(), "Read", &json!({"file_path": small}), dir.path());
        assert_eq!(v, OffloadVerdict::Pass);
    }

    #[test]
    fn targeted_read_passes() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.rs", 500);
        let v = check(
            &cfg(),
            "Read",
            &json!({"file_path": big, "offset": 100, "limit": 40}),
            dir.path(),
        );
        assert_eq!(v, OffloadVerdict::Pass);
        let v = check(
            &cfg(),
            "read_file",
            &json!({"path": big, "start_line_one_indexed": 1, "end_line_one_indexed_inclusive": 30}),
            dir.path(),
        );
        assert_eq!(v, OffloadVerdict::Pass);
    }

    #[test]
    fn relative_path_resolves_against_cwd() {
        let dir = tempfile::tempdir().unwrap();
        file_with_lines(dir.path(), "big.rs", 500);
        let v = check(&cfg(), "Read", &json!({"file_path": "big.rs"}), dir.path());
        assert!(v.is_block());
    }

    #[test]
    fn missing_file_passes() {
        let dir = tempfile::tempdir().unwrap();
        let v = check(
            &cfg(),
            "Read",
            &json!({"file_path": dir.path().join("nope.rs")}),
            dir.path(),
        );
        assert_eq!(v, OffloadVerdict::Pass);
    }

    #[test]
    fn binary_file_passes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("blob.bin");
        let mut bytes = vec![0u8; 64];
        bytes.extend(std::iter::repeat(b'\n').take(1000));
        std::fs::write(&p, bytes).unwrap();
        let v = check(&cfg(), "Read", &json!({"file_path": p}), dir.path());
        assert_eq!(v, OffloadVerdict::Pass);
    }

    #[test]
    fn bash_cat_large_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.log", 500);
        let v = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("cat {}", big.display())}),
            dir.path(),
        );
        assert!(v.is_block(), "{v:?}");
    }

    #[test]
    fn bash_cat_piped_passes() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.log", 500);
        for cmd in [
            format!("cat {} | grep ERROR", big.display()),
            format!("cat {} > /tmp/out", big.display()),
        ] {
            let v = check(&cfg(), "Bash", &json!({"command": cmd}), dir.path());
            assert_eq!(v, OffloadVerdict::Pass, "{cmd}");
        }
    }

    #[test]
    fn bash_head_default_passes_big_n_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.log", 500);
        let ok = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("head {}", big.display())}),
            dir.path(),
        );
        assert_eq!(ok, OffloadVerdict::Pass);
        let ok = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("tail -n 15 {}", big.display())}),
            dir.path(),
        );
        assert_eq!(ok, OffloadVerdict::Pass);
        let bad = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("head -n 400 {}", big.display())}),
            dir.path(),
        );
        assert!(bad.is_block(), "{bad:?}");
        let bad = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("tail -400 {}", big.display())}),
            dir.path(),
        );
        assert!(bad.is_block(), "{bad:?}");
    }

    #[test]
    fn bash_non_read_verbs_pass() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.log", 500);
        for cmd in [
            format!("wc -l {}", big.display()),
            format!("grep -n TODO {}", big.display()),
            format!("git log -- {}", big.display()),
            "ls -la".to_string(),
        ] {
            let v = check(&cfg(), "Bash", &json!({"command": cmd}), dir.path());
            assert_eq!(v, OffloadVerdict::Pass, "{cmd}");
        }
    }

    #[test]
    fn bash_chained_command_checks_each_segment() {
        let dir = tempfile::tempdir().unwrap();
        let big = file_with_lines(dir.path(), "big.log", 500);
        let v = check(
            &cfg(),
            "Bash",
            &json!({"command": format!("cd {} && cat big.log", dir.path().display())}),
            dir.path(),
        );
        assert!(v.is_block(), "{v:?}");
    }

    #[test]
    fn head_tail_count_parses_forms() {
        assert_eq!(head_tail_count(&["-n", "500", "f"]), Some(500));
        assert_eq!(head_tail_count(&["-n500", "f"]), Some(500));
        assert_eq!(head_tail_count(&["--lines=500", "f"]), Some(500));
        assert_eq!(head_tail_count(&["-500", "f"]), Some(500));
        assert_eq!(head_tail_count(&["-n", "+500", "f"]), Some(500));
        assert_eq!(head_tail_count(&["f"]), None);
    }

    #[test]
    fn env_parse_and_policy_fallback() {
        let mut policy = Policy::default();
        std::env::set_var(MIN_LINES_ENV, "350");
        assert_eq!(OffloadConfig::from_env().min_lines, 350);
        assert_eq!(OffloadConfig::resolve(&policy).min_lines, 350);
        std::env::set_var(MIN_LINES_ENV, "nope");
        assert!(!OffloadConfig::from_env().enabled());
        std::env::remove_var(MIN_LINES_ENV);
        assert!(!OffloadConfig::from_env().enabled());
        // No env: the shieldset value is what applies.
        policy.io_offload.min_lines = 500;
        assert_eq!(OffloadConfig::resolve(&policy).min_lines, 500);
        // Env `0` is an explicit per-machine off switch.
        std::env::set_var(MIN_LINES_ENV, "0");
        assert!(!OffloadConfig::resolve(&policy).enabled());
        std::env::remove_var(MIN_LINES_ENV);
    }

    #[test]
    fn shieldset_yaml_parses_io_offload_block() {
        let engine = crate::Engine::from_yaml(
            "shieldset:\n  version: 2\n  policy:\n    io_offload:\n      min_lines: 420\n  rules: []\n",
        )
        .expect("yaml");
        assert_eq!(engine.policy.io_offload.min_lines, 420);
        assert_eq!(
            crate::Engine::builtin_default().policy.io_offload.min_lines,
            0
        );
    }
}

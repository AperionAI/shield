//! Local decision memory — append-only JSONL of past approve/deny
//! decisions per (rule_id, argv-fingerprint). All processing is
//! purely local; nothing is ever sent off the box.
//!
//! Two adaptive behaviours derive from this log:
//!
//!   * Demote-after-N-approvals: if the user has approved this exact
//!     fingerprint ≥ `demote_after_approvals` times with no recent
//!     denial, severity drops one tier.
//!
//!   * Escalate-on-recent-deny: if any denial exists within
//!     `escalate_on_deny_days`, severity bumps one tier.
//!
//! The log file lives at `<cwd>/.aperion-shield/decisions.jsonl` by
//! default — co-located with the inbox so users only manage one
//! Shield-state directory per project. A user-global fallback under
//! `~/.aperion-shield/` is checked when the project directory is not
//! writable (e.g. read-only mounts in CI).

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::DecisionMemoryCfg;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub ts: DateTime<Utc>,
    pub rule_id: String,
    pub fingerprint: String,
    pub outcome: Outcome,
    pub tool: String,
}

/// Adaptive verdict drawn from the memory log for a given fingerprint.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryVerdict {
    pub recent_deny: bool,
    pub repeated_approve: bool,
    pub approve_count: u32,
    pub deny_count: u32,
}

#[derive(Debug, Clone)]
pub struct DecisionMemory {
    path: PathBuf,
    cfg: DecisionMemoryCfg,
}

impl DecisionMemory {
    /// Open (or initialise) the on-disk log. Returns even if the file
    /// doesn't exist yet — first writes will create it.
    pub fn open(cfg: DecisionMemoryCfg) -> Self {
        let path = resolve_path();
        Self { path, cfg }
    }

    #[cfg(test)]
    pub fn at_path(cfg: DecisionMemoryCfg, path: PathBuf) -> Self {
        Self { path, cfg }
    }

    pub fn enabled(&self) -> bool { self.cfg.enabled }
    pub fn path(&self) -> &PathBuf { &self.path }

    /// Append a new decision to the log. Errors are logged but never
    /// raised — decision memory is best-effort, must not break the
    /// proxy if disk is full / RO.
    pub fn record(&self, rule_id: &str, fingerprint: &str, outcome: Outcome, tool: &str) {
        if !self.cfg.enabled { return; }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let entry = MemoryEntry {
            ts: Utc::now(),
            rule_id: rule_id.to_string(),
            fingerprint: fingerprint.to_string(),
            outcome,
            tool: tool.to_string(),
        };
        match serde_json::to_string(&entry) {
            Ok(line) => {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.path) {
                    let _ = writeln!(f, "{}", line);
                }
            }
            Err(_) => {} // can't serialise our own struct → impossible
        }
    }

    /// Consult the log for a given fingerprint and produce a verdict.
    /// Reads sequentially; we expect the file to stay small (one entry
    /// per high-severity decision per user per project).
    pub fn verdict_for(&self, fingerprint: &str) -> MemoryVerdict {
        if !self.cfg.enabled { return MemoryVerdict::default(); }
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return MemoryVerdict::default(),
        };
        let now = Utc::now();
        let escalate_cutoff = now - Duration::days(self.cfg.escalate_on_deny_days as i64);
        let mut approve_count = 0u32;
        let mut deny_count = 0u32;
        let mut recent_deny = false;
        let mut last_deny: Option<DateTime<Utc>> = None;
        for line in BufReader::new(file).lines().flatten() {
            let entry: MemoryEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue, // skip malformed
            };
            if entry.fingerprint != fingerprint { continue; }
            match entry.outcome {
                Outcome::Approve => approve_count += 1,
                Outcome::Deny => {
                    deny_count += 1;
                    if entry.ts >= escalate_cutoff {
                        recent_deny = true;
                        last_deny = Some(entry.ts);
                    }
                }
            }
        }
        // Demotion only counts approvals that came *after* the last
        // deny. We re-walk to apply that rule precisely.
        let approve_after_last_deny = if let Some(d) = last_deny {
            let file = std::fs::File::open(&self.path).ok();
            let mut count = 0u32;
            if let Some(f) = file {
                for line in BufReader::new(f).lines().flatten() {
                    if let Ok(e) = serde_json::from_str::<MemoryEntry>(&line) {
                        if e.fingerprint == fingerprint
                            && matches!(e.outcome, Outcome::Approve)
                            && e.ts > d
                        {
                            count += 1;
                        }
                    }
                }
            }
            count
        } else {
            approve_count
        };
        let repeated_approve = approve_after_last_deny >= self.cfg.demote_after_approvals;
        MemoryVerdict {
            recent_deny,
            repeated_approve,
            approve_count,
            deny_count,
        }
    }
}

fn resolve_path() -> PathBuf {
    // Prefer cwd/.aperion-shield/decisions.jsonl (per-project memory)
    // but fall back to ~/.aperion-shield/decisions.jsonl when cwd is
    // read-only — we test by attempting to create the directory.
    let local = PathBuf::from(".aperion-shield");
    if std::fs::create_dir_all(&local).is_ok() {
        return local.join("decisions.jsonl");
    }
    if let Some(home) = dirs::home_dir() {
        let user = home.join(".aperion-shield");
        let _ = std::fs::create_dir_all(&user);
        return user.join("decisions.jsonl");
    }
    local.join("decisions.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg() -> DecisionMemoryCfg {
        DecisionMemoryCfg {
            enabled: true,
            demote_after_approvals: 3,
            escalate_on_deny_days: 7,
        }
    }

    #[test]
    fn empty_log_means_neutral() {
        let tmp = TempDir::new().unwrap();
        let mem = DecisionMemory::at_path(cfg(), tmp.path().join("decisions.jsonl"));
        let v = mem.verdict_for("abc123");
        assert!(!v.recent_deny);
        assert!(!v.repeated_approve);
        assert_eq!(v.approve_count, 0);
        assert_eq!(v.deny_count, 0);
    }

    #[test]
    fn three_approves_triggers_demotion() {
        let tmp = TempDir::new().unwrap();
        let mem = DecisionMemory::at_path(cfg(), tmp.path().join("decisions.jsonl"));
        for _ in 0..3 {
            mem.record("r1", "abc123", Outcome::Approve, "tool");
        }
        let v = mem.verdict_for("abc123");
        assert!(v.repeated_approve);
        assert!(!v.recent_deny);
    }

    #[test]
    fn deny_resets_approve_streak() {
        let tmp = TempDir::new().unwrap();
        let mem = DecisionMemory::at_path(cfg(), tmp.path().join("decisions.jsonl"));
        // 5 approvals, then a denial, then 1 more approval.
        for _ in 0..5 { mem.record("r1", "fp", Outcome::Approve, "t"); }
        std::thread::sleep(std::time::Duration::from_millis(2));
        mem.record("r1", "fp", Outcome::Deny, "t");
        std::thread::sleep(std::time::Duration::from_millis(2));
        mem.record("r1", "fp", Outcome::Approve, "t");
        let v = mem.verdict_for("fp");
        // Should NOT be considered "repeatedly approved" because there's
        // only one approval after the deny.
        assert!(!v.repeated_approve);
        // AND the deny is recent → escalation should fire.
        assert!(v.recent_deny);
    }

    #[test]
    fn fingerprint_isolation() {
        let tmp = TempDir::new().unwrap();
        let mem = DecisionMemory::at_path(cfg(), tmp.path().join("decisions.jsonl"));
        for _ in 0..3 { mem.record("r1", "fp_A", Outcome::Approve, "t"); }
        let other = mem.verdict_for("fp_B");
        assert!(!other.repeated_approve);
        let same = mem.verdict_for("fp_A");
        assert!(same.repeated_approve);
    }
}

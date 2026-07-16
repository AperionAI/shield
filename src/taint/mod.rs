//! Cross-tool secret taint tracking (v1.3).
//!
//! ## The gap this closes
//!
//! Every point-in-time, single-server MCP guardrail (including Shield
//! before v1.3) evaluates each tool call in isolation. The emerging MCP
//! threat -- OWASP MCP09 "Confused Deputy", measured by Unit 42 at a
//! 78.3% attack success rate in a 5-server session -- is *not* one
//! server misbehaving on its own. It's a **compromised server's output
//! (e.g. a leaked credential) flowing into a different, individually-
//! trusted tool's input**. Neither tool looks wrong on its own; the
//! danger is only visible when you correlate across them.
//!
//! Shield already spans four surfaces for one project (MCP proxy, git
//! hooks, shell shims, `--scan`). This module gives those surfaces a
//! shared, append-only ledger so a secret seen leaving surface A can be
//! recognised arriving at surface B.
//!
//! ## How it works
//!
//!   * **Tag** (`tag` / `tag_all_in`): when a credential-shaped value
//!     appears in a tool *result* (or, in future, shim stdout), we append
//!     `{ ts, entity_kind, hash, source_surface, source_tool, ttl_secs }`
//!     to `<project>/.aperion-shield/taint.jsonl`. We store only a
//!     SHA-256 hash of the value -- never the raw secret -- mirroring the
//!     `engine::fingerprint()` pattern.
//!   * **Check** (`check`): before an *outgoing* tool call is forwarded,
//!     we scan its arguments for credential shapes, hash each, and look
//!     them up in the ledger. A hit that is still within TTL means "this
//!     exact secret was just handed to us by a *different* tool/surface"
//!     -- a cross-tool relay worth escalating.
//!
//! ## Known limitations (see SECURITY.md)
//!
//!   * No file locking: a theoretical read/write race between two Shield
//!     processes can miss a just-written entry. Best-effort, same as
//!     decision memory.
//!   * Heuristic, not cryptographic: a secret re-encoded or partially
//!     retyped before reuse (base64, truncation) won't hash-match and
//!     will evade detection.
//!   * CWD-scoped ledger: the same inherited caveat as `memory.rs` --
//!     the ledger is per-project-directory.

pub mod entities;

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use entities::{hash_secret, scan_secrets, SecretMatch};

/// Default TTL for a tagged secret, in seconds. A credential is only
/// "in flight" for a short correlation window -- long enough to span a
/// multi-step agent turn, short enough that a stale value doesn't keep
/// escalating unrelated calls hours later.
pub const DEFAULT_TTL_SECS: u64 = 600;

/// One tagged sighting of a credential-shaped value. Persisted as one
/// JSON object per line. `hash` is `hash_secret(raw_value)`; the raw
/// value is never stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintEntry {
    pub ts: DateTime<Utc>,
    pub entity_kind: String,
    pub hash: String,
    /// Which Shield surface observed the secret leaving: e.g.
    /// `mcp_tool_result`, `check_cmd`, `check_staged`, `check_corpus`.
    pub source_surface: String,
    /// The tool / command / file the secret came out of, for the
    /// human-readable escalation reason.
    pub source_tool: String,
    pub ttl_secs: u64,
}

/// A positive taint hit: an outgoing value matched a previously-tagged
/// secret that is still within its TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintMatch {
    pub entity_kind: String,
    pub source_surface: String,
    pub source_tool: String,
    /// Seconds elapsed since the secret was tagged.
    pub age_secs: i64,
}

impl TaintMatch {
    /// One-line, human-readable reason string for logs / client errors.
    /// Never contains the secret itself.
    pub fn reason(&self) -> String {
        format!(
            "a {} value returned by '{}' (via {}) {}s ago is being sent to a different \
             tool/surface in this project -- possible cross-tool credential relay \
             (confused deputy)",
            self.entity_kind, self.source_tool, self.source_surface, self.age_secs
        )
    }

    /// Short label for the audit JSON / `--explain` signal.
    pub fn label(&self) -> String {
        format!("{} from {}/{}", self.entity_kind, self.source_surface, self.source_tool)
    }
}

/// Append-only, per-project ledger of tagged secrets.
#[derive(Debug, Clone)]
pub struct TaintLedger {
    path: PathBuf,
    ttl_secs: u64,
    enabled: bool,
}

impl TaintLedger {
    /// Open (or lazily initialise) the on-disk ledger. Resolves to
    /// `<cwd>/.aperion-shield/taint.jsonl`, falling back to
    /// `~/.aperion-shield/taint.jsonl` when the project dir isn't
    /// writable -- the exact same resolution `memory.rs` uses so all
    /// per-project Shield state lives in one directory.
    pub fn open(ttl_secs: u64, enabled: bool) -> Self {
        Self {
            path: resolve_path(),
            ttl_secs,
            enabled,
        }
    }

    #[cfg(test)]
    pub fn at_path(path: PathBuf, ttl_secs: u64, enabled: bool) -> Self {
        Self { path, ttl_secs, enabled }
    }

    pub fn enabled(&self) -> bool { self.enabled }
    pub fn path(&self) -> &PathBuf { &self.path }
    pub fn ttl_secs(&self) -> u64 { self.ttl_secs }

    /// Tag a single known secret value. Best-effort: I/O errors are
    /// swallowed (the ledger must never break the proxy hot path), same
    /// contract as `memory.rs::record()`.
    pub fn tag(&self, entity_kind: &str, raw_value: &str, source_surface: &str, source_tool: &str) {
        if !self.enabled { return; }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let entry = TaintEntry {
            ts: Utc::now(),
            entity_kind: entity_kind.to_string(),
            hash: hash_secret(raw_value),
            source_surface: source_surface.to_string(),
            source_tool: source_tool.to_string(),
            ttl_secs: self.ttl_secs,
        };
        if let Ok(line) = serde_json::to_string(&entry) {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.path) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }

    /// Scan `text` for every credential shape and tag each one. Returns
    /// the number of secrets tagged. Used on the *output* side (tool
    /// results, corpus inputs).
    pub fn tag_all_in(&self, text: &str, source_surface: &str, source_tool: &str) -> usize {
        if !self.enabled { return 0; }
        let found = scan_secrets(text);
        for s in &found {
            self.tag(s.kind, &s.value, source_surface, source_tool);
        }
        found.len()
    }

    /// Scan `text` (an outgoing tool call's arguments, a staged diff line,
    /// a shim command line) for credential shapes and look each up in the
    /// ledger. Returns the first still-within-TTL match, or `None`.
    ///
    /// Full sequential scan of the ledger, same approach as
    /// `memory.rs::verdict_for()` -- the file stays small (one line per
    /// distinct secret sighting per project).
    pub fn check(&self, text: &str) -> Option<TaintMatch> {
        if !self.enabled { return None; }
        let candidates = scan_secrets(text);
        if candidates.is_empty() {
            return None;
        }
        let wanted: Vec<String> = candidates.iter().map(|s| hash_secret(&s.value)).collect();

        let file = std::fs::File::open(&self.path).ok()?;
        let now = Utc::now();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let entry: TaintEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue, // skip malformed
            };
            if !wanted.contains(&entry.hash) {
                continue;
            }
            let age = now.signed_duration_since(entry.ts).num_seconds();
            if age < 0 || age > entry.ttl_secs as i64 {
                continue; // expired (or clock skew from the future)
            }
            return Some(TaintMatch {
                entity_kind: entry.entity_kind,
                source_surface: entry.source_surface,
                source_tool: entry.source_tool,
                age_secs: age,
            });
        }
        None
    }

    /// All non-expired entries, for `--taint-list`. Reads the whole file.
    pub fn list(&self) -> Vec<TaintEntry> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let now = Utc::now();
        let mut out = Vec::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(entry) = serde_json::from_str::<TaintEntry>(&line) {
                let age = now.signed_duration_since(entry.ts).num_seconds();
                if age >= 0 && age <= entry.ttl_secs as i64 {
                    out.push(entry);
                }
            }
        }
        out
    }

    /// Delete the ledger file, for `--taint-flush`. Returns how many
    /// entries were dropped.
    pub fn flush(&self) -> std::io::Result<usize> {
        let count = self.list().len();
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(count),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e),
        }
    }
}

fn resolve_path() -> PathBuf {
    let local = PathBuf::from(".aperion-shield");
    if std::fs::create_dir_all(&local).is_ok() {
        return local.join("taint.jsonl");
    }
    if let Some(home) = dirs::home_dir() {
        let user = home.join(".aperion-shield");
        let _ = std::fs::create_dir_all(&user);
        return user.join("taint.jsonl");
    }
    local.join("taint.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

    fn ledger(tmp: &TempDir) -> TaintLedger {
        TaintLedger::at_path(tmp.path().join("taint.jsonl"), DEFAULT_TTL_SECS, true)
    }

    #[test]
    fn empty_ledger_never_matches() {
        let tmp = TempDir::new().unwrap();
        let l = ledger(&tmp);
        assert!(l.check(&format!("send {AWS}")).is_none());
    }

    #[test]
    fn tag_then_check_matches_same_secret() {
        let tmp = TempDir::new().unwrap();
        let l = ledger(&tmp);
        let n = l.tag_all_in(&format!("your key is {AWS}"), "mcp_tool_result", "fetch_url");
        assert_eq!(n, 1);
        let hit = l.check(&format!("{{\"auth\":\"{AWS}\"}}")).expect("cross-tool hit");
        assert_eq!(hit.entity_kind, "aws_access_key");
        assert_eq!(hit.source_tool, "fetch_url");
        assert_eq!(hit.source_surface, "mcp_tool_result");
    }

    #[test]
    fn different_secret_does_not_match() {
        let tmp = TempDir::new().unwrap();
        let l = ledger(&tmp);
        l.tag_all_in(&format!("key {AWS}"), "mcp_tool_result", "a");
        assert!(l.check("key AKIAIOSFODNN7EXAMPLF").is_none());
    }

    #[test]
    fn expired_entry_is_ignored() {
        let tmp = TempDir::new().unwrap();
        // TTL of 0 seconds: anything tagged is already expired by check time.
        let l = TaintLedger::at_path(tmp.path().join("taint.jsonl"), 0, true);
        l.tag_all_in(&format!("key {AWS}"), "mcp_tool_result", "a");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(l.check(&format!("relay {AWS}")).is_none());
    }

    #[test]
    fn disabled_ledger_is_inert() {
        let tmp = TempDir::new().unwrap();
        let l = TaintLedger::at_path(tmp.path().join("taint.jsonl"), DEFAULT_TTL_SECS, false);
        assert_eq!(l.tag_all_in(&format!("key {AWS}"), "s", "t"), 0);
        assert!(l.check(&format!("relay {AWS}")).is_none());
        assert!(!l.path().exists(), "disabled ledger must not create a file");
    }

    #[test]
    fn list_and_flush() {
        let tmp = TempDir::new().unwrap();
        let l = ledger(&tmp);
        l.tag_all_in(&format!("{AWS} and {}", concat!("sk-", "abcdefghijklmnopqrstuvwx")), "mcp_tool_result", "t");
        assert_eq!(l.list().len(), 2);
        assert_eq!(l.flush().unwrap(), 2);
        assert!(l.list().is_empty());
        // Flushing an already-gone ledger is a no-op, not an error.
        assert_eq!(l.flush().unwrap(), 0);
    }

    #[test]
    fn reason_and_label_never_contain_the_secret() {
        let m = TaintMatch {
            entity_kind: "aws_access_key".into(),
            source_surface: "mcp_tool_result".into(),
            source_tool: "fetch_url".into(),
            age_secs: 3,
        };
        assert!(!m.reason().contains(AWS));
        assert!(m.reason().contains("fetch_url"));
        assert!(m.label().contains("aws_access_key"));
    }
}

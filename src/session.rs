//! Per-project session flags for the v1.8 agent hooks.
//!
//! The post-tool hook (and Cursor's `beforeReadFile`, which already has
//! the file body) records two facts:
//!
//!   * `tainted`  -- this session read a credential store, or a tool
//!     result contained a credential-shaped value.
//!   * `injected` -- a tool result matched prompt-injection rules.
//!
//! The next pre-tool call reads the flags and escalates a network send.
//! The file sits next to the taint ledger (`<cwd>/.aperion-shield/session.json`).
//! Entries expire on the same TTL as taint (default 600s). Raw secrets
//! are never written here; `sources` is a short label ("Read .env"),
//! not the file contents.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::taint::DEFAULT_TTL_SECS;

thread_local! {
    static PATH_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static MIRROR_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Tests point the user-level mirror at a temp file.
pub fn set_mirror_override(path: Option<PathBuf>) {
    MIRROR_OVERRIDE.with(|slot| *slot.borrow_mut() = path);
}

fn user_session_path() -> Option<PathBuf> {
    if let Some(over) = MIRROR_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return Some(over);
    }
    dirs::home_dir().map(|h| h.join(".aperion-shield").join("session.json"))
}

/// Point `SessionStore::open` at a specific file for this thread.
/// Tests use this so a predicate and a hook share a temp ledger without
/// touching the crate directory. Pass `None` to clear.
pub fn set_path_override(path: Option<PathBuf>) {
    PATH_OVERRIDE.with(|slot| *slot.borrow_mut() = path);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFlags {
    pub tainted: bool,
    pub injected: bool,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEntry {
    cwd: String,
    tainted: bool,
    injected: bool,
    updated_at: DateTime<Utc>,
    ttl_secs: u64,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SessionFile {
    #[serde(default)]
    entries: Vec<SessionEntry>,
}

/// Append-friendly store. One JSON document, rewritten on each mark.
/// Best-effort, same as the taint ledger: I/O errors never fail a hook.
#[derive(Debug, Clone)]
pub struct SessionStore {
    path: PathBuf,
    ttl_secs: u64,
}

impl SessionStore {
    pub fn open(ttl_secs: u64) -> Self {
        let path = PATH_OVERRIDE
            .with(|slot| slot.borrow().clone())
            .unwrap_or_else(|| PathBuf::from(".aperion-shield").join("session.json"));
        Self { path, ttl_secs }
    }

    #[cfg(test)]
    pub fn at_path(path: PathBuf, ttl_secs: u64) -> Self {
        Self { path, ttl_secs }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// OR of every non-expired entry. The file is per-project, so a flag
    /// set while the hook's `cwd` differed from the process cwd still
    /// counts.
    pub fn flags(&self) -> SessionFlags {
        let file = match self.read() {
            Some(f) => f,
            None => return SessionFlags::default(),
        };
        let now = Utc::now();
        let mut out = SessionFlags::default();
        for entry in file.entries {
            if !fresh(&entry, now) {
                continue;
            }
            out.tainted |= entry.tainted;
            out.injected |= entry.injected;
            for s in entry.sources {
                if !out.sources.contains(&s) {
                    out.sources.push(s);
                }
            }
        }
        out
    }

    /// Set `tainted` and/or `injected` for `cwd`. A `false` flag does not
    /// clear a flag that was already set inside the TTL.
    pub fn mark(&self, cwd: &str, tainted: bool, injected: bool, source: &str) {
        if !tainted && !injected {
            return;
        }
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let now = Utc::now();
        let mut file = self.read().unwrap_or_default();
        file.entries.retain(|e| fresh(e, now));
        let cwd_key = if cwd.is_empty() {
            ".".to_string()
        } else {
            cwd.to_string()
        };
        if let Some(entry) = file.entries.iter_mut().find(|e| e.cwd == cwd_key) {
            entry.tainted |= tainted;
            entry.injected |= injected;
            entry.updated_at = now;
            entry.ttl_secs = self.ttl_secs;
            push_source(&mut entry.sources, source);
        } else {
            let mut sources = Vec::new();
            push_source(&mut sources, source);
            file.entries.push(SessionEntry {
                cwd: cwd_key,
                tainted,
                injected,
                updated_at: now,
                ttl_secs: self.ttl_secs,
                sources,
            });
        }
        if let Ok(body) = serde_json::to_string(&file) {
            let _ = fs::write(&self.path, body);
        }
        self.mirror_user_level();
    }

    /// Copy the live flags to `~/.aperion-shield/session.json` so Edge's
    /// native host can see a tainted session without knowing the project
    /// directory. Best-effort. A store that is already the user file, or
    /// that does not live under `.aperion-shield`, does not mirror.
    fn mirror_user_level(&self) {
        let Some(user) = user_session_path() else {
            return;
        };
        if user == self.path {
            return;
        }
        let in_shield_dir = self
            .path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n == ".aperion-shield")
            .unwrap_or(false);
        if !in_shield_dir {
            return;
        }
        let flags = self.flags();
        if !flags.tainted && !flags.injected {
            return;
        }
        let source = flags
            .sources
            .last()
            .cloned()
            .unwrap_or_else(|| "session".to_string());
        let user_store = SessionStore {
            path: user,
            ttl_secs: self.ttl_secs,
        };
        user_store.mark("machine", flags.tainted, flags.injected, &source);
    }

    fn read(&self) -> Option<SessionFile> {
        let raw = fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&raw).ok()
    }
}

fn fresh(entry: &SessionEntry, now: DateTime<Utc>) -> bool {
    let age = now.signed_duration_since(entry.updated_at).num_seconds();
    age >= 0 && age <= entry.ttl_secs as i64
}

fn push_source(sources: &mut Vec<String>, source: &str) {
    let source = source.trim();
    if source.is_empty() || sources.iter().any(|s| s == source) {
        return;
    }
    if sources.len() >= 8 {
        sources.remove(0);
    }
    sources.push(source.to_string());
}

/// Flags from the process-cwd store. Predicates call this; they only
/// have the command string, not the hook's session handle.
pub fn current_flags() -> SessionFlags {
    SessionStore::open(DEFAULT_TTL_SECS).flags()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_then_flags_round_trip_and_expire() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SessionStore::at_path(tmp.path().join("session.json"), 600);
        assert!(!store.flags().tainted);
        store.mark("/work", true, false, "Read .env");
        let flags = store.flags();
        assert!(flags.tainted);
        assert!(!flags.injected);
        assert_eq!(flags.sources, vec!["Read .env".to_string()]);

        store.mark("/work", false, true, "injection in README");
        let flags = store.flags();
        assert!(
            flags.tainted,
            "a later injected mark must not clear tainted"
        );
        assert!(flags.injected);
    }

    #[test]
    fn mark_mirrors_to_the_user_session_file() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj").join(".aperion-shield");
        std::fs::create_dir_all(&project).unwrap();
        let mirror = tmp.path().join("home-session.json");
        set_mirror_override(Some(mirror.clone()));
        let store = SessionStore::at_path(project.join("session.json"), 600);
        store.mark("/work", true, false, "Read .env");
        set_mirror_override(None);
        let raw = std::fs::read_to_string(&mirror).unwrap();
        assert!(raw.contains("\"tainted\":true"), "{raw}");
        assert!(raw.contains("machine"));
    }
}

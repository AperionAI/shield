//! On-disk, hash-chained event spool for an enrolled device.
//!
//! Every Shield decision that isn't a plain allow is appended to
//! `spool/events.jsonl` with `prev_hash` and `hash`, so the server can
//! tell when events were dropped or rewritten. Allows are tallied per tool
//! and go out as one summary event. Hook processes, the MCP proxy, and the
//! guard all write here; whichever process holds `send.lock` forwards.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use fs2::FileExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::audit_sink::AuditEvent;
use super::client::{OrgApi, OrgApiError};

const EVENTS: &str = "events.jsonl";
const HEAD: &str = "head";
const SENT: &str = "sent";
const ALLOWS: &str = "allows.json";
const LOCK: &str = "lock";
const SEND_LOCK: &str = "send.lock";
pub const GENESIS: &str = "genesis";
const BATCH: usize = 200;
/// Fully-sent spool files past this size are truncated.
const COMPACT_BYTES: u64 = 1 << 20;

pub struct Spool {
    dir: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Forwarded {
    Idle,
    Busy,
    Sent(usize),
}

fn hash_event(prev: &str, ev: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(ev.to_string().as_bytes());
    hex::encode(h.finalize())
}

impl Spool {
    pub fn open() -> anyhow::Result<Self> {
        Self::at(super::state::shield_dir()?.join("spool"))
    }

    pub fn at(dir: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self { dir })
    }

    fn p(&self, f: &str) -> PathBuf {
        self.dir.join(f)
    }

    fn lock(&self, name: &str) -> anyhow::Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.p(name))?;
        f.lock_exclusive()?;
        Ok(f)
    }

    fn read_trim(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }

    /// Caller holds `lock`.
    fn append_locked(&self, ev: &AuditEvent) -> anyhow::Result<String> {
        let prev = Self::read_trim(&self.p(HEAD)).unwrap_or_else(|| GENESIS.to_string());
        let body = serde_json::to_value(ev)?;
        let hash = hash_event(&prev, &body);
        let mut line = body;
        line["prev_hash"] = json!(prev);
        line["hash"] = json!(hash);
        let mut f = OpenOptions::new().create(true).append(true).open(self.p(EVENTS))?;
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_data()?;
        fs::write(self.p(HEAD), &hash)?;
        Ok(hash)
    }

    pub fn append(&self, ev: &AuditEvent) -> anyhow::Result<String> {
        let _g = self.lock(LOCK)?;
        self.append_locked(ev)
    }

    pub fn count_allow(&self, tool: &str) -> anyhow::Result<()> {
        let _g = self.lock(LOCK)?;
        let mut counts: BTreeMap<String, u64> = fs::read(self.p(ALLOWS))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        *counts.entry(tool.to_string()).or_default() += 1;
        fs::write(self.p(ALLOWS), serde_json::to_vec(&counts)?)?;
        Ok(())
    }

    /// Move the allow tallies into the chain as one event.
    pub fn flush_allow_counts(&self) -> anyhow::Result<bool> {
        let _g = self.lock(LOCK)?;
        let counts: BTreeMap<String, u64> = match fs::read(self.p(ALLOWS)) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => return Ok(false),
        };
        if counts.is_empty() {
            return Ok(false);
        }
        let total: u64 = counts.values().sum();
        self.append_locked(&AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            ts: chrono::Utc::now(),
            rule_id: "allow.count".into(),
            decision: "allow".into(),
            severity: "Info".into(),
            tool: "*".into(),
            fingerprint: String::new(),
            context: json!({"total": total, "by_tool": counts}),
        })?;
        fs::remove_file(self.p(ALLOWS))?;
        Ok(true)
    }

    /// Unsent events, oldest first, and the byte offset after the last one.
    fn pending(&self, max: usize) -> anyhow::Result<(Vec<Value>, u64)> {
        let start: u64 = Self::read_trim(&self.p(SENT)).and_then(|s| s.parse().ok()).unwrap_or(0);
        let Ok(mut f) = File::open(self.p(EVENTS)) else {
            return Ok((Vec::new(), start));
        };
        let len = f.metadata()?.len();
        let start = if start > len { 0 } else { start };
        f.seek(SeekFrom::Start(start))?;
        let mut out = Vec::new();
        let mut end = start;
        let mut rd = BufReader::new(f);
        let mut line = String::new();
        while out.len() < max {
            line.clear();
            let n = rd.read_line(&mut line)?;
            if n == 0 || !line.ends_with('\n') {
                break;
            }
            end += n as u64;
            if let Ok(v) = serde_json::from_str::<Value>(line.trim_end()) {
                out.push(v);
            }
        }
        Ok((out, end))
    }

    fn ack(&self, end: u64) -> anyhow::Result<()> {
        let _g = self.lock(LOCK)?;
        let len = fs::metadata(self.p(EVENTS)).map(|m| m.len()).unwrap_or(0);
        if end >= len && len > COMPACT_BYTES {
            fs::write(self.p(EVENTS), b"")?;
            fs::write(self.p(SENT), b"0")?;
        } else {
            fs::write(self.p(SENT), end.to_string())?;
        }
        Ok(())
    }

    /// Send everything unsent. Returns `Busy` when another process is
    /// already forwarding. A 401 comes back as an error so the caller can
    /// stop.
    pub async fn forward(&self, api: &OrgApi) -> Result<Forwarded, OrgApiError> {
        let net = |e: anyhow::Error| OrgApiError::Decode(e.to_string());
        let send_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.p(SEND_LOCK))
            .map_err(|e| net(e.into()))?;
        if send_lock.try_lock_exclusive().is_err() {
            return Ok(Forwarded::Busy);
        }
        let mut sent = 0;
        loop {
            let (batch, end) = self.pending(BATCH).map_err(net)?;
            if batch.is_empty() {
                break;
            }
            api.post_events(&batch).await?;
            self.ack(end).map_err(net)?;
            sent += batch.len();
        }
        Ok(if sent == 0 { Forwarded::Idle } else { Forwarded::Sent(sent) })
    }

    #[cfg(test)]
    fn all(&self) -> Vec<Value> {
        self.pending(usize::MAX).unwrap().0
    }
}

/// Recompute the chain over `events`, starting from `prev`. Returns the
/// index of the first event whose link or hash doesn't check out.
pub fn verify_chain(prev: &str, events: &[Value]) -> Option<usize> {
    let mut prev = prev.to_string();
    for (i, ev) in events.iter().enumerate() {
        let mut body = ev.clone();
        let obj = body.as_object_mut()?;
        let got_prev = obj.remove("prev_hash").and_then(|v| v.as_str().map(str::to_string));
        let got_hash = obj.remove("hash").and_then(|v| v.as_str().map(str::to_string));
        if got_prev.as_deref() != Some(prev.as_str()) || got_hash.as_deref() != Some(&hash_event(&prev, &body)) {
            return Some(i);
        }
        prev = got_hash.unwrap_or_default();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(rule: &str) -> AuditEvent {
        AuditEvent {
            id: rule.into(),
            ts: chrono::Utc::now(),
            rule_id: rule.into(),
            decision: "block".into(),
            severity: "High".into(),
            tool: "shell".into(),
            fingerprint: "f".into(),
            context: json!({}),
        }
    }

    #[test]
    fn chain_links_and_detects_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Spool::at(tmp.path().to_path_buf()).unwrap();
        s.append(&ev("a")).unwrap();
        s.append(&ev("b")).unwrap();
        s.append(&ev("c")).unwrap();
        let mut all = s.all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["prev_hash"], GENESIS);
        assert_eq!(all[1]["prev_hash"], all[0]["hash"]);
        assert_eq!(verify_chain(GENESIS, &all), None);
        all[1]["decision"] = json!("allow");
        assert_eq!(verify_chain(GENESIS, &all), Some(1));
        all.remove(1);
        assert_eq!(verify_chain(GENESIS, &all), Some(1));
    }

    #[test]
    fn allows_become_one_counted_event() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Spool::at(tmp.path().to_path_buf()).unwrap();
        assert!(!s.flush_allow_counts().unwrap());
        s.count_allow("shell").unwrap();
        s.count_allow("shell").unwrap();
        s.count_allow("fs.read").unwrap();
        assert!(s.flush_allow_counts().unwrap());
        let all = s.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0]["rule_id"], "allow.count");
        assert_eq!(all[0]["context"]["total"], 3);
        assert_eq!(all[0]["context"]["by_tool"]["shell"], 2);
        assert!(!s.flush_allow_counts().unwrap());
    }

    #[test]
    fn ack_advances_and_compacts_without_breaking_the_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Spool::at(tmp.path().to_path_buf()).unwrap();
        s.append(&ev("a")).unwrap();
        let (batch, end) = s.pending(10).unwrap();
        assert_eq!(batch.len(), 1);
        s.ack(end).unwrap();
        assert!(s.pending(10).unwrap().0.is_empty());
        s.append(&ev("b")).unwrap();
        let next = s.pending(10).unwrap().0;
        assert_eq!(next.len(), 1);
        assert_eq!(next[0]["prev_hash"], batch[0]["hash"]);
    }
}

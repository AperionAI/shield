//! Root watchdog (v1.23).
//!
//! `aperion-shield --watchdog` runs as a system service installed by MDM.
//! It holds root-owned reference copies of the managed agent settings
//! (Claude Code managed-settings.json, Cursor's system hooks.json) and
//! puts them back if they change, and it restarts each enrolled user's
//! guard when it isn't running. Forwarding stays in the user guard, which
//! can read the user's keystore. What the watchdog fixes is written into
//! the user's spool as a tamper event, so it reaches Smartflow.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::orgmode::audit_sink::AuditEvent;
use crate::orgmode::spool::Spool;

pub const LAUNCHD_LABEL: &str = "ai.aperion.shield.watchdog";
pub const SYSTEMD_UNIT: &str = "aperion-shield-watchdog.service";
const MANIFEST: &str = "protected.json";

/// Root-owned directory for reference copies.
pub fn system_dir() -> PathBuf {
    if let Ok(d) = std::env::var("APERION_SHIELD_SYSTEM_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Aperion/Shield")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Aperion\Shield")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        PathBuf::from("/etc/aperion-shield")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Protected {
    pub target: PathBuf,
    pub reference: PathBuf,
    pub sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn load_manifest(dir: &Path) -> Vec<Protected> {
    fs::read(dir.join(MANIFEST))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Write `body` to `target` and keep a reference copy the watchdog
/// restores from. Needs write access to `dir` (root in production).
pub fn protect(dir: &Path, target: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(target, body).with_context(|| format!("write {}", target.display()))?;
    let refs = dir.join("protected");
    fs::create_dir_all(&refs).with_context(|| format!("create {}", refs.display()))?;
    let sha = sha256_hex(body);
    let reference = refs.join(format!("{}.ref", &sha256_hex(target.to_string_lossy().as_bytes())[..16]));
    fs::write(&reference, body)?;
    let mut manifest = load_manifest(dir);
    manifest.retain(|p| p.target != target);
    manifest.push(Protected {
        target: target.to_path_buf(),
        reference,
        sha256: sha,
    });
    fs::write(dir.join(MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

/// Put back any protected file that was edited or removed. Returns the
/// targets that were restored.
pub fn restore_protected(dir: &Path) -> Vec<PathBuf> {
    let mut restored = Vec::new();
    for p in load_manifest(dir) {
        let current = fs::read(&p.target).ok();
        if current.as_deref().map(sha256_hex).as_deref() == Some(p.sha256.as_str()) {
            continue;
        }
        let Ok(body) = fs::read(&p.reference) else { continue };
        if sha256_hex(&body) != p.sha256 {
            continue;
        }
        if let Some(parent) = p.target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&p.target, &body).is_ok() {
            restored.push(p.target);
        }
    }
    restored
}

/// An enrolled user on this machine.
#[derive(Debug, Clone)]
pub struct EnrolledUser {
    pub home: PathBuf,
    pub shield_dir: PathBuf,
}

/// Homes under `roots` with an `orgmode.json`.
pub fn enrolled_users(roots: &[PathBuf]) -> Vec<EnrolledUser> {
    let mut out = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else { continue };
        for e in entries.flatten() {
            let home = e.path();
            let shield_dir = home.join(".aperion-shield");
            if shield_dir.join(crate::orgmode::ORG_STATE_FILE).is_file() {
                out.push(EnrolledUser { home, shield_dir });
            }
        }
    }
    out
}

fn default_home_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/Users")]
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec![PathBuf::from("/home"), PathBuf::from("/root")]
    }
}

/// Append a tamper event to the user's spool and hand the files back to
/// the user, so their hooks can keep writing.
pub fn record_tamper(user: &EnrolledUser, rule_id: &str, detail: serde_json::Value) -> Result<()> {
    let spool_dir = user.shield_dir.join("spool");
    let spool = Spool::at(spool_dir.clone())?;
    spool.append(&AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        ts: chrono::Utc::now(),
        rule_id: rule_id.to_string(),
        decision: "warn".into(),
        severity: "High".into(),
        tool: "shield.watchdog".into(),
        fingerprint: String::new(),
        context: detail,
    })?;
    give_back(&user.shield_dir, &spool_dir);
    Ok(())
}

#[cfg(unix)]
fn give_back(owner_of: &Path, dir: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = fs::metadata(owner_of) else { return };
    let (uid, gid) = (meta.uid(), meta.gid());
    let _ = std::os::unix::fs::chown(dir, Some(uid), Some(gid));
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::os::unix::fs::chown(e.path(), Some(uid), Some(gid));
        }
    }
}

#[cfg(not(unix))]
fn give_back(_owner_of: &Path, _dir: &Path) {}

/// Start the user's guard if it is installed but not running. Returns
/// true when it had to be started.
#[cfg(target_os = "macos")]
fn ensure_guard(user: &EnrolledUser) -> bool {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;
    let plist = crate::guard::unit_path(&user.home);
    if !plist.is_file() {
        return false;
    }
    let Ok(uid) = fs::metadata(&user.home).map(|m| m.uid()) else { return false };
    let domain = format!("gui/{uid}");
    let logged_in = Command::new("launchctl").args(["print", &domain]).output().is_ok_and(|o| o.status.success());
    if !logged_in {
        return false;
    }
    let svc = format!("{domain}/{}", crate::guard::LAUNCHD_LABEL);
    let running = Command::new("launchctl")
        .args(["print", &svc])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("state = running"));
    if running {
        return false;
    }
    let _ = Command::new("launchctl").args(["bootstrap", &domain, &plist.display().to_string()]).status();
    let _ = Command::new("launchctl").args(["kickstart", &svc]).status();
    true
}

#[cfg(all(unix, not(target_os = "macos")))]
fn ensure_guard(user: &EnrolledUser) -> bool {
    use std::process::Command;
    if !crate::guard::unit_path(&user.home).is_file() {
        return false;
    }
    let Some(name) = user.home.file_name().and_then(|n| n.to_str()) else { return false };
    let machine = format!("{name}@");
    let active = Command::new("systemctl")
        .args(["--user", "--machine", &machine, "is-active", "--quiet", crate::guard::SYSTEMD_UNIT])
        .status()
        .is_ok_and(|s| s.success());
    if active {
        return false;
    }
    Command::new("systemctl")
        .args(["--user", "--machine", &machine, "start", crate::guard::SYSTEMD_UNIT])
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
fn ensure_guard(_user: &EnrolledUser) -> bool {
    false
}

#[derive(Debug, Default)]
pub struct WatchdogTick {
    pub restored: Vec<PathBuf>,
    pub guards_started: usize,
}

pub fn tick(dir: &Path, home_roots: &[PathBuf]) -> WatchdogTick {
    let users = enrolled_users(home_roots);
    let restored = restore_protected(dir);
    let mut guards_started = 0;
    for user in &users {
        for path in &restored {
            let _ = record_tamper(
                user,
                "tamper.managed_settings_restored",
                serde_json::json!({"path": path.display().to_string()}),
            );
        }
        if ensure_guard(user) {
            guards_started += 1;
            let _ = record_tamper(user, "tamper.guard_restarted", serde_json::json!({}));
        }
    }
    WatchdogTick { restored, guards_started }
}

pub fn run(interval: Duration, once: bool) -> Result<i32> {
    let dir = system_dir();
    let roots = default_home_roots();
    loop {
        let t = tick(&dir, &roots);
        if !t.restored.is_empty() || t.guards_started > 0 {
            eprintln!(
                "[shield] watchdog: restored {} file(s), restarted {} guard(s)",
                t.restored.len(),
                t.guards_started
            );
        }
        if once {
            return Ok(0);
        }
        std::thread::sleep(interval);
    }
}

pub fn unit_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from(format!("/etc/systemd/system/{SYSTEMD_UNIT}"))
    }
}

pub fn unit_body(bin: &Path) -> String {
    let bin = bin.display();
    #[cfg(target_os = "macos")]
    {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>--watchdog</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!(
            r#"[Unit]
Description=Aperion Shield watchdog

[Service]
ExecStart={bin} --watchdog
Restart=always

[Install]
WantedBy=multi-user.target
"#
        )
    }
}

/// Write and load the system unit. Run as root.
#[cfg(unix)]
pub fn install(bin: &Path) -> Result<PathBuf> {
    use std::process::Command;
    let path = unit_path();
    fs::write(&path, unit_body(bin)).with_context(|| format!("write {} (run as root)", path.display()))?;
    fs::create_dir_all(system_dir())?;
    #[cfg(target_os = "macos")]
    {
        let p = path.display().to_string();
        let _ = Command::new("launchctl").args(["bootout", "system", &p]).status();
        let ok = Command::new("launchctl").args(["bootstrap", "system", &p]).status()?.success();
        if !ok {
            anyhow::bail!("launchctl bootstrap system failed");
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let ok = Command::new("systemctl").args(["enable", "--now", SYSTEMD_UNIT]).status()?.success();
        if !ok {
            anyhow::bail!("systemctl enable failed");
        }
    }
    Ok(path)
}

#[cfg(not(unix))]
pub fn install(_bin: &Path) -> Result<PathBuf> {
    anyhow::bail!("the watchdog service isn't packaged for Windows yet; deploy managed settings through Intune")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edited_or_deleted_protected_file_is_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let target = tmp.path().join("ClaudeCode/managed-settings.json");
        protect(&sys, &target, b"{\"allowManagedHooksOnly\":true}\n").unwrap();
        assert!(restore_protected(&sys).is_empty());
        fs::write(&target, b"{}").unwrap();
        assert_eq!(restore_protected(&sys), vec![target.clone()]);
        assert_eq!(fs::read(&target).unwrap(), b"{\"allowManagedHooksOnly\":true}\n");
        fs::remove_file(&target).unwrap();
        assert_eq!(restore_protected(&sys).len(), 1);
        assert!(target.is_file());
    }

    #[test]
    fn tampered_reference_is_not_used() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let target = tmp.path().join("t.json");
        protect(&sys, &target, b"good").unwrap();
        let reference = load_manifest(&sys)[0].reference.clone();
        fs::write(&reference, b"evil").unwrap();
        fs::write(&target, b"changed").unwrap();
        assert!(restore_protected(&sys).is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"changed");
    }

    #[test]
    fn restore_is_recorded_in_each_enrolled_users_spool() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("sys");
        let homes = tmp.path().join("Users");
        let alice = homes.join("alice/.aperion-shield");
        fs::create_dir_all(&alice).unwrap();
        fs::write(alice.join(crate::orgmode::ORG_STATE_FILE), "{}").unwrap();
        fs::create_dir_all(homes.join("bob")).unwrap();
        let target = tmp.path().join("hooks.json");
        protect(&sys, &target, b"{\"version\":1}").unwrap();
        fs::write(&target, b"{}").unwrap();
        let t = tick(&sys, std::slice::from_ref(&homes));
        assert_eq!(t.restored.len(), 1);
        let line = fs::read_to_string(alice.join("spool/events.jsonl")).unwrap();
        assert!(line.contains("tamper.managed_settings_restored"));
        assert!(!homes.join("bob/.aperion-shield").exists());
    }
}

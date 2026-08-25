//! On-disk org-mode enrollment record.
//!
//! Persisted at `~/.aperion-shield/orgmode.json` with mode 0600. Stores
//! everything `aperion-shield` needs to continue talking to Smartflow
//! across restarts: the virtual key (treat as bearer secret), device id,
//! policy group, and the smartflow base URL.

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

/// Filename relative to the user's `~/.aperion-shield/` directory.
pub const ORG_STATE_FILE: &str = "orgmode.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgState {
    /// Base URL of the Smartflow control plane, e.g.
    /// `https://smartflow.langsmart.app`. Used for every REST call.
    pub smartflow_url: String,

    /// Virtual key issued by `enterprise_device_api::token_enroll`.
    /// Sent as `Authorization: Bearer <vkey>` on every request.
    pub vkey: String,

    /// Server-assigned device id (uuid v4).
    pub device_id: String,

    /// Policy group this device is bound to. Used to fetch the right
    /// shieldset from `/api/enterprise/shield/shieldset/<group>`.
    pub policy_group: String,

    /// Original enrolling user email (informational; the dashboard
    /// shows it in the fleet view).
    #[serde(default)]
    pub owner_email: Option<String>,

    /// RFC 3339 timestamp of when this device was enrolled.
    pub enrolled_at: String,

    /// Device platform string sent at enrollment time -- "macos",
    /// "linux", or "windows". Drives policy group resolution on the
    /// server.
    pub platform: String,

    /// Friendly device name shown in the fleet view. Defaults to the
    /// machine's hostname.
    pub device_name: String,

    /// Hashed device fingerprint -- prevents the server from issuing
    /// two records for the same physical machine if the user re-enrolls.
    pub device_fingerprint: String,
}

impl OrgState {
    /// Resolve `~/.aperion-shield/orgmode.json`. Honour the
    /// `APERION_SHIELD_HOME` env override so tests don't write into
    /// the real user home.
    pub fn default_path() -> anyhow::Result<PathBuf> {
        let dir = if let Ok(custom) = std::env::var("APERION_SHIELD_HOME") {
            PathBuf::from(custom)
        } else {
            let mut home =
                dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
            home.push(".aperion-shield");
            home
        };
        std::fs::create_dir_all(&dir).context("create ~/.aperion-shield/")?;
        Ok(dir.join(ORG_STATE_FILE))
    }

    /// Load if present; `Ok(None)` means "not enrolled" (the normal
    /// standalone path).
    pub fn load() -> anyhow::Result<Option<Self>> {
        let path = Self::default_path()?;
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let state: OrgState =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        Ok(Some(state))
    }

    /// Persist atomically with mode 0600 on Unix.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::default_path()?;
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
        Ok(())
    }

    /// Remove the on-disk file. Used by `aperion-shield disenroll`.
    pub fn remove() -> anyhow::Result<()> {
        let path = Self::default_path()?;
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
        Ok(())
    }

    /// Derive a fingerprint that's stable across re-enrolls on the
    /// same physical machine but doesn't leak anything sensitive.
    /// SHA-256 of `<hostname>|<os-name>|<machine-id-if-available>`.
    pub fn fingerprint() -> String {
        use sha2::{Digest, Sha256};
        let hostname = hostname_string();
        let os = std::env::consts::OS.to_string();
        let machine_id = machine_id_string();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}|{}|{}", hostname, os, machine_id).as_bytes());
        hex::encode(hasher.finalize())
    }
}

fn hostname_string() -> String {
    // Fallback chain: HOSTNAME env, then uname-style read, then "unknown".
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn machine_id_string() -> String {
    // Best-effort. On Linux /etc/machine-id is universal; on macOS we
    // hash IOPlatformUUID; on Windows we use the registry's MachineGuid
    // (skip Windows for now -- not deployed).
    if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
        return s.trim().to_string();
    }
    if cfg!(target_os = "macos") {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            if let Ok(s) = String::from_utf8(out.stdout) {
                for line in s.lines() {
                    if let Some(idx) = line.find("IOPlatformUUID") {
                        if let Some(uuid) = line[idx..].split('"').nth(3) {
                            return uuid.to_string();
                        }
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let a = OrgState::fingerprint();
        let b = OrgState::fingerprint();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}

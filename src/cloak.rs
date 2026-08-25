//! Reversible secret cloaking (v1.4).
//!
//! Register a secret under a NAME, then reference it in your agent's
//! tool-call arguments as the placeholder `{{cloak:NAME}}`. Shield resolves
//! the placeholder to the real secret value **only on the copy of the frame
//! it forwards to the real MCP server** — so the real secret never lives in
//! the agent / LLM context, the transcript, or any prompt cache.
//!
//! In the reverse direction, any registered secret value that appears in a
//! `tools/call` result is scrubbed back to its `{{cloak:NAME}}` placeholder
//! before the result is handed to the agent, so a compromised or curious
//! upstream server cannot echo a secret into the model's context.
//!
//! This is the reversible complement to the v1.3 taint ledger: taint is
//! detect-and-escalate over one-way SHA-256 hashes; cloak is a reversible
//! local vault that transforms the wire at the two proxy seams.
//!
//! ## Storage & threat model
//!
//! The vault lives at `~/.aperion-shield/cloak-vault.json`, written with
//! Unix mode `0600` (owner read/write only) via an atomic tmp+rename — the
//! same on-disk posture as `~/.aperion-shield/identity-key` and
//! `orgmode.json`. Values are **not** encrypted at rest; the file is
//! protected by filesystem permissions. Secret values are never logged and
//! never included in audit events (only NAMEs and placeholders are).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Placeholder wrapper. A registered secret NAME is referenced in tool
/// arguments as `{{cloak:NAME}}`.
const PH_OPEN: &str = "{{cloak:";
const PH_CLOSE: &str = "}}";

/// Render the placeholder token for a secret name: `{{cloak:NAME}}`.
pub fn placeholder(name: &str) -> String {
    format!("{PH_OPEN}{name}{PH_CLOSE}")
}

/// On-disk representation. Kept separate from the runtime struct so the
/// persisted file only ever contains the secret map, never runtime state.
#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultFile {
    #[serde(default)]
    secrets: BTreeMap<String, String>,
}

/// A reversible secret vault plus the runtime toggle and resolved path.
///
/// An *inert* vault (constructed with `enabled = false`, e.g. `--no-cloak`,
/// or one with no registered secrets) performs no resolution or scrubbing —
/// every transform method short-circuits and returns `None`, so the proxy
/// hot path pays nothing.
#[derive(Debug, Clone, Default)]
pub struct CloakVault {
    secrets: BTreeMap<String, String>,
    path: PathBuf,
    enabled: bool,
}

impl CloakVault {
    /// Load the vault from `~/.aperion-shield/cloak-vault.json`. A missing
    /// or malformed file yields an empty vault (never an error — the vault
    /// must never break startup). `enabled = false` makes the vault inert
    /// regardless of stored contents.
    pub fn load(enabled: bool) -> Self {
        let path = resolve_path();
        Self {
            secrets: read_secrets(&path),
            path,
            enabled,
        }
    }

    /// Load from an explicit path (tests, and any embedder that wants a
    /// project-local vault instead of the home-dir default).
    pub fn at_path(path: PathBuf, enabled: bool) -> Self {
        let secrets = read_secrets(&path);
        Self {
            secrets,
            path,
            enabled,
        }
    }

    /// Vault file path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// True when cloaking is enabled AND at least one secret is registered —
    /// i.e. when a transform could actually do something.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.secrets.is_empty()
    }

    /// Number of registered secrets.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// True when no secrets are registered.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Registered secret names, sorted (never the values).
    pub fn names(&self) -> Vec<&str> {
        self.secrets.keys().map(|s| s.as_str()).collect()
    }

    /// Register (or overwrite) a secret value under `name`.
    pub fn register(&mut self, name: &str, value: &str) {
        self.secrets.insert(name.to_string(), value.to_string());
    }

    /// Remove a secret. Returns true if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.secrets.remove(name).is_some()
    }

    /// Persist the vault atomically with mode `0600`.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = VaultFile {
            secrets: self.secrets.clone(),
        };
        let json = serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".to_string());
        atomic_write_0600(&self.path, json.as_bytes())
    }

    // ── Wire transforms ────────────────────────────────────────────────

    /// Uncloak a client `tools/call` request for upstream dispatch: replace
    /// every `{{cloak:NAME}}` placeholder in `params.arguments` with the real
    /// secret value. Returns `Some(serialized_frame)` when at least one
    /// placeholder was resolved, else `None` (caller forwards the original
    /// frame unchanged — zero-copy fast path).
    ///
    /// Only `tools/call` frames are touched, and only the `arguments`
    /// subtree, so a placeholder that happens to appear elsewhere in the
    /// JSON-RPC envelope is left alone.
    pub fn uncloak_request(&self, req: &Value) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        if req.get("method").and_then(|m| m.as_str()) != Some("tools/call") {
            return None;
        }
        let mut cloned = req.clone();
        let resolved = cloned
            .pointer_mut("/params/arguments")
            .map(|a| self.resolve_value(a))
            .unwrap_or(0);
        if resolved == 0 {
            return None;
        }
        Some(cloned.to_string())
    }

    /// Scrub registered secret values out of an arbitrary string, replacing
    /// each with its `{{cloak:NAME}}` placeholder. Used for audit snippets so
    /// a secret can never leak into a log line. Returns the input unchanged
    /// when the vault is inert or nothing matched.
    pub fn scrub_plain(&self, s: &str) -> String {
        if !self.is_active() {
            return s.to_string();
        }
        self.scrub_str(s).unwrap_or_else(|| s.to_string())
    }

    /// Scrub registered secret values out of a `tools/call` result frame,
    /// replacing each occurrence with its `{{cloak:NAME}}` placeholder before
    /// the result reaches the agent. Returns `Some(serialized_frame)` when
    /// something was scrubbed, else `None`.
    pub fn scrub_response(&self, parsed: &Value) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        let mut cloned = parsed.clone();
        let scrubbed = cloned
            .get_mut("result")
            .map(|r| self.scrub_value(r))
            .unwrap_or(0);
        if scrubbed == 0 {
            return None;
        }
        Some(cloned.to_string())
    }

    // ── Internals ──────────────────────────────────────────────────────

    /// Replace `{{cloak:NAME}}` placeholders in a single string. Returns the
    /// rewritten string only if at least one known placeholder was present.
    fn resolve_str(&self, s: &str) -> Option<String> {
        if !s.contains(PH_OPEN) {
            return None;
        }
        let mut out = s.to_string();
        let mut hit = false;
        for (name, value) in &self.secrets {
            let ph = placeholder(name);
            if out.contains(&ph) {
                out = out.replace(&ph, value);
                hit = true;
            }
        }
        if hit {
            Some(out)
        } else {
            None
        }
    }

    fn resolve_value(&self, v: &mut Value) -> usize {
        match v {
            Value::String(s) => {
                if let Some(new) = self.resolve_str(s) {
                    *s = new;
                    1
                } else {
                    0
                }
            }
            Value::Array(items) => items.iter_mut().map(|it| self.resolve_value(it)).sum(),
            Value::Object(map) => map.values_mut().map(|it| self.resolve_value(it)).sum(),
            _ => 0,
        }
    }

    /// Replace real secret values in a single string with their placeholders.
    fn scrub_str(&self, s: &str) -> Option<String> {
        let mut out = s.to_string();
        let mut hit = false;
        for (name, value) in &self.secrets {
            if value.is_empty() {
                continue;
            }
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &placeholder(name));
                hit = true;
            }
        }
        if hit {
            Some(out)
        } else {
            None
        }
    }

    fn scrub_value(&self, v: &mut Value) -> usize {
        match v {
            Value::String(s) => {
                if let Some(new) = self.scrub_str(s) {
                    *s = new;
                    1
                } else {
                    0
                }
            }
            Value::Array(items) => items.iter_mut().map(|it| self.scrub_value(it)).sum(),
            Value::Object(map) => map.values_mut().map(|it| self.scrub_value(it)).sum(),
            _ => 0,
        }
    }
}

fn read_secrets(path: &PathBuf) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<VaultFile>(&s).ok())
        .map(|v| v.secrets)
        .unwrap_or_default()
}

/// Resolve the vault path. Unlike the per-project taint ledger, the cloak
/// vault holds raw secrets, so it defaults to the user's home directory
/// (never the project dir, which is often committed).
fn resolve_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        let dir = home.join(".aperion-shield");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("cloak-vault.json");
    }
    PathBuf::from(".aperion-shield").join("cloak-vault.json")
}

/// Write `bytes` to `path` via a tmp file + rename, chmod `0600` on Unix.
fn atomic_write_0600(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn vault(tmp: &TempDir) -> CloakVault {
        CloakVault::at_path(tmp.path().join("cloak-vault.json"), true)
    }

    #[test]
    fn placeholder_format() {
        assert_eq!(placeholder("stripe_key"), "{{cloak:stripe_key}}");
    }

    #[test]
    fn uncloak_resolves_placeholder_in_arguments_only() {
        let tmp = TempDir::new().unwrap();
        let mut v = vault(&tmp);
        v.register("stripe_key", "sk_live_ABC123");
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "http_post", "arguments": {
                "url": "https://api.stripe.com",
                "headers": { "Authorization": "Bearer {{cloak:stripe_key}}" }
            }}
        });
        let out = v.uncloak_request(&req).expect("should resolve");
        assert!(out.contains("Bearer sk_live_ABC123"));
        assert!(!out.contains("{{cloak:stripe_key}}"));
    }

    #[test]
    fn uncloak_ignores_non_tool_call() {
        let tmp = TempDir::new().unwrap();
        let mut v = vault(&tmp);
        v.register("k", "secret");
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        assert!(v.uncloak_request(&req).is_none());
    }

    #[test]
    fn uncloak_none_when_no_placeholder() {
        let tmp = TempDir::new().unwrap();
        let mut v = vault(&tmp);
        v.register("k", "secret");
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hello" } }
        });
        assert!(v.uncloak_request(&req).is_none());
    }

    #[test]
    fn scrub_replaces_leaked_secret_with_placeholder() {
        let tmp = TempDir::new().unwrap();
        let mut v = vault(&tmp);
        v.register("stripe_key", "sk_live_ABC123");
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": [
                { "type": "text", "text": "your key is sk_live_ABC123 do not share" }
            ]}
        });
        let out = v.scrub_response(&resp).expect("should scrub");
        assert!(out.contains("{{cloak:stripe_key}}"));
        assert!(!out.contains("sk_live_ABC123"));
    }

    #[test]
    fn round_trip_never_exposes_secret_to_agent() {
        let tmp = TempDir::new().unwrap();
        let mut v = vault(&tmp);
        v.register("token", "T0P-SECRET-VALUE");
        // Outbound: agent sends placeholder -> upstream sees the real value.
        let req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "call", "arguments": { "auth": "{{cloak:token}}" } }
        });
        let upstream = v.uncloak_request(&req).unwrap();
        assert!(upstream.contains("T0P-SECRET-VALUE"));
        // Inbound: upstream echoes the value -> agent sees the placeholder.
        let resp: Value = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":7,"result":{"echo":"T0P-SECRET-VALUE"}}"#,
        )
        .unwrap();
        let scrubbed = v.scrub_response(&resp).unwrap();
        assert!(scrubbed.contains("{{cloak:token}}"));
        assert!(!scrubbed.contains("T0P-SECRET-VALUE"));
    }

    #[test]
    fn inert_vault_is_noop() {
        let tmp = TempDir::new().unwrap();
        let mut v = CloakVault::at_path(tmp.path().join("cloak-vault.json"), false);
        v.register("k", "secret");
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "call", "arguments": { "auth": "{{cloak:k}}" } }
        });
        assert!(v.uncloak_request(&req).is_none());
    }

    #[test]
    fn save_and_reload_persists_secrets() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("cloak-vault.json");
        {
            let mut v = CloakVault::at_path(path.clone(), true);
            v.register("a", "one");
            v.register("b", "two");
            v.save().unwrap();
        }
        let reloaded = CloakVault::at_path(path, true);
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.names(), vec!["a", "b"]);
    }
}

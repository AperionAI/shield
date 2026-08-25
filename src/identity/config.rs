//! `identity.yaml` -- the configuration file that lists the identity
//! providers Shield can talk to (ID.me, mock, future Okta/Auth0/...).
//!
//! Loaded from one of:
//!   1. The `--identity-config <PATH>` CLI flag.
//!   2. `$APERION_SHIELD_IDENTITY_CONFIG` if set.
//!   3. `~/.aperion-shield/identity.yaml`.
//!   4. Built-in defaults (mock-only) -- so `aperion-shield` always has
//!      *something* to fall back to, and tests don't need a real file
//!      on disk.
//!
//! Schema (all fields optional unless marked required):
//!
//! ```yaml
//! identity:
//!   enabled: true
//!   callback_host: 127.0.0.1     # NEVER 0.0.0.0 -- local only
//!   callback_port: 0             # 0 = OS-assigned random port
//!   hold_seconds: 120            # how long Shield blocks before
//!                                #   returning "verify out-of-band"
//!   providers:
//!     - id: id_me                # required: matches rules[*].identity.provider
//!       kind: id_me              # required: "id_me" | "mock"
//!       sandbox: true            # talk to the ID.me sandbox host
//!       client_id_env: IDME_CLIENT_ID
//!       client_secret_env: IDME_CLIENT_SECRET
//!       scopes: ["openid", "ial2"]
//!     - id: mock
//!       kind: mock
//!       subject: "[email protected]"
//!       email: "[email protected]"
//!       loa: 2
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level YAML wrapper -- matches the existing `shieldset:` style
/// (one named root key) so a single file *could* hold both rules and
/// identity config in the future.
#[derive(Debug, Deserialize)]
struct Root {
    identity: IdentityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_callback_host")]
    pub callback_host: String,

    #[serde(default)]
    pub callback_port: u16,

    #[serde(default = "default_hold")]
    pub hold_seconds: u64,

    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            callback_host: default_callback_host(),
            callback_port: 0,
            hold_seconds: default_hold(),
            providers: vec![ProviderConfig::default_mock()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Stable id referenced by `rules[*].identity.provider` in shieldset.yaml.
    pub id: String,
    pub kind: ProviderKind,

    // ID.me fields ---------------------------------------------------
    #[serde(default)]
    pub sandbox: bool,
    /// Name of the env var holding the client_id.
    #[serde(default)]
    pub client_id_env: Option<String>,
    /// Name of the env var holding the client_secret.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// OAuth scopes to request. Default is `["openid"]`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Override the authorize endpoint (advanced; default depends on
    /// `sandbox`).
    #[serde(default)]
    pub authorize_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub userinfo_url: Option<String>,

    // Mock fields ----------------------------------------------------
    /// Mock-only: synthetic subject id the provider returns on every
    /// verification.
    #[serde(default)]
    pub subject: Option<String>,
    /// Mock-only: synthetic email returned on verification.
    #[serde(default)]
    pub email: Option<String>,
    /// Mock-only: LOA claimed by the synthetic verification.
    #[serde(default)]
    pub loa: u8,
}

impl ProviderConfig {
    pub fn default_mock() -> Self {
        Self {
            id: "mock".to_string(),
            kind: ProviderKind::Mock,
            sandbox: false,
            client_id_env: None,
            client_secret_env: None,
            scopes: default_scopes(),
            authorize_url: None,
            token_url: None,
            userinfo_url: None,
            subject: Some("mock-subject-0001".to_string()),
            email: Some("[email protected]".to_string()),
            loa: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Build the URL, exchange the code, fetch userinfo from ID.me.
    IdMe,
    /// Local "always verifies" provider used for tests and demos.
    Mock,
}

fn default_true() -> bool {
    true
}
fn default_callback_host() -> String {
    "127.0.0.1".to_string()
}
fn default_hold() -> u64 {
    120
}
fn default_scopes() -> Vec<String> {
    vec!["openid".to_string()]
}

impl IdentityConfig {
    /// Parse YAML text.
    pub fn from_yaml(raw: &str) -> anyhow::Result<Self> {
        let root: Root = serde_yaml::from_str(raw)?;
        Ok(root.identity)
    }

    /// Load using the documented precedence: explicit path > env var >
    /// `~/.aperion-shield/identity.yaml` > built-in defaults.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(p) = explicit {
            let raw = std::fs::read_to_string(p)?;
            return Self::from_yaml(&raw);
        }
        if let Ok(p) = std::env::var("APERION_SHIELD_IDENTITY_CONFIG") {
            if !p.is_empty() {
                let raw = std::fs::read_to_string(&p)?;
                return Self::from_yaml(&raw);
            }
        }
        if let Some(home) = dirs::home_dir() {
            let p = home.join(".aperion-shield").join("identity.yaml");
            if p.exists() {
                let raw = std::fs::read_to_string(&p)?;
                return Self::from_yaml(&raw);
            }
        }
        Ok(Self::default())
    }

    /// Best-effort resolution of the state directory: respects
    /// `$APERION_SHIELD_STATE_DIR`, then falls back to
    /// `~/.aperion-shield`.
    pub fn state_dir() -> PathBuf {
        if let Ok(d) = std::env::var("APERION_SHIELD_STATE_DIR") {
            if !d.is_empty() {
                return PathBuf::from(d);
            }
        }
        dirs::home_dir()
            .map(|h| h.join(".aperion-shield"))
            .unwrap_or_else(|| PathBuf::from(".aperion-shield"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_mock_provider() {
        let c = IdentityConfig::default();
        assert!(c.enabled);
        assert_eq!(c.callback_host, "127.0.0.1");
        assert_eq!(c.hold_seconds, 120);
        assert_eq!(c.providers.len(), 1);
        assert_eq!(c.providers[0].id, "mock");
        assert_eq!(c.providers[0].kind, ProviderKind::Mock);
    }

    #[test]
    fn parses_full_yaml() {
        let yaml = r#"
identity:
  enabled: true
  callback_host: 127.0.0.1
  callback_port: 0
  hold_seconds: 90
  providers:
    - id: id_me
      kind: id_me
      sandbox: true
      client_id_env: IDME_CLIENT_ID
      client_secret_env: IDME_CLIENT_SECRET
      scopes: ["openid", "ial2"]
    - id: mock
      kind: mock
      subject: "[email protected]"
      loa: 2
"#;
        let c = IdentityConfig::from_yaml(yaml).unwrap();
        assert_eq!(c.hold_seconds, 90);
        assert_eq!(c.providers.len(), 2);
        assert_eq!(c.providers[0].kind, ProviderKind::IdMe);
        assert!(c.providers[0].sandbox);
        assert_eq!(
            c.providers[0].scopes,
            vec!["openid".to_string(), "ial2".into()]
        );
        assert_eq!(c.providers[1].kind, ProviderKind::Mock);
    }
}

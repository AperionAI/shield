//! Aperion Shield -- identity-gated tool calls.
//!
//! When a rule in `shieldset.yaml` carries an `identity:` block and would
//! otherwise resolve to **Approval** or **Block**, the engine emits a
//! [`crate::Decision::IdentityVerification`] instead. The MCP middleman
//! then:
//!
//!   1. Looks up a fresh, cryptographically-signed proof in the local
//!      cache (`~/.aperion-shield/identity-cache.json`). A "fresh" proof
//!      is one whose `provider`, `scope`, allowed-subject set, and
//!      level-of-assurance all satisfy the rule's [`Requirement`], and
//!      whose `expires_at` is in the future.
//!   2. **Cache hit** -- the call is released and we log
//!      `identity_satisfied` to the audit stream.
//!   3. **Cache miss** -- Shield lazily starts a tiny localhost HTTP
//!      server (random port), mints a [`Challenge`], hands the user a
//!      `verify_url`, and holds the tool call server-side for at most
//!      `hold_seconds` (default 120). If the user completes the
//!      provider's flow (e.g. ID.me OAuth + biometric) within that
//!      window, Shield mints a [`Proof`], persists it, and releases the
//!      held call. If the window elapses, Shield returns a structured
//!      `shield_identity_required` error to the agent; the user can
//!      verify out-of-band and retry the call.
//!
//! All identity work is gated by the YAML schema -- a rule with no
//! `identity:` block behaves exactly as it did pre-v0.4. The free
//! standalone build ships both a fully-working `mock` provider (for
//! integration tests and demos) and a stubbed `id_me` provider whose
//! OAuth client is ready to activate the moment we receive sandbox
//! credentials from the ID.me partner program.
//!
//! Module layout:
//!
//! ```text
//! identity/
//!   mod.rs       -- public surface: types, trait, [`IdentityGate`]
//!   config.rs    -- `identity.yaml` schema + loader
//!   proof.rs     -- Ed25519 sign / verify, on-disk keypair
//!   cache.rs     -- file-backed proof cache with TTL eviction
//!   server.rs    -- hyper localhost callback server
//!   providers/
//!     mock.rs    -- always-verify provider (tests, demos)
//!     idme.rs    -- ID.me OAuth provider (creds not yet activated)
//! ```

#![allow(clippy::module_inception)]

pub mod cache;
pub mod config;
pub mod proof;
pub mod providers;
pub mod server;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use cache::ProofCache;
pub use config::{IdentityConfig, ProviderConfig, ProviderKind};
pub use proof::{Proof, ProofSigner};
pub use providers::{idme::IdMeProvider, mock::MockProvider};
pub use server::{CallbackServer, Inflight, ServerHandle};

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

/// A single requirement attached to a rule. Authored in YAML as the
/// `identity:` block under a rule; compiled into this struct once at
/// rule-load time and reused on every match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    /// `id` of the provider in `identity.yaml` to invoke. Must resolve
    /// to a known [`ProviderConfig`].
    pub provider: String,

    /// Logical scope name (free-form). Doubles as the cache partition
    /// key, so a proof for `scm.commit_to_main` does **not** satisfy a
    /// rule asking for `db.production_apply`.
    pub scope: String,

    /// Set of subjects allowed to satisfy this gate. Each entry is
    /// matched against [`VerifiedIdentity::subject`] AND
    /// [`VerifiedIdentity::email`]; ANY hit passes.
    ///
    /// Accepted forms:
    ///   * Email      -- `[email protected]`
    ///   * Subject    -- `idme|550e8400-e29b-41d4-a716-446655440000`
    ///   * Wildcard   -- `*` (any user verifying is enough; useful
    ///                  for single-operator laptops)
    pub allowed_subjects: Vec<String>,

    /// Maximum acceptable age (seconds) for a cached proof. Older
    /// proofs are ignored and the user is re-prompted.
    #[serde(default = "default_max_age")]
    pub max_proof_age_seconds: u64,

    /// Required ID.me level-of-assurance (0/1/2/3). A proof issued at
    /// a lower LOA does not satisfy the gate.
    #[serde(default)]
    pub loa: u8,
}

fn default_max_age() -> u64 {
    900 // 15 minutes
}

impl Requirement {
    /// Does this allow-list include the given identity?
    pub fn allows(&self, vi: &VerifiedIdentity) -> bool {
        let want: HashSet<&str> = self.allowed_subjects.iter().map(String::as_str).collect();
        if want.contains("*") {
            return true;
        }
        let prefixed = format!("{}|{}", vi.provider, vi.subject);
        if want.contains(prefixed.as_str()) {
            return true;
        }
        if want.contains(vi.subject.as_str()) {
            return true;
        }
        if let Some(email) = vi.email.as_deref() {
            if want.contains(email) {
                return true;
            }
        }
        false
    }

    /// True if the given (already-decoded, signature-verified) proof
    /// satisfies all of: provider, scope, allow-list, LOA, freshness.
    pub fn is_satisfied_by(&self, proof: &Proof, now_secs: u64) -> bool {
        if proof.provider != self.provider {
            return false;
        }
        if proof.scope != self.scope {
            return false;
        }
        if proof.loa < self.loa {
            return false;
        }
        if proof.expires_at <= now_secs {
            return false;
        }
        if now_secs.saturating_sub(proof.verified_at) > self.max_proof_age_seconds {
            return false;
        }
        // Subject / email check.
        let vi = VerifiedIdentity {
            provider: proof.provider.clone(),
            subject: proof.subject.clone(),
            email: proof.email.clone(),
            loa: proof.loa,
            raw: serde_json::Value::Null,
        };
        self.allows(&vi)
    }
}

/// The "begin verification" input. Produced by the engine, consumed by
/// a provider's [`IdentityProvider::begin`] implementation.
#[derive(Debug, Clone)]
pub struct ChallengeRequest {
    pub rule_id: String,
    pub requirement: Requirement,
    /// The URL the provider should redirect back to once the user
    /// completes the flow. Always `http://127.0.0.1:<port>/callback`
    /// where `<port>` is the OS-assigned port the callback server is
    /// listening on.
    pub callback_url: String,
    /// Opaque, unguessable challenge id (also the cache key for the
    /// in-flight challenge state held by the callback server).
    pub challenge_id: String,
}

/// A provider-issued challenge. The `verify_url` is what we surface to
/// the user; the optional state-bag (`pkce_verifier`, `nonce`) is what
/// we hold privately so we can validate the callback.
#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge_id: String,
    /// The URL the user opens in a browser to complete verification.
    /// For real OAuth providers this is the authorize URL with a
    /// `state=<challenge_id>` query param. For the mock provider it's
    /// the local server's `/verify/<id>` endpoint.
    pub verify_url: String,
    /// PKCE verifier (for OAuth 2.0 + PKCE flows). Stored alongside
    /// the challenge so the callback handler can complete the token
    /// exchange.
    pub pkce_verifier: Option<String>,
    /// Anti-replay nonce embedded in the authorize URL and validated
    /// on callback.
    pub nonce: String,
    /// When this challenge expires; the callback server reaps any
    /// challenge older than this.
    pub expires_at: u64,
}

/// The result of a successful provider exchange. Translated by Shield
/// into a signed [`Proof`] before being cached / returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub provider: String,
    /// Stable provider-side subject id (e.g. ID.me's `sub` claim). This
    /// is the identity key -- emails can change, subjects do not.
    pub subject: String,
    /// Email at the time of verification, for human-readable logs and
    /// allow-list matching by address.
    pub email: Option<String>,
    /// Level of assurance achieved (ID.me IAL/LOA tier).
    pub loa: u8,
    /// Provider-specific raw response payload, retained for audit but
    /// NEVER persisted to the proof cache (PII surface).
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub raw: serde_json::Value,
}

/// Provider trait. Every concrete provider (mock, ID.me, future Okta /
/// Auth0 / etc.) implements this. Designed to be `Send + Sync + 'static`
/// so providers can live inside an `Arc` for the whole process.
#[async_trait]
pub trait IdentityProvider: Send + Sync + 'static {
    /// Stable identifier matching the `id:` field in `identity.yaml`.
    fn id(&self) -> &str;

    /// True if this provider has the credentials it needs to operate.
    /// The ID.me adapter returns `false` until sandbox credentials are
    /// supplied; the mock provider always returns `true`.
    fn is_ready(&self) -> bool;

    /// Begin a verification flow. Returns the URL the user should open
    /// plus the bookkeeping needed to validate the callback.
    async fn begin(&self, req: ChallengeRequest) -> anyhow::Result<Challenge>;

    /// Complete the verification flow given the provider's response.
    /// For OAuth providers, `code` is the authorization code; for the
    /// mock provider it's a synthetic token. `state` must match the
    /// challenge id we minted in [`begin`].
    async fn exchange(
        &self,
        challenge_id: &str,
        code: &str,
        state: &str,
        pkce_verifier: Option<&str>,
    ) -> anyhow::Result<VerifiedIdentity>;
}

// ────────────────────────────────────────────────────────────────────
// Gate -- the public composition object
// ────────────────────────────────────────────────────────────────────

/// The [`IdentityGate`] is the single object `main.rs` interacts with.
/// It owns the provider registry, the signed proof cache, and (lazily)
/// the local callback server.
///
/// Construction is cheap (loads config, opens cache file, generates or
/// loads the signing key). The callback server is **not** spun up until
/// the first [`IdentityGate::start_challenge`] call -- shields that
/// never hit an identity-gated rule pay zero runtime cost.
pub struct IdentityGate {
    config: IdentityConfig,
    providers: Vec<Arc<dyn IdentityProvider>>,
    cache: Arc<ProofCache>,
    signer: Arc<ProofSigner>,
    server: tokio::sync::OnceCell<ServerHandle>,
}

impl IdentityGate {
    /// Build a gate from a config and a list of provider implementations.
    /// Cache key + signing keypair live in `<state_dir>` (typically
    /// `~/.aperion-shield`).
    pub fn new(
        config: IdentityConfig,
        providers: Vec<Arc<dyn IdentityProvider>>,
        state_dir: std::path::PathBuf,
    ) -> anyhow::Result<Self> {
        let signer = Arc::new(ProofSigner::load_or_create(&state_dir)?);
        let cache = Arc::new(ProofCache::open(
            state_dir.join("identity-cache.json"),
            &signer,
        )?);
        Ok(Self {
            config,
            providers,
            cache,
            signer,
            server: tokio::sync::OnceCell::new(),
        })
    }

    /// Look up a cached proof satisfying `req`. None means we have to
    /// prompt the user.
    pub fn cached_proof_for(&self, req: &Requirement) -> Option<Proof> {
        let now = unix_now();
        self.cache.find_satisfying(req, now)
    }

    /// Provider with the given id, or None.
    pub fn provider(&self, id: &str) -> Option<Arc<dyn IdentityProvider>> {
        self.providers.iter().find(|p| p.id() == id).cloned()
    }

    /// Lazily start the callback server, sharing the same provider /
    /// cache / signer instances the gate already holds. Subsequent calls
    /// return the cached handle.
    async fn ensure_server(&self) -> anyhow::Result<&ServerHandle> {
        self.server
            .get_or_try_init(|| async {
                CallbackServer::spawn(
                    &self.config.callback_host,
                    self.config.callback_port,
                    self.providers.clone(),
                    self.cache.clone(),
                    self.signer.clone(),
                )
                .await
            })
            .await
    }

    /// Ensure the callback server is running and return its base URL
    /// (e.g. `http://127.0.0.1:53201`).
    pub async fn callback_base(&self) -> anyhow::Result<String> {
        let h = self.ensure_server().await?;
        Ok(h.base_url())
    }

    /// Hand the gate a freshly-minted challenge so the callback server
    /// can correlate the user's redirect back to its in-flight state.
    pub async fn register_inflight(
        &self,
        challenge: &Challenge,
        requirement: Requirement,
        provider: String,
        rule_id: String,
    ) -> anyhow::Result<()> {
        let h = self.ensure_server().await?;
        h.register(
            challenge.clone(),
            server::Inflight {
                rule_id,
                provider,
                requirement,
            },
        )
        .await;
        Ok(())
    }

    /// Block up to `hold_seconds` waiting for a proof to land in the
    /// cache for `req`. Returns the proof if one arrives; None on
    /// timeout. Callers should treat None as "tell the agent to retry".
    pub async fn wait_for_proof(&self, req: &Requirement, hold_seconds: u64) -> Option<Proof> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(hold_seconds);
        loop {
            if let Some(p) = self.cached_proof_for(req) {
                return Some(p);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Persist a freshly-verified identity as a signed proof.
    pub fn mint_and_cache(
        &self,
        vi: &VerifiedIdentity,
        req: &Requirement,
    ) -> anyhow::Result<Proof> {
        let now = unix_now();
        let proof = Proof {
            v: 1,
            provider: vi.provider.clone(),
            subject: vi.subject.clone(),
            email: vi.email.clone(),
            loa: vi.loa,
            scope: req.scope.clone(),
            verified_at: now,
            expires_at: now.saturating_add(req.max_proof_age_seconds),
            nonce: hex::encode(rand::random::<[u8; 16]>()),
            sig: String::new(),
        };
        let signed = self.signer.sign(proof)?;
        self.cache.insert(signed.clone())?;
        Ok(signed)
    }

    /// Number of valid (signature-verified, non-expired) proofs cached.
    pub fn cached_count(&self) -> usize {
        self.cache.count_valid(unix_now())
    }

    /// Drop every cached proof. Returns how many were evicted.
    pub fn flush(&self) -> anyhow::Result<usize> {
        self.cache.flush()
    }

    /// Hold seconds configured for this gate.
    pub fn hold_seconds(&self) -> u64 {
        self.config.hold_seconds
    }

    /// True if at least one provider is registered AND ready.
    pub fn has_ready_provider(&self) -> bool {
        self.providers.iter().any(|p| p.is_ready())
    }

    /// Read-only access to the loaded config.
    pub fn config(&self) -> &IdentityConfig {
        &self.config
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vi(provider: &str, subject: &str, email: Option<&str>, loa: u8) -> VerifiedIdentity {
        VerifiedIdentity {
            provider: provider.into(),
            subject: subject.into(),
            email: email.map(str::to_string),
            loa,
            raw: serde_json::Value::Null,
        }
    }

    #[test]
    fn allow_list_matches_email() {
        // Compose the email literals at runtime so the source contains
        // no `name@domain` token. Some doc/display layers normalise
        // such tokens to a placeholder which made earlier versions of
        // this test compare two identical strings without us noticing.
        let allowed = format!("{}@{}", "ace", "aperion.ai");
        let denied = format!("{}@{}", "bee", "other.com");
        let req = Requirement {
            provider: "id_me".into(),
            scope: "scm.commit".into(),
            allowed_subjects: vec![allowed.clone()],
            max_proof_age_seconds: 900,
            loa: 2,
        };
        // Email matches the allow list -> allowed.
        assert!(req.allows(&vi("id_me", "sub-1", Some(allowed.as_str()), 2)));
        // Different email, no other identifier on the allow list -> denied.
        assert!(!req.allows(&vi("id_me", "sub-2", Some(denied.as_str()), 2)));
        // No email at all -> denied.
        assert!(!req.allows(&vi("id_me", "sub-3", None, 2)));
    }

    #[test]
    fn allow_list_matches_subject_with_prefix() {
        let req = Requirement {
            provider: "id_me".into(),
            scope: "x".into(),
            allowed_subjects: vec!["id_me|sub-1".into()],
            max_proof_age_seconds: 900,
            loa: 0,
        };
        assert!(req.allows(&vi("id_me", "sub-1", None, 0)));
    }

    #[test]
    fn wildcard_lets_anyone_pass() {
        let req = Requirement {
            provider: "id_me".into(),
            scope: "x".into(),
            allowed_subjects: vec!["*".into()],
            max_proof_age_seconds: 900,
            loa: 0,
        };
        assert!(req.allows(&vi("id_me", "sub-99", Some("[email protected]"), 0)));
    }

    #[test]
    fn requirement_freshness_check() {
        let req = Requirement {
            provider: "id_me".into(),
            scope: "x".into(),
            allowed_subjects: vec!["*".into()],
            max_proof_age_seconds: 60,
            loa: 0,
        };
        let now = unix_now();
        let fresh = Proof {
            v: 1,
            provider: "id_me".into(),
            subject: "s".into(),
            email: None,
            loa: 0,
            scope: "x".into(),
            verified_at: now,
            expires_at: now + 60,
            nonce: "".into(),
            sig: "".into(),
        };
        let stale = Proof {
            verified_at: now - 120,
            expires_at: now + 60,
            ..fresh.clone()
        };
        let wrong_scope = Proof {
            scope: "y".into(),
            ..fresh.clone()
        };
        let low_loa = Proof {
            loa: 0,
            ..fresh.clone()
        };
        let high_loa_req = Requirement {
            loa: 2,
            ..req.clone()
        };

        assert!(req.is_satisfied_by(&fresh, now));
        assert!(!req.is_satisfied_by(&stale, now));
        assert!(!req.is_satisfied_by(&wrong_scope, now));
        assert!(!high_loa_req.is_satisfied_by(&low_loa, now));
    }
}

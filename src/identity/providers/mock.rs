//! Mock identity provider.
//!
//! Used by:
//!   * Integration tests (no external service, deterministic output).
//!   * `aperion-shield --check` runs that need to exercise an
//!     identity-gated rule without any browser interaction.
//!   * Local demos before the ID.me sandbox is online.
//!
//! Behaviour:
//!   * [`begin`] returns a `verify_url` of the form
//!     `http://127.0.0.1:<port>/verify/<challenge_id>?mock=1`. When
//!     the user opens that URL, the local callback server immediately
//!     hits [`exchange`] with a synthetic code and the mock returns a
//!     [`VerifiedIdentity`] composed from its config.
//!   * [`exchange`] always succeeds. There is no failure path -- this
//!     is **not** a security boundary; never enable the mock provider
//!     in production.
//!
//! Configuration ([`crate::identity::config::ProviderConfig`]):
//!
//! ```yaml
//! - id: mock
//!   kind: mock
//!   subject: "[email protected]"   # synthetic subject id
//!   email:   "[email protected]"   # synthetic email claim
//!   loa: 2                          # LOA tier the mock claims
//! ```

use async_trait::async_trait;

use crate::identity::{
    Challenge, ChallengeRequest, IdentityProvider, VerifiedIdentity,
};

pub struct MockProvider {
    id: String,
    subject: String,
    email: Option<String>,
    loa: u8,
}

impl MockProvider {
    pub fn new(id: impl Into<String>, subject: impl Into<String>, email: Option<String>, loa: u8) -> Self {
        Self {
            id: id.into(),
            subject: subject.into(),
            email,
            loa,
        }
    }
}

#[async_trait]
impl IdentityProvider for MockProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn is_ready(&self) -> bool {
        true
    }

    async fn begin(&self, req: ChallengeRequest) -> anyhow::Result<Challenge> {
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        // Mock URL: the local callback server matches /verify/<id>?mock=1
        // and short-circuits to an exchange with a synthetic code.
        let verify_url = format!(
            "{base}/verify/{cid}?mock=1",
            base = strip_callback_suffix(&req.callback_url),
            cid = req.challenge_id,
        );
        Ok(Challenge {
            challenge_id: req.challenge_id,
            verify_url,
            pkce_verifier: None,
            nonce,
            expires_at: super::super::unix_now() + 300,
        })
    }

    async fn exchange(
        &self,
        _challenge_id: &str,
        _code: &str,
        _state: &str,
        _pkce_verifier: Option<&str>,
    ) -> anyhow::Result<VerifiedIdentity> {
        Ok(VerifiedIdentity {
            provider: self.id.clone(),
            subject: self.subject.clone(),
            email: self.email.clone(),
            loa: self.loa,
            raw: serde_json::Value::Null,
        })
    }
}

/// `callback_url` is given to providers as `http://host:port/callback`.
/// For the mock URL we want `http://host:port` (so we can compose
/// `/verify/<id>?mock=1`). Strip the trailing `/callback` if present.
fn strip_callback_suffix(callback_url: &str) -> String {
    callback_url
        .strip_suffix("/callback")
        .unwrap_or(callback_url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Requirement;

    #[tokio::test]
    async fn mock_begin_and_exchange_succeed() {
        let p = MockProvider::new("mock", "sub-a", Some("[email protected]".into()), 2);
        let req = ChallengeRequest {
            rule_id: "scm.commit_to_main".into(),
            requirement: Requirement {
                provider: "mock".into(),
                scope: "scm.commit_to_main".into(),
                allowed_subjects: vec!["*".into()],
                max_proof_age_seconds: 900,
                loa: 2,
            },
            callback_url: "http://127.0.0.1:9999/callback".into(),
            challenge_id: "ch-1".into(),
        };
        let ch = p.begin(req).await.unwrap();
        assert_eq!(ch.challenge_id, "ch-1");
        assert!(ch.verify_url.starts_with("http://127.0.0.1:9999/verify/ch-1"));
        let vi = p.exchange("ch-1", "synthetic-code", "ch-1", None).await.unwrap();
        assert_eq!(vi.subject, "sub-a");
        assert_eq!(vi.loa, 2);
    }
}

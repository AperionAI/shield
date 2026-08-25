//! Smartflow-mediated identity gate.
//!
//! When org mode is active the standalone Shield delegates identity
//! verification to Smartflow instead of running its own OAuth dance.
//! Smartflow speaks to the real ID.me (or any configured OIDC IdP) on
//! behalf of the whole org and hands the standalone a short-lived,
//! HMAC-signed assertion.
//!
//! This module does NOT implement [`crate::IdentityProvider`] -- that
//! trait is tied to the local callback server. Instead, the org-mode
//! identity handler in `main.rs` calls `SmartflowProvider::resolve`
//! directly when an enrolled Shield encounters a
//! [`crate::Decision::IdentityVerification`].

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::time::sleep;

use super::client::{IdentityCheckRequest, IdentityCheckResponse, OrgApi};
use crate::IdentityRequirement;

/// Default polling cadence while we wait for the user to complete the
/// browser-side verify flow.
const POLL_EVERY: Duration = Duration::from_secs(2);

/// Outcome of [`SmartflowProvider::resolve`].
#[derive(Debug)]
pub enum ResolveOutcome {
    /// User is already verified for this scope and LOA. The standalone
    /// should release the held tool call immediately. The contained
    /// [`SmartflowProof`] is a server-signed assertion we log for audit.
    Verified(SmartflowProof),

    /// User needs to verify. The standalone surfaces the `verify_url`
    /// to the developer and polls until either the proof lands or
    /// `hold_seconds` elapses (then returns [`ResolveOutcome::HoldExpired`]).
    HoldExpired {
        verify_url: String,
        challenge_id: String,
    },

    /// Provider is not configured on Smartflow's side (e.g. id_me with
    /// no sandbox creds). Treated as a deny.
    ProviderUnready { provider: String, message: String },

    /// Hard error (network, server fault). Treated as a deny -- we
    /// don't want to silently allow a gated call when the control plane
    /// is unreachable.
    Error(SmartflowError),
}

#[derive(Debug, Clone)]
pub struct SmartflowProof {
    pub provider: String,
    pub subject: String,
    pub loa: u8,
    pub expires_at: DateTime<Utc>,
    /// Hex-encoded HMAC over the canonical proof fields. The standalone
    /// stores this in the audit row but doesn't re-verify it locally --
    /// the vkey-authenticated HTTPS connection is the trust boundary.
    pub signature: Option<String>,
}

#[derive(Debug, Error)]
pub enum SmartflowError {
    #[error("network/http: {0}")]
    Net(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("server response: {0}")]
    Server(String),
}

pub struct SmartflowProvider {
    api: Arc<OrgApi>,
    /// How long we wait before giving up on a user verification.
    /// Matches the local identity gate default (120 s).
    pub hold_seconds: u64,
}

impl SmartflowProvider {
    pub fn new(api: Arc<OrgApi>) -> Self {
        Self {
            api,
            hold_seconds: 120,
        }
    }

    pub fn with_hold_seconds(mut self, secs: u64) -> Self {
        self.hold_seconds = secs;
        self
    }

    /// Convert an engine [`IdentityRequirement`] into the wire DTO the
    /// server expects.
    fn requirement_to_request(req: &IdentityRequirement) -> IdentityCheckRequest {
        IdentityCheckRequest {
            provider: req.provider.clone(),
            scope: req.scope.clone(),
            allowed_subjects: req.allowed_subjects.iter().cloned().collect(),
            min_loa: if req.loa == 0 { None } else { Some(req.loa) },
            max_age_seconds: req.max_proof_age_seconds,
        }
    }

    /// Resolve a requirement to an outcome. This is the single public
    /// entry point the org-mode handler calls.
    pub async fn resolve(&self, req: &IdentityRequirement) -> ResolveOutcome {
        let wire = Self::requirement_to_request(req);
        let first = match self.api.identity_check(&wire).await {
            Ok(r) => r,
            Err(super::client::OrgApiError::Http { status: 503, body }) => {
                return ResolveOutcome::ProviderUnready {
                    provider: req.provider.clone(),
                    message: body,
                };
            }
            Err(e) => return ResolveOutcome::Error(SmartflowError::Net(e.to_string())),
        };

        if first.verified {
            return ResolveOutcome::Verified(proof_from_response(req, &first));
        }

        // The server returned a verify URL. Poll until the user
        // completes the flow or we time out.
        let (verify_url, challenge_id) = match (first.verify_url, first.challenge_id) {
            (Some(u), Some(c)) => (u, c),
            _ => {
                return ResolveOutcome::Error(SmartflowError::Server(
                    "server reported unverified but did not return verify_url + challenge_id"
                        .into(),
                ));
            }
        };

        // Best-effort surface to the developer. The MCP middleman will
        // also print a structured JSON-RPC error so the IDE can render
        // a prompt; this stderr line gives a CLI / terminal user the
        // URL even when the IDE is silent.
        eprintln!(
            "[shield] identity verification required for scope='{}' provider='{}'",
            req.scope, req.provider
        );
        eprintln!("[shield] open: {}", verify_url);
        eprintln!(
            "[shield] holding tool call for {}s (challenge={})",
            self.hold_seconds, challenge_id
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(self.hold_seconds);
        while std::time::Instant::now() < deadline {
            sleep(POLL_EVERY).await;
            match self.api.identity_result(&challenge_id).await {
                Ok(r) if r.verified => {
                    return ResolveOutcome::Verified(proof_from_response(req, &r));
                }
                Ok(_) => continue,
                Err(super::client::OrgApiError::Http { status: 404, .. }) => {
                    // Challenge expired server-side -- bail.
                    break;
                }
                Err(e) => {
                    log::warn!("[shield] identity_result poll error: {}", e);
                    // Keep polling -- network blips shouldn't cancel
                    // an in-progress verification.
                }
            }
        }

        ResolveOutcome::HoldExpired {
            verify_url,
            challenge_id,
        }
    }
}

fn proof_from_response(req: &IdentityRequirement, resp: &IdentityCheckResponse) -> SmartflowProof {
    SmartflowProof {
        provider: req.provider.clone(),
        subject: resp.subject.clone().unwrap_or_default(),
        loa: resp.loa.unwrap_or(0),
        expires_at: resp.expires_at.unwrap_or_else(Utc::now),
        signature: resp.signature.clone(),
    }
}

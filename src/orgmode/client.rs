//! Thin reqwest wrapper around the Smartflow REST API.
//!
//! Owns its own `reqwest::Client` with conservative defaults (HTTPS-only
//! in the typical deployment, 10 s timeouts, no fancy connection pool
//! settings -- we make few requests). Errors surface as
//! [`OrgApiError`]; callers decide whether to retry, fall back to local,
//! or propagate.

use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::state::OrgState;

/// Connect timeout per request -- matches what the enterprise
/// device API expects.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum OrgApiError {
    #[error("network: {0}")]
    Network(String),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("decode: {0}")]
    Decode(String),
    #[error("unauthorized -- vkey rejected; the device may have been revoked")]
    Unauthorized,
}

impl From<reqwest::Error> for OrgApiError {
    fn from(e: reqwest::Error) -> Self {
        OrgApiError::Network(e.to_string())
    }
}

pub struct OrgApi {
    http: Client,
    smartflow_url: String,
    vkey: String,
}

impl OrgApi {
    pub fn new(smartflow_url: impl Into<String>, vkey: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(format!("aperion-shield/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client build");
        Self {
            http,
            smartflow_url: smartflow_url.into(),
            vkey: vkey.into(),
        }
    }

    pub fn from_state(state: &OrgState) -> Self {
        Self::new(&state.smartflow_url, &state.vkey)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.smartflow_url.trim_end_matches('/'), path)
    }

    async fn unwrap_response<T: for<'de> Deserialize<'de>>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, OrgApiError> {
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(OrgApiError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrgApiError::Http {
                status: status.as_u16(),
                body,
            });
        }
        resp.json::<T>()
            .await
            .map_err(|e| OrgApiError::Decode(e.to_string()))
    }

    // ── Enrollment ────────────────────────────────────────────────

    /// Exchange a one-time enrollment token for a virtual key + device
    /// id. Uses the existing `enterprise_device_api::token_enroll`
    /// endpoint -- no new server code required for enrollment itself.
    pub async fn token_enroll(
        smartflow_url: &str,
        enrollment_token: &str,
        device_fingerprint: &str,
        device_name: &str,
        platform: &str,
        user_email: Option<&str>,
    ) -> Result<TokenEnrollResponse, OrgApiError> {
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(format!("aperion-shield/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        let body = serde_json::json!({
            "enrollment_token": enrollment_token,
            "device_fingerprint": device_fingerprint,
            "device_name": device_name,
            "platform": platform,
            "user_email": user_email,
        });
        let resp = http
            .post(format!(
                "{}/api/enterprise/devices/token-enroll",
                smartflow_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrgApiError::Http {
                status: status.as_u16(),
                body,
            });
        }
        resp.json::<TokenEnrollResponse>()
            .await
            .map_err(|e| OrgApiError::Decode(e.to_string()))
    }

    // ── Heartbeat ─────────────────────────────────────────────────

    pub async fn heartbeat(&self, device_id: &str) -> Result<(), OrgApiError> {
        let resp = self
            .http
            .post(self.url(&format!(
                "/api/enterprise/devices/{}/heartbeat",
                device_id
            )))
            .bearer_auth(&self.vkey)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrgApiError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    // ── Shieldset (policy) ────────────────────────────────────────

    /// Fetch the current shieldset YAML for a group, returning
    /// `(yaml, version)`. Version comes from the `X-Shield-Policy-Version`
    /// header so the caller can decide whether to hot-reload.
    pub async fn get_shieldset(&self, group: &str) -> Result<(String, u64), OrgApiError> {
        let resp = self
            .http
            .get(self.url(&format!("/api/enterprise/shield/shieldset/{}", group)))
            .bearer_auth(&self.vkey)
            .send()
            .await?;
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(OrgApiError::Unauthorized);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrgApiError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let version: u64 = resp
            .headers()
            .get("X-Shield-Policy-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let yaml = resp.text().await?;
        Ok((yaml, version))
    }

    /// Cheap version probe -- no payload. Used by the policy pull loop
    /// to decide whether to fetch a full shieldset.
    pub async fn get_shieldset_version(&self, group: &str) -> Result<VersionInfo, OrgApiError> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/api/enterprise/shield/shieldset/{}/version",
                group
            )))
            .bearer_auth(&self.vkey)
            .send()
            .await?;
        self.unwrap_response(resp).await
    }

    // ── Events (audit sink) ───────────────────────────────────────

    pub async fn post_events(
        &self,
        events: &[serde_json::Value],
    ) -> Result<EventsAck, OrgApiError> {
        let resp = self
            .http
            .post(self.url("/api/enterprise/shield/events"))
            .bearer_auth(&self.vkey)
            .json(&serde_json::json!({ "events": events }))
            .send()
            .await?;
        self.unwrap_response(resp).await
    }

    // ── Identity (M3) ─────────────────────────────────────────────

    pub async fn identity_check(
        &self,
        req: &IdentityCheckRequest,
    ) -> Result<IdentityCheckResponse, OrgApiError> {
        let resp = self
            .http
            .post(self.url("/api/enterprise/shield/identity/check"))
            .bearer_auth(&self.vkey)
            .json(req)
            .send()
            .await?;
        self.unwrap_response(resp).await
    }

    pub async fn identity_begin(
        &self,
        req: &IdentityCheckRequest,
    ) -> Result<IdentityCheckResponse, OrgApiError> {
        let resp = self
            .http
            .post(self.url("/api/enterprise/shield/identity/begin"))
            .bearer_auth(&self.vkey)
            .json(req)
            .send()
            .await?;
        self.unwrap_response(resp).await
    }

    pub async fn identity_result(
        &self,
        challenge_id: &str,
    ) -> Result<IdentityCheckResponse, OrgApiError> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/api/enterprise/shield/identity/result/{}",
                challenge_id
            )))
            .bearer_auth(&self.vkey)
            .send()
            .await?;
        self.unwrap_response(resp).await
    }

    // ── Info / killswitch ─────────────────────────────────────────

    pub async fn info(&self) -> Result<InfoResponse, OrgApiError> {
        let resp = self
            .http
            .get(self.url("/api/enterprise/shield/info"))
            .bearer_auth(&self.vkey)
            .send()
            .await?;
        self.unwrap_response(resp).await
    }
}

// ─────────────────────────────────────────────────────────────────────
// DTOs
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenEnrollResponse {
    pub device_id: String,
    pub vkey: String,
    pub proxy_url: String,
    pub policy_group: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub policy_ws_url: String,
}

#[derive(Debug, Deserialize)]
pub struct VersionInfo {
    pub group: String,
    pub version: u64,
    pub killswitch: KillswitchState,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct KillswitchState {
    pub on: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventsAck {
    pub ok: bool,
    pub received: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct IdentityCheckRequest {
    pub provider: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_subjects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_loa: Option<u8>,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityCheckResponse {
    pub verified: bool,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub loa: Option<u8>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub verify_url: Option<String>,
    #[serde(default)]
    pub challenge_id: Option<String>,
    #[serde(default)]
    pub provider: String,
}

#[derive(Debug, Deserialize)]
pub struct InfoResponse {
    pub device_id: String,
    pub policy_group: String,
    pub owner_email: String,
    pub policy_version: u64,
    pub killswitch: KillswitchState,
    pub server_time: DateTime<Utc>,
    pub identity_providers: Vec<IdentityProviderInfo>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityProviderInfo {
    pub id: String,
    pub display_name: String,
    pub kind: String,
    pub ready: bool,
}

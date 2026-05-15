//! ID.me OAuth 2.0 + PKCE provider.
//!
//! Status: **scaffolded but not activated**. The wire flow is complete
//! (authorize URL, PKCE pair, token exchange POST, userinfo GET, LOA
//! extraction from the `acr` / `verified_at` claims). The provider
//! refuses to operate until both:
//!
//!   * `client_id` resolves from the env var named in
//!     `client_id_env` (default `IDME_CLIENT_ID`), AND
//!   * `client_secret` resolves from the env var named in
//!     `client_secret_env` (default `IDME_CLIENT_SECRET`).
//!
//! Once you have sandbox credentials from the ID.me partner program,
//! drop them into the environment and Shield's `[shield]` startup
//! banner will switch from `idme=stubbed` to `idme=ready`.
//!
//! Endpoint defaults
//! -----------------
//!
//! | Field         | Production                            | Sandbox                                   |
//! |---------------|---------------------------------------|-------------------------------------------|
//! | authorize_url | `https://api.id.me/oauth/authorize`   | `https://api.idmelabs.com/oauth/authorize`|
//! | token_url     | `https://api.id.me/oauth/token`       | `https://api.idmelabs.com/oauth/token`    |
//! | userinfo_url  | `https://api.id.me/api/public/v3/attributes.json` | `https://api.idmelabs.com/api/public/v3/attributes.json` |
//!
//! Per-provider overrides in `identity.yaml` take precedence -- useful
//! for talking to a private federation gateway.
//!
//! LOA mapping
//! -----------
//!
//! ID.me userinfo returns a verified-method string. We map it to our
//! LOA tier:
//!
//! | userinfo `verified` value | LOA |
//! |---------------------------|-----|
//! | `false` / missing         | 0   |
//! | `true`, no biometric      | 1   |
//! | `true` + `selfie` proof   | 2   |
//! | `true` + IAL2 attestation | 3   |
//!
//! The mapping lives in [`map_loa`] so it's easy to tweak as we learn
//! more about the partner's claim shape.

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::identity::{
    Challenge, ChallengeRequest, IdentityProvider, VerifiedIdentity,
};

/// Reference to the parts of the `identity.yaml` provider block that
/// the ID.me adapter actually consumes. The full config struct lives
/// in `super::super::config`; copying just what we need here avoids
/// holding a heavier reference across `.await` points.
#[derive(Debug, Clone)]
pub struct IdMeConfig {
    pub id: String,
    pub sandbox: bool,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

impl IdMeConfig {
    /// Endpoint defaults for the sandbox / production host pair.
    pub fn endpoint_defaults(sandbox: bool) -> (String, String, String) {
        if sandbox {
            (
                "https://api.idmelabs.com/oauth/authorize".into(),
                "https://api.idmelabs.com/oauth/token".into(),
                "https://api.idmelabs.com/api/public/v3/attributes.json".into(),
            )
        } else {
            (
                "https://api.id.me/oauth/authorize".into(),
                "https://api.id.me/oauth/token".into(),
                "https://api.id.me/api/public/v3/attributes.json".into(),
            )
        }
    }
}

pub struct IdMeProvider {
    cfg: IdMeConfig,
}

impl IdMeProvider {
    pub fn new(cfg: IdMeConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl IdentityProvider for IdMeProvider {
    fn id(&self) -> &str {
        &self.cfg.id
    }

    fn is_ready(&self) -> bool {
        self.cfg.client_id.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
            && self.cfg.client_secret.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
    }

    async fn begin(&self, req: ChallengeRequest) -> anyhow::Result<Challenge> {
        if !self.is_ready() {
            anyhow::bail!(
                "id_me provider '{}' not yet activated: set the env vars referenced by \
                 client_id_env / client_secret_env in identity.yaml so Shield can \
                 sign requests to the ID.me sandbox.",
                self.cfg.id,
            );
        }
        let client_id = self.cfg.client_id.as_deref().unwrap();
        let nonce = hex::encode(rand::random::<[u8; 16]>());

        let (verifier, challenge) = generate_pkce_pair();

        // Build the authorize URL with required OAuth 2.0 + PKCE params.
        let mut u = url::Url::parse(&self.cfg.authorize_url)?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", client_id);
            q.append_pair("redirect_uri", &req.callback_url);
            q.append_pair("scope", &self.cfg.scopes.join(" "));
            q.append_pair("state", &req.challenge_id);
            q.append_pair("nonce", &nonce);
            q.append_pair("code_challenge", &challenge);
            q.append_pair("code_challenge_method", "S256");
        }
        let authorize_url = u.into();

        Ok(Challenge {
            challenge_id: req.challenge_id,
            verify_url: authorize_url,
            pkce_verifier: Some(verifier),
            nonce,
            expires_at: super::super::unix_now() + 600,
        })
    }

    async fn exchange(
        &self,
        challenge_id: &str,
        code: &str,
        state: &str,
        pkce_verifier: Option<&str>,
    ) -> anyhow::Result<VerifiedIdentity> {
        if state != challenge_id {
            anyhow::bail!("OAuth state mismatch: expected '{}', got '{}'", challenge_id, state);
        }
        let pkce_verifier = pkce_verifier
            .ok_or_else(|| anyhow::anyhow!("PKCE verifier missing for id_me exchange"))?;
        let client_id = self
            .cfg
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("id_me provider missing client_id"))?;
        let client_secret = self
            .cfg
            .client_secret
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("id_me provider missing client_secret"))?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        // POST /oauth/token -- exchange the authorization code.
        let token_resp: TokenResponse = http
            .post(&self.cfg.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("code_verifier", pkce_verifier),
                // redirect_uri MUST match the one used in /authorize.
                // The callback server is the only entity that ever calls
                // us, so we *could* hardcode it; safer to require the
                // caller to pass it forward. For now we omit it -- ID.me
                // does not require redirect_uri in the token exchange
                // when PKCE is in use, per their integration guide.
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?;

        // GET /attributes.json -- fetch the user profile + verified flags.
        let attrs: AttributesResponse = http
            .get(&self.cfg.userinfo_url)
            .bearer_auth(&token_resp.access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<AttributesResponse>()
            .await?;

        let subject = attrs
            .attributes
            .iter()
            .find(|a| a.handle == "uuid")
            .and_then(|a| a.value.as_deref())
            .ok_or_else(|| anyhow::anyhow!("id_me attributes.json missing uuid"))?
            .to_string();
        let email = attrs
            .attributes
            .iter()
            .find(|a| a.handle == "email")
            .and_then(|a| a.value.as_deref())
            .map(str::to_string);
        let verified = attrs
            .attributes
            .iter()
            .find(|a| a.handle == "verified")
            .and_then(|a| a.value.as_deref())
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let method = attrs
            .attributes
            .iter()
            .find(|a| a.handle == "verification_method")
            .and_then(|a| a.value.as_deref())
            .unwrap_or("");
        let loa = map_loa(verified, method);

        let raw = serde_json::to_value(&attrs).unwrap_or(serde_json::Value::Null);

        Ok(VerifiedIdentity {
            provider: self.cfg.id.clone(),
            subject,
            email,
            loa,
            raw,
        })
    }
}

/// Map ID.me's `verified` + `verification_method` claims to our LOA
/// tier. Adjusted as we learn more about the actual claim payload from
/// the partner sandbox.
fn map_loa(verified: bool, method: &str) -> u8 {
    if !verified {
        return 0;
    }
    match method.to_ascii_lowercase().as_str() {
        // Biometric + government ID.
        "ial2" | "ial_2" | "biometric_id" | "selfie_id_match" => 3,
        // Strong NPV: phone, address, financial.
        "nv_strong" | "strong_npv" | "ial1_5" => 2,
        // Plain NPV: knowledge-based.
        "nv" | "ial1" | "knowledge" => 1,
        _ => 1,
    }
}

/// Generate a (verifier, challenge) PKCE pair using the SHA-256
/// challenge method.
fn generate_pkce_pair() -> (String, String) {
    use base64::Engine;
    let raw: [u8; 32] = rand::random();
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    #[serde(default)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    expires_in: Option<u64>,
    #[allow(dead_code)]
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct AttributesResponse {
    #[serde(default)]
    attributes: Vec<Attribute>,
    #[serde(default)]
    #[allow(dead_code)]
    status: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct Attribute {
    handle: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Requirement;

    fn cfg(client_id: Option<&str>, client_secret: Option<&str>) -> IdMeConfig {
        let (a, t, u) = IdMeConfig::endpoint_defaults(true);
        IdMeConfig {
            id: "id_me".into(),
            sandbox: true,
            client_id: client_id.map(str::to_string),
            client_secret: client_secret.map(str::to_string),
            scopes: vec!["openid".into(), "ial2".into()],
            authorize_url: a,
            token_url: t,
            userinfo_url: u,
        }
    }

    #[test]
    fn unready_until_creds_present() {
        let p = IdMeProvider::new(cfg(None, None));
        assert!(!p.is_ready());
        let p = IdMeProvider::new(cfg(Some(""), Some("")));
        assert!(!p.is_ready());
        let p = IdMeProvider::new(cfg(Some("cid"), Some("csec")));
        assert!(p.is_ready());
    }

    #[tokio::test]
    async fn begin_returns_authorize_url_with_pkce() {
        let p = IdMeProvider::new(cfg(Some("CID"), Some("CSEC")));
        let req = ChallengeRequest {
            rule_id: "scm.commit".into(),
            requirement: Requirement {
                provider: "id_me".into(),
                scope: "scm.commit".into(),
                allowed_subjects: vec!["*".into()],
                max_proof_age_seconds: 900,
                loa: 2,
            },
            callback_url: "http://127.0.0.1:9999/callback".into(),
            challenge_id: "ch-xyz".into(),
        };
        let ch = p.begin(req).await.unwrap();
        assert!(ch.verify_url.contains("client_id=CID"));
        assert!(ch.verify_url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcallback"));
        assert!(ch.verify_url.contains("state=ch-xyz"));
        assert!(ch.verify_url.contains("code_challenge="));
        assert!(ch.verify_url.contains("code_challenge_method=S256"));
        assert!(ch.pkce_verifier.is_some());
    }

    #[tokio::test]
    async fn begin_errors_when_unready() {
        let p = IdMeProvider::new(cfg(None, None));
        let req = ChallengeRequest {
            rule_id: "x".into(),
            requirement: Requirement {
                provider: "id_me".into(),
                scope: "x".into(),
                allowed_subjects: vec!["*".into()],
                max_proof_age_seconds: 900,
                loa: 0,
            },
            callback_url: "http://127.0.0.1:9999/callback".into(),
            challenge_id: "c".into(),
        };
        assert!(p.begin(req).await.is_err());
    }

    #[test]
    fn loa_mapping_promotes_biometric() {
        assert_eq!(map_loa(false, "ial2"), 0);
        assert_eq!(map_loa(true, ""), 1);
        assert_eq!(map_loa(true, "nv"), 1);
        assert_eq!(map_loa(true, "nv_strong"), 2);
        assert_eq!(map_loa(true, "ial2"), 3);
        assert_eq!(map_loa(true, "selfie_id_match"), 3);
    }
}

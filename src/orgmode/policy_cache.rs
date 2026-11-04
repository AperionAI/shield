//! Last signed org shieldset, on disk, for the hook processes.
//!
//! The guard, the MCP proxy, and enrollment write it. Each hook re-checks
//! the signature against the key pinned at enrollment, so editing the file
//! gets the device the same treatment as having no policy: every tool
//! call asks.

use std::path::PathBuf;

use crate::Engine;

use super::client::SignedShieldset;
use super::state::{shield_dir, OrgState};

const FILE: &str = "org-shieldset.json";
pub const STALE_RULE: &str = "shield.policy_stale";

pub struct HookPolicy {
    pub engine: Engine,
    /// Set when every tool call should ask, with the reason to show.
    pub ask_reason: Option<String>,
}

fn path() -> anyhow::Result<PathBuf> {
    Ok(shield_dir()?.join(FILE))
}

pub fn save(s: &SignedShieldset) -> anyhow::Result<()> {
    super::write_private(&path()?, &serde_json::to_vec(s)?)
}

pub fn load_raw() -> Option<SignedShieldset> {
    serde_json::from_slice(&std::fs::read(path().ok()?).ok()?).ok()
}

/// What a hook should run for this enrollment, at `now` (unix seconds).
pub fn for_hook(state: &OrgState, cached: Option<SignedShieldset>, now: i64) -> HookPolicy {
    let fallback = |why: &str| HookPolicy {
        engine: Engine::builtin_default(),
        ask_reason: Some(format!(
            "{why} Shield is asking on every tool call until the guard pulls a fresh policy from Smartflow."
        )),
    };
    let Some(s) = cached else {
        return fallback("This device has no org policy yet.");
    };
    if s.group != state.policy_group {
        return fallback("The cached org policy is for a different group.");
    }
    if let Some(pk) = &state.bundle_pubkey {
        if !super::device_identity::verify_shieldset(pk, s.issued_at, &s.group, s.yaml.as_bytes(), &s.signature) {
            return fallback("The cached org policy failed its signature check.");
        }
    }
    let engine = match Engine::from_yaml(&s.yaml) {
        Ok(e) => e,
        Err(_) => return fallback("The cached org policy doesn't parse."),
    };
    let org = &engine.policy.org;
    let age = now.saturating_sub(s.issued_at);
    let max = (org.max_policy_age_hours as i64).saturating_mul(3600);
    let ask_reason = (org.regulated && age > max).then(|| {
        format!(
            "Org policy is {}h old (limit {}h). Shield is asking on every tool call until it can reach Smartflow.",
            age / 3600,
            org.max_policy_age_hours
        )
    });
    HookPolicy { engine, ask_reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(pk: Option<String>) -> OrgState {
        OrgState {
            smartflow_url: "https://sf".into(),
            vkey: String::new(),
            device_id: "d".into(),
            policy_group: "eng".into(),
            owner_email: None,
            enrolled_at: String::new(),
            platform: "macos".into(),
            device_name: "n".into(),
            device_fingerprint: "f".into(),
            bundle_pubkey: pk,
        }
    }

    fn signed(sk: &ed25519_dalek::SigningKey, yaml: &str, issued_at: i64, group: &str) -> SignedShieldset {
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        let mut msg = b"aperion-shieldset-v2\n".to_vec();
        msg.extend_from_slice(format!("{issued_at}\n{group}\n").as_bytes());
        msg.extend_from_slice(yaml.as_bytes());
        SignedShieldset {
            yaml: yaml.into(),
            version: 1,
            issued_at,
            group: group.into(),
            signature: format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(sk.sign(&msg).to_bytes())
            ),
        }
    }

    const REGULATED: &str =
        "shieldset:\n  policy:\n    org:\n      regulated: true\n      max_policy_age_hours: 24\n  rules: []\n";
    const OPEN: &str = "shieldset:\n  rules: []\n";

    #[test]
    fn missing_tampered_or_foreign_policy_asks() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let st = state(Some(hex::encode(sk.verifying_key().as_bytes())));
        let now = 1_700_000_000;
        assert!(for_hook(&st, None, now).ask_reason.is_some());
        let mut s = signed(&sk, OPEN, now, "eng");
        assert!(for_hook(&st, Some(s.clone()), now).ask_reason.is_none());
        s.yaml.push_str("# edited\n");
        assert!(for_hook(&st, Some(s), now).ask_reason.is_some());
        let other = signed(&sk, OPEN, now, "finance");
        assert!(for_hook(&st, Some(other), now).ask_reason.is_some());
        let mut back_dated = signed(&sk, OPEN, now - 10, "eng");
        back_dated.issued_at = now;
        assert!(for_hook(&st, Some(back_dated), now).ask_reason.is_some());
    }

    #[test]
    fn only_regulated_policies_go_stale() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let st = state(Some(hex::encode(sk.verifying_key().as_bytes())));
        let issued = 1_700_000_000;
        let later = issued + 25 * 3600;
        assert!(for_hook(&st, Some(signed(&sk, REGULATED, issued, "eng")), issued + 3600).ask_reason.is_none());
        let stale = for_hook(&st, Some(signed(&sk, REGULATED, issued, "eng")), later);
        assert!(stale.ask_reason.unwrap().contains("25h old"));
        assert!(for_hook(&st, Some(signed(&sk, OPEN, issued, "eng")), later).ask_reason.is_none());
    }
}

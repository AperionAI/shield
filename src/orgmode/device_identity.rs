//! Device identity created at enrollment.
//!
//! - TLS client key and cert: `device.key` (0600) and `device.crt` in the
//!   shield dir. Claude Code reads them through `CLAUDE_CODE_CLIENT_CERT` /
//!   `CLAUDE_CODE_CLIENT_KEY`, which only take file paths.
//! - Ed25519 key that signs event batches, and the vkey: OS keystore.

use std::path::PathBuf;

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::keystore;
use super::state::shield_dir;

pub const CERT_FILE: &str = "device.crt";
pub const KEY_FILE: &str = "device.key";
pub const CA_FILE: &str = "smartflow-device-ca.pem";
const SIGNING_KEY: &str = "signing-key";
const VKEY: &str = "vkey";

/// Must match the server's `EVENTS_SIG_DOMAIN` / `SHIELDSET_SIG_DOMAIN`.
const EVENTS_SIG_DOMAIN: &[u8] = b"aperion-shield-events-v1\n";
const SHIELDSET_SIG_DOMAIN: &[u8] = b"aperion-shieldset-v2\n";
const KILLSWITCH_SIG_DOMAIN: &[u8] = b"aperion-shield-killswitch-v1\n";

pub struct Pending {
    pub tls_key_pem: String,
    pub csr_pem: String,
    pub signing: SigningKey,
}

impl Pending {
    pub fn signing_pubkey_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }
}

pub fn generate(device_name: &str) -> anyhow::Result<Pending> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate TLS key")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).context("CSR params")?;
    params.distinguished_name.push(rcgen::DnType::CommonName, device_name);
    let csr_pem = params.serialize_request(&kp).context("build CSR")?.pem().context("encode CSR")?;
    Ok(Pending {
        tls_key_pem: kp.serialize_pem(),
        csr_pem,
        signing: SigningKey::generate(&mut rand::rngs::OsRng),
    })
}

pub fn path(file: &str) -> anyhow::Result<PathBuf> {
    Ok(shield_dir()?.join(file))
}

/// Persist the identity after a successful enrollment.
pub fn save(p: &Pending, cert_pem: Option<&str>, ca_pem: Option<&str>, vkey: &str) -> anyhow::Result<()> {
    if let Some(cert) = cert_pem {
        super::write_private(&path(KEY_FILE)?, p.tls_key_pem.as_bytes())?;
        std::fs::write(path(CERT_FILE)?, cert).context("write device.crt")?;
    }
    if let Some(ca) = ca_pem {
        std::fs::write(path(CA_FILE)?, ca).context("write device CA")?;
    }
    keystore::put(SIGNING_KEY, &hex::encode(p.signing.to_bytes()))?;
    keystore::put(VKEY, vkey)?;
    Ok(())
}

pub fn clear() -> anyhow::Result<()> {
    for f in [CERT_FILE, KEY_FILE, CA_FILE] {
        let p = path(f)?;
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    keystore::delete(SIGNING_KEY)?;
    keystore::delete(VKEY)
}

/// Cert followed by key, the form `reqwest::Identity::from_pem` takes.
pub fn identity_pem() -> Option<Vec<u8>> {
    let cert = std::fs::read(path(CERT_FILE).ok()?).ok()?;
    let key = std::fs::read(path(KEY_FILE).ok()?).ok()?;
    let mut out = cert;
    out.push(b'\n');
    out.extend_from_slice(&key);
    Some(out)
}

pub fn vkey() -> Option<String> {
    keystore::get(VKEY).ok().flatten().filter(|s| !s.is_empty())
}

pub fn signing_key() -> Option<SigningKey> {
    let hex_key = keystore::get(SIGNING_KEY).ok().flatten()?;
    let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;
    Some(SigningKey::from_bytes(&bytes))
}

/// Hex Ed25519 signature over the batch body, or `None` for devices
/// enrolled before batch signing existed.
pub fn sign_batch(body: &[u8]) -> Option<String> {
    let key = signing_key()?;
    Some(sign_with(&key, body))
}

fn sign_with(key: &SigningKey, body: &[u8]) -> String {
    let mut msg = EVENTS_SIG_DOMAIN.to_vec();
    msg.extend_from_slice(body);
    hex::encode(key.sign(&msg).to_bytes())
}

fn shieldset_message(issued_at: i64, group: &str, body: &[u8]) -> Vec<u8> {
    let mut msg = SHIELDSET_SIG_DOMAIN.to_vec();
    msg.extend_from_slice(format!("{issued_at}\n{group}\n").as_bytes());
    msg.extend_from_slice(body);
    msg
}

/// Check `X-Shield-Policy-Signature` (`ed25519:<base64>`) against the
/// server key pinned at enrollment. The signature covers the issue time
/// and the group as well as the YAML.
pub fn verify_shieldset(pubkey_hex: &str, issued_at: i64, group: &str, body: &[u8], header: &str) -> bool {
    verify_ed25519(pubkey_hex, &shieldset_message(issued_at, group, body), header)
}

/// Check `X-Shield-Killswitch-Signature` for the state served with a shieldset.
pub fn verify_killswitch(pubkey_hex: &str, issued_at: i64, group: &str, on: bool, header: &str) -> bool {
    let mut msg = KILLSWITCH_SIG_DOMAIN.to_vec();
    msg.extend_from_slice(format!("{issued_at}\n{group}\n{}", if on { "on" } else { "off" }).as_bytes());
    verify_ed25519(pubkey_hex, &msg, header)
}

fn verify_ed25519(pubkey_hex: &str, msg: &[u8], header: &str) -> bool {
    use base64::Engine;
    let Some(b64) = header.trim().strip_prefix("ed25519:") else { return false };
    let Ok(sig) = base64::engine::general_purpose::STANDARD.decode(b64) else { return false };
    let Ok(sig) = Signature::from_slice(&sig) else { return false };
    let Ok(pk) = hex::decode(pubkey_hex) else { return false };
    let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn csr_is_pem_and_keys_differ() {
        let p = generate("test-laptop").unwrap();
        assert!(p.csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(p.tls_key_pem.contains("PRIVATE KEY"));
        assert_eq!(p.signing_pubkey_hex().len(), 64);
    }

    #[test]
    fn shieldset_signature_roundtrip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = hex::encode(sk.verifying_key().as_bytes());
        let body = b"shieldset:\n  rules: []\n";
        let msg = shieldset_message(1_700_000_000, "eng", body);
        let header = format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode(sk.sign(&msg).to_bytes())
        );
        assert!(verify_shieldset(&pk, 1_700_000_000, "eng", body, &header));
        assert!(!verify_shieldset(&pk, 1_700_000_000, "eng", b"shieldset:\n  rules: [x]\n", &header));
        assert!(!verify_shieldset(&pk, 1_800_000_000, "eng", body, &header));
        assert!(!verify_shieldset(&pk, 1_700_000_000, "other", body, &header));
        assert!(!verify_shieldset(&pk, 1_700_000_000, "eng", body, "ed25519:AAAA"));
        assert!(!verify_shieldset(&pk, 1_700_000_000, "eng", body, ""));
    }

    #[test]
    fn batch_signature_uses_domain() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let sig = hex::decode(sign_with(&sk, b"{}")).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        let mut msg = EVENTS_SIG_DOMAIN.to_vec();
        msg.extend_from_slice(b"{}");
        assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
        assert!(sk.verifying_key().verify(b"{}", &sig).is_err());
    }
}

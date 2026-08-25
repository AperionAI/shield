//! Cryptographic proofs of identity verification.
//!
//! Every successful [`super::IdentityProvider::exchange`] is turned into
//! a [`Proof`] -- a small signed record asserting "user U verified at
//! time T with LOA L, valid for scope S until time E".
//!
//! Why sign them?
//!
//! The proof file is JSON on disk. Without a signature, anything with
//! filesystem access (a malicious script, another agent, a compromised
//! IDE plugin) could append a row claiming "[email protected] verified
//! seconds ago, LOA 3" and bypass every identity gate. Ed25519 means
//! Shield is the only process holding the private key, so unsigned or
//! mis-signed rows are rejected the moment the cache loads.
//!
//! Key on disk
//! -----------
//!
//! `~/.aperion-shield/identity-key` is a JSON blob:
//!
//! ```json
//! { "v": 1, "alg": "ed25519",
//!   "private": "<32 bytes hex>", "public": "<32 bytes hex>" }
//! ```
//!
//! Created with mode 0600 on first use. If the file is missing or
//! malformed, a new keypair is generated and any previously-cached
//! proofs become unverifiable (a feature, not a bug -- replacing the
//! key forces a clean re-verify pass).

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A signed verification proof. Persisted in the proof cache.
///
/// Field order is part of the canonicalisation contract -- the signature
/// covers `bincode-of(canonical view)` which is just a deterministic
/// JSON serialization minus the `sig` field itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Schema version. Bump if we change canonicalisation.
    pub v: u32,
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub loa: u8,
    pub scope: String,
    pub verified_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    /// `ed25519:<base64>`. Empty during construction, filled by [`ProofSigner::sign`].
    pub sig: String,
}

impl Proof {
    /// Compose the bytes the signature covers. Stable across processes
    /// and OS so a proof signed on macOS is verifiable on Linux with
    /// the same key.
    fn canonical_bytes(&self) -> Vec<u8> {
        // Deterministic JSON without the `sig` field.
        let mut canon = serde_json::Map::new();
        canon.insert("v".into(), self.v.into());
        canon.insert("provider".into(), self.provider.clone().into());
        canon.insert("subject".into(), self.subject.clone().into());
        canon.insert(
            "email".into(),
            self.email
                .clone()
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null),
        );
        canon.insert("loa".into(), self.loa.into());
        canon.insert("scope".into(), self.scope.clone().into());
        canon.insert("verified_at".into(), self.verified_at.into());
        canon.insert("expires_at".into(), self.expires_at.into());
        canon.insert("nonce".into(), self.nonce.clone().into());
        serde_json::to_vec(&serde_json::Value::Object(canon))
            .expect("canonical JSON serialisation must succeed")
    }
}

/// Ed25519 signer + verifier for [`Proof`]s. Owns a keypair stored on
/// disk at `<state_dir>/identity-key` and provides the only path Shield
/// uses to mint or validate proofs.
pub struct ProofSigner {
    signing: SigningKey,
    verifying: VerifyingKey,
    #[allow(dead_code)]
    key_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredKey {
    v: u32,
    alg: String,
    private: String,
    public: String,
}

impl ProofSigner {
    /// Load the existing key from `<state_dir>/identity-key`, or
    /// generate one and persist it if absent.
    pub fn load_or_create(state_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700));
        }

        let key_path = state_dir.join("identity-key");
        if key_path.exists() {
            if let Ok(raw) = fs::read_to_string(&key_path) {
                if let Ok(stored) = serde_json::from_str::<StoredKey>(&raw) {
                    if stored.alg == "ed25519" {
                        if let (Ok(priv_bytes), Ok(pub_bytes)) =
                            (hex::decode(&stored.private), hex::decode(&stored.public))
                        {
                            if priv_bytes.len() == 32 && pub_bytes.len() == 32 {
                                let signing =
                                    SigningKey::from_bytes(&priv_bytes.try_into().unwrap());
                                let verifying = signing.verifying_key();
                                return Ok(Self {
                                    signing,
                                    verifying,
                                    key_path,
                                });
                            }
                        }
                    }
                }
            }
            // Fall through: regenerate on any parse failure.
        }

        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let stored = StoredKey {
            v: 1,
            alg: "ed25519".into(),
            private: hex::encode(signing.to_bytes()),
            public: hex::encode(verifying.to_bytes()),
        };
        let body = serde_json::to_string_pretty(&stored)? + "\n";
        fs::write(&key_path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            signing,
            verifying,
            key_path,
        })
    }

    /// Sign a proof in-place, returning the now-fully-populated value.
    pub fn sign(&self, mut proof: Proof) -> anyhow::Result<Proof> {
        let bytes = proof.canonical_bytes();
        let sig: Signature = self.signing.sign(&bytes);
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            sig.to_bytes(),
        );
        proof.sig = format!("ed25519:{}", b64);
        Ok(proof)
    }

    /// Verify a previously-minted proof. Returns Ok(()) if the
    /// signature matches; an error otherwise.
    pub fn verify(&self, proof: &Proof) -> anyhow::Result<()> {
        let (alg, b64) = proof
            .sig
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("proof.sig missing algorithm prefix"))?;
        if alg != "ed25519" {
            anyhow::bail!("unsupported proof signature alg '{}'", alg);
        }
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, b64)
                .map_err(|e| anyhow::anyhow!("base64 decode of proof.sig: {}", e))?;
        if sig_bytes.len() != 64 {
            anyhow::bail!("proof.sig wrong length ({} bytes)", sig_bytes.len());
        }
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("bad ed25519 signature: {}", e))?;
        self.verifying
            .verify(&proof.canonical_bytes(), &sig)
            .map_err(|e| anyhow::anyhow!("ed25519 verify failed: {}", e))?;
        Ok(())
    }

    /// Hex-encoded public key -- useful for surfacing in audit logs so
    /// a fleet admin can confirm two laptops are running independent
    /// shields.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(subject: &str) -> Proof {
        Proof {
            v: 1,
            provider: "mock".into(),
            subject: subject.into(),
            email: Some("[email protected]".into()),
            loa: 2,
            scope: "scm.commit".into(),
            verified_at: 1_700_000_000,
            expires_at: 1_700_000_900,
            nonce: "abc".into(),
            sig: String::new(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = ProofSigner::load_or_create(tmp.path()).unwrap();
        let signed = s.sign(proof("sub-a")).unwrap();
        assert!(signed.sig.starts_with("ed25519:"));
        s.verify(&signed).expect("signature must verify");
    }

    #[test]
    fn tampered_proof_fails_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let s = ProofSigner::load_or_create(tmp.path()).unwrap();
        let mut signed = s.sign(proof("sub-a")).unwrap();
        signed.loa = 3; // forge: bump LOA after signing
        assert!(s.verify(&signed).is_err());
    }

    #[test]
    fn different_keys_cannot_verify_each_other() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let a = ProofSigner::load_or_create(tmp1.path()).unwrap();
        let b = ProofSigner::load_or_create(tmp2.path()).unwrap();
        let signed = a.sign(proof("sub-a")).unwrap();
        assert!(a.verify(&signed).is_ok());
        assert!(b.verify(&signed).is_err());
    }

    #[test]
    fn key_persists_across_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let a = ProofSigner::load_or_create(tmp.path()).unwrap();
        let signed = a.sign(proof("sub-a")).unwrap();
        drop(a);
        let b = ProofSigner::load_or_create(tmp.path()).unwrap();
        b.verify(&signed)
            .expect("regenerated signer must verify proofs from prior session");
    }
}

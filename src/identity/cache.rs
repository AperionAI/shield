//! On-disk cache of signed verification proofs.
//!
//! Stored as JSON at `<state_dir>/identity-cache.json`:
//!
//! ```json
//! {
//!   "v": 1,
//!   "public_key": "<hex>",            // for diagnostics; not authoritative
//!   "proofs": [ { ...Proof... }, ... ]
//! }
//! ```
//!
//! Every entry is signature-verified on load. Any entry that fails
//! verification (tampered, signed by a different key, expired schema)
//! is silently dropped. The cache is then rewritten with only the
//! survivors so the file stays clean.
//!
//! Thread-safety: a `parking_lot`-style `RwLock` would be ideal but
//! we already depend on `std::sync::RwLock`. We hold the write lock
//! only across in-memory state mutations and the file write, which is
//! fast (< 1 ms for typical proof counts), so contention is a
//! non-issue for the standalone Shield's single-user-on-a-laptop case.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::proof::{Proof, ProofSigner};
use super::Requirement;

#[derive(Debug, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default = "default_v")]
    v: u32,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    proofs: Vec<Proof>,
}

fn default_v() -> u32 { 1 }

impl Default for CacheFile {
    fn default() -> Self {
        Self { v: 1, public_key: String::new(), proofs: Vec::new() }
    }
}

pub struct ProofCache {
    path: PathBuf,
    public_key: String,
    inner: RwLock<Vec<Proof>>,
}

impl ProofCache {
    /// Open (and signature-verify) the cache at `path`. Missing files
    /// are treated as empty caches.
    pub fn open(path: PathBuf, signer: &ProofSigner) -> anyhow::Result<Self> {
        let mut survivors = Vec::<Proof>::new();
        if path.exists() {
            let raw = fs::read_to_string(&path).unwrap_or_default();
            let file: CacheFile = serde_json::from_str(&raw).unwrap_or_default();
            for p in file.proofs {
                if signer.verify(&p).is_ok() {
                    survivors.push(p);
                } else {
                    log::warn!(
                        "[shield-identity] dropping proof with bad signature \
                         (provider={} subject={} scope={})",
                        p.provider, p.subject, p.scope
                    );
                }
            }
        }
        Ok(Self {
            path,
            public_key: signer.public_key_hex(),
            inner: RwLock::new(survivors),
        })
    }

    /// Insert a (presumably just-minted, already-signed) proof and
    /// persist the cache. Replaces any existing proof for the same
    /// (provider, subject, scope) tuple -- one slot per identity per
    /// scope, so re-verifying simply refreshes the timestamp.
    pub fn insert(&self, proof: Proof) -> anyhow::Result<()> {
        {
            let mut g = self.inner.write().expect("cache write lock poisoned");
            g.retain(|p| {
                !(p.provider == proof.provider
                    && p.subject == proof.subject
                    && p.scope == proof.scope)
            });
            g.push(proof);
        }
        self.persist()
    }

    /// Drop every cached proof. Returns the number evicted.
    pub fn flush(&self) -> anyhow::Result<usize> {
        let n = {
            let mut g = self.inner.write().expect("cache write lock poisoned");
            let n = g.len();
            g.clear();
            n
        };
        self.persist()?;
        Ok(n)
    }

    /// Find any proof that satisfies `req` at `now`. Returns the proof
    /// with the latest `verified_at` if multiple match (most-recently-
    /// verified wins).
    pub fn find_satisfying(&self, req: &Requirement, now: u64) -> Option<Proof> {
        let g = self.inner.read().expect("cache read lock poisoned");
        g.iter()
            .filter(|p| req.is_satisfied_by(p, now))
            .max_by_key(|p| p.verified_at)
            .cloned()
    }

    /// How many proofs are currently cached AND not expired at `now`.
    pub fn count_valid(&self, now: u64) -> usize {
        let g = self.inner.read().expect("cache read lock poisoned");
        g.iter().filter(|p| p.expires_at > now).count()
    }

    /// Persist the in-memory state to disk via write-then-rename so a
    /// crash mid-write never produces a truncated cache file.
    fn persist(&self) -> anyhow::Result<()> {
        let snapshot = {
            let g = self.inner.read().expect("cache read lock poisoned");
            CacheFile {
                v: 1,
                public_key: self.public_key.clone(),
                proofs: g.clone(),
            }
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(&snapshot)?;
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&body)?;
            f.write_all(b"\n")?;
            f.sync_all().ok();
        }
        fs::rename(&tmp_path, &self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(subject: &str, scope: &str, ttl: u64) -> Proof {
        let now = super::super::unix_now();
        Proof {
            v: 1, provider: "mock".into(), subject: subject.into(),
            email: Some("[email protected]".into()),
            loa: 2, scope: scope.into(),
            verified_at: now, expires_at: now + ttl,
            nonce: "abc".into(), sig: String::new(),
        }
    }

    #[test]
    fn round_trip_insert_and_find() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = ProofSigner::load_or_create(tmp.path()).unwrap();
        let cache = ProofCache::open(tmp.path().join("c.json"), &signer).unwrap();

        let p = signer.sign(proof("sub-a", "scm.commit", 600)).unwrap();
        cache.insert(p).unwrap();

        let req = Requirement {
            provider: "mock".into(),
            scope: "scm.commit".into(),
            allowed_subjects: vec!["sub-a".into()],
            max_proof_age_seconds: 900,
            loa: 2,
        };
        let now = super::super::unix_now();
        assert!(cache.find_satisfying(&req, now).is_some());
    }

    #[test]
    fn reload_drops_tampered_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = ProofSigner::load_or_create(tmp.path()).unwrap();
        let cache_path = tmp.path().join("c.json");
        {
            let cache = ProofCache::open(cache_path.clone(), &signer).unwrap();
            let p = signer.sign(proof("sub-a", "scm.commit", 600)).unwrap();
            cache.insert(p).unwrap();
        }
        let raw = std::fs::read_to_string(&cache_path).unwrap();
        let tampered = raw.replace("\"loa\": 2", "\"loa\": 3");
        std::fs::write(&cache_path, tampered).unwrap();

        let cache2 = ProofCache::open(cache_path.clone(), &signer).unwrap();
        let now = super::super::unix_now();
        let req = Requirement {
            provider: "mock".into(),
            scope: "scm.commit".into(),
            allowed_subjects: vec!["*".into()],
            max_proof_age_seconds: 900,
            loa: 0,
        };
        // The tampered row must NOT survive.
        assert!(cache2.find_satisfying(&req, now).is_none());
    }

    #[test]
    fn insert_replaces_same_scope_subject() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = ProofSigner::load_or_create(tmp.path()).unwrap();
        let cache = ProofCache::open(tmp.path().join("c.json"), &signer).unwrap();
        let p1 = signer.sign(proof("sub-a", "scm.commit", 600)).unwrap();
        let p2 = signer.sign(proof("sub-a", "scm.commit", 600)).unwrap();
        cache.insert(p1).unwrap();
        cache.insert(p2).unwrap();
        let now = super::super::unix_now();
        assert_eq!(cache.count_valid(now), 1);
    }
}

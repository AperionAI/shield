//! Secret-shape entity corpus (v1.3).
//!
//! One canonical Rust regex set for credential-shaped values, used by
//! both the taint *tagger* (scan a tool result / diff for secrets to
//! remember) and the taint *checker* (scan an outgoing tool call's
//! arguments for a value we've already seen leave somewhere else).
//!
//! This consolidates shapes that were previously scattered across three
//! places in the repo:
//!
//!   * `config/shieldset-atr.yaml` -- rule `atr.context_exfiltration.00021`
//!     carried the richest existing set (AWS / Stripe / Google keys, JWTs,
//!     PEM private-key blocks, DB connection strings).
//!   * `scripts/extract-cursor-corpus.py` -- AKIA / `sk-` / `ghp_` / JWT
//!     redaction patterns used when building test corpora.
//!   * ad-hoc `text_matches` in a few other rules.
//!
//! ## Design notes
//!
//! * We only match *high-signal, low-false-positive* shapes. This is a
//!   deliberate scope decision for v1.3 (see the plan / README): the
//!   value of cross-tool taint tracking comes from catching a real
//!   credential relayed between tools, not from flagging every
//!   base64-ish blob.
//! * Extraction must be **stable**: the exact substring the regex
//!   matches on the tagging side must be byte-identical to what it
//!   matches on the checking side, because the ledger only stores a hash
//!   of that substring. Any pattern that could match a *different* span
//!   of the same secret in two contexts would silently fail to correlate.
//!   That's why the private-key entity matches the whole PEM block (BEGIN
//!   .. END), not just the `-----BEGIN ... -----` marker -- the marker is
//!   identical across *all* keys of a type and would both (a) collide
//!   distinct keys and (b) never uniquely identify one.

use once_cell::sync::Lazy;
use regex::Regex;

/// A credential-shaped value located inside some text, together with the
/// entity kind that matched it. `value` is the exact matched substring;
/// the ledger stores only `hash_secret(value)`, never the raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    pub kind: &'static str,
    pub value: String,
}

struct EntityPattern {
    kind: &'static str,
    re: Regex,
}

/// The canonical corpus. Order matters only for which `kind` label a
/// given span is reported under when two patterns could overlap; the
/// more specific vendor patterns are listed before the generic ones.
static ENTITIES: Lazy<Vec<EntityPattern>> = Lazy::new(|| {
    let specs: &[(&str, &str)] = &[
        // ── Vendor API keys / tokens (specific first) ──────────────
        // Anthropic -- must precede the generic `sk-` OpenAI shape so an
        // `sk-ant-...` key is labelled anthropic_key rather than openai_key.
        ("anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        // OpenAI (classic `sk-...` and project `sk-proj-...`).
        ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
        // AWS access key id.
        ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        // GitHub tokens: PAT (classic + fine-grained), OAuth, user, server, refresh.
        ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("github_token", r"github_pat_[A-Za-z0-9_]{60,}"),
        // Slack tokens.
        ("slack_token", r"xox[bpasr]-[A-Za-z0-9\-]{10,}"),
        // Google API key.
        ("google_api_key", r"AIza[A-Za-z0-9_\-]{35}"),
        // Stripe keys (live + test, secret + publishable + restricted).
        ("stripe_key", r"(?:sk_live|pk_live|sk_test|pk_test|rk_live)_[A-Za-z0-9]{20,}"),
        // ── Structural credentials ─────────────────────────────────
        // JWT (three base64url segments; the first two start with the
        // canonical `eyJ` header/payload prefix).
        ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),
        // PEM private-key block -- match the WHOLE block (BEGIN..END) so
        // the hash is unique per key, not per key *type*. `[\s\S]` matches
        // across newlines in the `regex` crate without the multiline flag.
        (
            "private_key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{1,8192}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        ),
        // Database / broker connection string carrying inline credentials.
        (
            "db_connection_string",
            r#"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s"']{10,}"#,
        ),
    ];

    specs
        .iter()
        .map(|(kind, pat)| EntityPattern {
            kind,
            re: Regex::new(pat).unwrap_or_else(|e| panic!("secret-shape regex '{pat}' failed to compile: {e}")),
        })
        .collect()
});

/// Scan `text` for every credential-shaped value and return each match
/// with its entity kind. Overlapping matches from different entities are
/// all reported; de-duplicated by (kind, value).
pub fn scan_secrets(text: &str) -> Vec<SecretMatch> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<SecretMatch> = Vec::new();
    for ent in ENTITIES.iter() {
        for m in ent.re.find_iter(text) {
            let candidate = SecretMatch {
                kind: ent.kind,
                value: m.as_str().to_string(),
            };
            if !out.iter().any(|s| s.kind == candidate.kind && s.value == candidate.value) {
                out.push(candidate);
            }
        }
    }
    out
}

/// Hash a raw secret value into the stable, non-reversible identifier the
/// ledger stores. SHA-256 hex, mirroring the `engine::fingerprint()`
/// philosophy of never persisting the raw sensitive material. We keep the
/// full 256-bit digest (64 hex chars) here -- the ledger is
/// cross-*process* (two Shield instances correlating), so we want the
/// widest possible collision margin.
pub fn hash_secret(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(64);
    for b in out.iter() {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<&'static str> {
        scan_secrets(text).into_iter().map(|s| s.kind).collect()
    }

    #[test]
    fn aws_access_key_detected() {
        let m = scan_secrets("key=AKIAIOSFODNN7EXAMPLE end");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, "aws_access_key");
        assert_eq!(m[0].value, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn openai_key_detected() {
        // Token literals split via concat! so the contiguous secret shape
        // never appears in the source (defeats naive secret scanners); the
        // assembled &str is byte-identical, so the taint regex still matches.
        assert!(kinds(concat!("sk-", "abcdefghijklmnopqrstuvwx")).contains(&"openai_key"));
    }

    #[test]
    fn anthropic_key_labelled_anthropic_not_openai() {
        let ks = kinds(concat!("token sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz"));
        assert!(ks.contains(&"anthropic_key"), "kinds={ks:?}");
        assert!(!ks.contains(&"openai_key"), "sk-ant must not double-report as openai: {ks:?}");
    }

    #[test]
    fn github_pat_detected() {
        assert!(kinds(concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz")).contains(&"github_token"));
        assert!(kinds(concat!("github_pat_11ABC", "DEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDE")).contains(&"github_token"));
    }

    #[test]
    fn slack_token_detected() {
        assert!(kinds(concat!("xoxb-", "1234567890-abcdefghij")).contains(&"slack_token"));
    }

    #[test]
    fn google_api_key_detected() {
        assert!(kinds(concat!("AIzaSy", "A1234567890abcdefghijklmnopqrstuv")).contains(&"google_api_key"));
    }

    #[test]
    fn stripe_key_detected() {
        assert!(kinds(concat!("sk_live_", "0123456789abcdefghijklmn")).contains(&"stripe_key"));
    }

    #[test]
    fn jwt_detected() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N";
        assert!(kinds(jwt).contains(&"jwt"));
    }

    #[test]
    fn private_key_block_matches_whole_block_not_just_marker() {
        let a = concat!("-----BEGIN RSA ", "PRIVATE KEY-----\nAAAAkeymaterialAAAA\n-----END RSA PRIVATE KEY-----");
        let b = concat!("-----BEGIN RSA ", "PRIVATE KEY-----\nBBBBdifferentkeyBBBB\n-----END RSA PRIVATE KEY-----");
        let ma = scan_secrets(a);
        let mb = scan_secrets(b);
        assert_eq!(ma.len(), 1);
        assert_eq!(ma[0].kind, "private_key");
        // Two DIFFERENT keys must hash differently -- otherwise every pair
        // of private keys would spuriously "correlate".
        assert_ne!(hash_secret(&ma[0].value), hash_secret(&mb[0].value));
    }

    #[test]
    fn db_connection_string_detected() {
        assert!(kinds("postgres://user:pass@host:5432/db").contains(&"db_connection_string"));
        assert!(kinds("mongodb+srv://u:p@cluster0.mongodb.net/app").contains(&"db_connection_string"));
    }

    #[test]
    fn clean_text_yields_nothing() {
        assert!(scan_secrets("the quick brown fox ran 12345 times").is_empty());
        assert!(scan_secrets("").is_empty());
        // A short `sk-` fragment below the length floor must not match.
        assert!(scan_secrets("sk-short").is_empty());
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_secret("AKIAIOSFODNN7EXAMPLE"), hash_secret("AKIAIOSFODNN7EXAMPLE"));
        assert_ne!(hash_secret("AKIAIOSFODNN7EXAMPLE"), hash_secret("AKIAIOSFODNN7EXAMPLF"));
        assert_eq!(hash_secret("x").len(), 64);
    }

    #[test]
    fn same_secret_extracts_identically_across_contexts() {
        // The core correlation invariant: the same secret embedded in two
        // different surrounding strings must extract to the same substring
        // (and therefore the same hash).
        let key = "AKIAIOSFODNN7EXAMPLE";
        let from_result = scan_secrets(&format!("Here is your key: {key}\nkeep it safe"));
        let from_args = scan_secrets(&format!("{{\"authorization\":\"{key}\"}}"));
        assert_eq!(from_result[0].value, from_args[0].value);
        assert_eq!(hash_secret(&from_result[0].value), hash_secret(&from_args[0].value));
    }
}

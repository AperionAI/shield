//! End-to-end coverage for identity-gated rules.
//!
//! These tests don't spin up the callback HTTP server -- they exercise
//! the engine's new decision variant and the cache contract directly,
//! which is what the MCP middleman ultimately relies on.

use std::sync::Arc;

use aperion_shield::identity::{providers::mock::MockProvider, ChallengeRequest};
use aperion_shield::IdentityProvider;
use aperion_shield::{
    decide, Adjustments, Decision, Engine, IdentityConfig, IdentityGate, IdentityRequirement,
};

const YAML_WITH_IDENTITY: &str = r#"
shieldset:
  version: 2
  rules:
    - id: scm.commit_to_main
      severity: High
      points: 4
      where: tool_call
      match:
        tool: ["run_terminal"]
        any_param_matches:
          - '(?i)\bgit\s+(commit|push)\b'
      identity:
        provider: mock
        scope: scm.commit_to_main
        allowed_subjects: ["*"]
        max_proof_age_seconds: 900
        loa: 2
      reason: "Commits to main require biometric ID.me verification."
"#;

fn build_engine() -> Engine {
    Engine::from_yaml(YAML_WITH_IDENTITY).expect("YAML must parse")
}

fn fresh_gate() -> (IdentityGate, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig::default();
    let mock = Arc::new(MockProvider::new(
        "mock",
        "mock-subject-0001",
        Some(format!("{}@{}", "demo", "aperion.ai")),
        2,
    ));
    let gate = IdentityGate::new(cfg, vec![mock], tmp.path().to_path_buf()).unwrap();
    (gate, tmp)
}

#[test]
fn rule_emits_identity_verification_decision() {
    let engine = build_engine();
    let params = serde_json::json!({
        "name": "run_terminal",
        "arguments": { "command": "git commit -am 'release fix'" }
    });
    let eval = engine.evaluate("run_terminal", &params, Adjustments::default());
    assert!(!eval.matches.is_empty(), "rule should match");
    match decide(&eval) {
        Decision::IdentityVerification { rule_id, requirement, .. } => {
            assert_eq!(rule_id, "scm.commit_to_main");
            assert_eq!(requirement.provider, "mock");
            assert_eq!(requirement.scope, "scm.commit_to_main");
            assert_eq!(requirement.loa, 2);
        }
        other => panic!("expected IdentityVerification, got {}", other.label()),
    }
}

#[test]
fn rule_without_identity_still_falls_back_to_approval() {
    let yaml = r#"
shieldset:
  version: 2
  rules:
    - id: scm.commit_to_main
      severity: High
      points: 4
      where: tool_call
      match:
        tool: ["run_terminal"]
        any_param_matches:
          - '(?i)\bgit\s+(commit|push)\b'
      reason: "Commits to main require a human approval."
"#;
    let engine = Engine::from_yaml(yaml).unwrap();
    let params = serde_json::json!({
        "name": "run_terminal",
        "arguments": { "command": "git push origin main" }
    });
    let eval = engine.evaluate("run_terminal", &params, Adjustments::default());
    assert!(matches!(decide(&eval), Decision::Approval { .. }));
}

#[tokio::test]
async fn cached_proof_satisfies_subsequent_evaluations() {
    let (gate, _tmp) = fresh_gate();
    let provider = gate.provider("mock").expect("mock provider registered");

    let req = IdentityRequirement {
        provider: "mock".into(),
        scope: "scm.commit_to_main".into(),
        allowed_subjects: vec!["*".into()],
        max_proof_age_seconds: 900,
        loa: 2,
    };
    // No proof in the cache initially.
    assert!(gate.cached_proof_for(&req).is_none());

    // Drive the mock through begin -> exchange -> mint+cache.
    let creq = ChallengeRequest {
        rule_id: "scm.commit_to_main".into(),
        requirement: req.clone(),
        callback_url: "http://127.0.0.1:9999/callback".into(),
        challenge_id: "ch-e2e-1".into(),
    };
    let _ch = provider.begin(creq).await.unwrap();
    let vi = provider
        .exchange("ch-e2e-1", "synthetic-code", "ch-e2e-1", None)
        .await
        .unwrap();
    let proof = gate.mint_and_cache(&vi, &req).unwrap();
    assert!(proof.sig.starts_with("ed25519:"));
    assert_eq!(proof.provider, "mock");
    assert_eq!(proof.scope, "scm.commit_to_main");

    // Cache hit on next lookup with the same requirement.
    let hit = gate.cached_proof_for(&req).expect("cache hit");
    assert_eq!(hit.subject, vi.subject);
    assert!(hit.expires_at > hit.verified_at);
}

#[tokio::test]
async fn proof_for_one_scope_does_not_satisfy_another() {
    let (gate, _tmp) = fresh_gate();
    let provider = gate.provider("mock").unwrap();

    let scope_a = IdentityRequirement {
        provider: "mock".into(),
        scope: "scm.commit_to_main".into(),
        allowed_subjects: vec!["*".into()],
        max_proof_age_seconds: 900,
        loa: 2,
    };
    let scope_b = IdentityRequirement {
        provider: "mock".into(),
        scope: "db.production_apply".into(),
        allowed_subjects: vec!["*".into()],
        max_proof_age_seconds: 900,
        loa: 2,
    };

    let creq = ChallengeRequest {
        rule_id: "scm.commit_to_main".into(),
        requirement: scope_a.clone(),
        callback_url: "http://127.0.0.1:9999/callback".into(),
        challenge_id: "ch-scope-a".into(),
    };
    let _ = provider.begin(creq).await.unwrap();
    let vi = provider
        .exchange("ch-scope-a", "synthetic", "ch-scope-a", None)
        .await
        .unwrap();
    gate.mint_and_cache(&vi, &scope_a).unwrap();

    assert!(gate.cached_proof_for(&scope_a).is_some());
    assert!(
        gate.cached_proof_for(&scope_b).is_none(),
        "a proof for scope_a must NOT satisfy a request for scope_b"
    );
}

#[tokio::test]
async fn loa_below_requirement_does_not_satisfy() {
    // Mock at LOA 1, rule requires LOA 2.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig::default();
    let mock = Arc::new(MockProvider::new("mock", "subject-loa1", Some(format!("{}@{}", "low", "test")), 1));
    let gate = IdentityGate::new(cfg, vec![mock], tmp.path().to_path_buf()).unwrap();
    let provider = gate.provider("mock").unwrap();

    let req = IdentityRequirement {
        provider: "mock".into(),
        scope: "scm.commit_to_main".into(),
        allowed_subjects: vec!["*".into()],
        max_proof_age_seconds: 900,
        loa: 2,
    };
    let creq = ChallengeRequest {
        rule_id: "scm.commit_to_main".into(),
        requirement: req.clone(),
        callback_url: "http://127.0.0.1:9999/callback".into(),
        challenge_id: "ch-loa".into(),
    };
    let _ = provider.begin(creq).await.unwrap();
    let vi = provider.exchange("ch-loa", "s", "ch-loa", None).await.unwrap();
    gate.mint_and_cache(&vi, &req).unwrap();
    // The mint stores the LOA-1 proof. Requirement wants LOA-2.
    assert!(
        gate.cached_proof_for(&req).is_none(),
        "a proof with LOA below the requirement must NOT satisfy"
    );
}

#[tokio::test]
async fn allowlist_restricts_which_subjects_can_satisfy() {
    let (gate, _tmp) = fresh_gate();
    let provider = gate.provider("mock").unwrap();

    let allowed = format!("{}@{}", "ace", "aperion.ai");
    let _denied = format!("{}@{}", "bee", "other.com");

    // Restricting to a specific allowed_subject value.
    let req = IdentityRequirement {
        provider: "mock".into(),
        scope: "scm.commit_to_main".into(),
        allowed_subjects: vec![allowed.clone()],
        max_proof_age_seconds: 900,
        loa: 2,
    };
    // Mock issues identity for "[email protected]" (its default config).
    let creq = ChallengeRequest {
        rule_id: "scm.commit_to_main".into(),
        requirement: req.clone(),
        callback_url: "http://127.0.0.1:9999/callback".into(),
        challenge_id: "ch-allow".into(),
    };
    let _ = provider.begin(creq).await.unwrap();
    let vi = provider.exchange("ch-allow", "s", "ch-allow", None).await.unwrap();
    gate.mint_and_cache(&vi, &req).unwrap();
    // The mock's email is "[email protected]", which is NOT on the
    // allow-list (which contains "[email protected]"). So the cached
    // proof must not satisfy the requirement.
    assert!(gate.cached_proof_for(&req).is_none());
}

#[test]
fn flush_clears_the_cache() {
    let yaml = r#"
shieldset:
  version: 2
  rules: []
"#;
    let _engine = Engine::from_yaml(yaml).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let cfg = IdentityConfig::default();
    let mock = Arc::new(MockProvider::new("mock", "subject", Some(format!("{}@{}", "demo", "x")), 2));
    let gate = IdentityGate::new(cfg, vec![mock.clone()], tmp.path().to_path_buf()).unwrap();
    let req = IdentityRequirement {
        provider: "mock".into(),
        scope: "x".into(),
        allowed_subjects: vec!["*".into()],
        max_proof_age_seconds: 900,
        loa: 2,
    };
    let vi = aperion_shield::identity::VerifiedIdentity {
        provider: "mock".into(),
        subject: "subject".into(),
        email: Some(format!("{}@{}", "demo", "x")),
        loa: 2,
        raw: serde_json::Value::Null,
    };
    gate.mint_and_cache(&vi, &req).unwrap();
    assert_eq!(gate.cached_count(), 1);
    let evicted = gate.flush().unwrap();
    assert_eq!(evicted, 1);
    assert_eq!(gate.cached_count(), 0);
}

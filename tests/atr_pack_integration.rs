//! Integration tests for the ATR community rule pack
//! (`config/shieldset-atr.yaml`).
//!
//! Three layers:
//!   1. the pack parses and every regex compiles (Engine::extend_from_yaml
//!      is the authoritative validator -- it uses the same `regex` crate
//!      the proxy uses at runtime);
//!   2. merging the pack on top of the bundled defaults works, grows the
//!      rule count, and rejects duplicate ids;
//!   3. the upstream corpus's own true-positive / true-negative cases
//!      (vendored in `tests/fixtures/atr_cases.json`) behave as labelled
//!      when run through `evaluate_scoped_text`.

use aperion_shield::engine::{Adjustments, Engine, Scope};

const PACK: &str = include_str!("../config/shieldset-atr.yaml");
const CASES: &str = include_str!("fixtures/atr_cases.json");

#[derive(serde::Deserialize)]
struct Case {
    rule_id: String,
    scope: String,
    text: String,
    expect: String,
}

fn scope_of(name: &str) -> Scope {
    match name {
        "tool_result" => Scope::ToolResult,
        "tool_description" => Scope::ToolDescription,
        "llm_response" => Scope::LlmResponse,
        other => panic!("unknown scope in fixture: {other}"),
    }
}

fn engine_with_pack() -> Engine {
    let mut e = Engine::builtin_default();
    e.extend_from_yaml(PACK).expect("ATR pack must merge cleanly");
    e
}

#[test]
fn pack_parses_and_merges_on_top_of_defaults() {
    let base_count = Engine::builtin_default().rules.len();
    let merged = engine_with_pack();
    assert!(
        merged.rules.len() > base_count,
        "pack should add rules ({} -> {})",
        base_count,
        merged.rules.len()
    );
    // Every pack rule id carries the atr. prefix so provenance is
    // visible in block messages and audit logs.
    let atr_rules = merged
        .rules
        .iter()
        .filter(|r| r.id.starts_with("atr."))
        .count();
    assert_eq!(atr_rules, merged.rules.len() - base_count);
}

#[test]
fn duplicate_rule_ids_are_rejected() {
    let mut e = engine_with_pack();
    // Merging the same pack twice must fail loudly, not double-count.
    let err = e.extend_from_yaml(PACK).unwrap_err();
    assert!(
        err.to_string().contains("duplicate rule id"),
        "unexpected error: {err}"
    );
}

#[test]
fn pack_policy_block_is_ignored() {
    let mut e = Engine::builtin_default();
    let baseline_pinning = e.policy.supply_chain.pinning;
    let pack_with_policy = r#"
shieldset:
  policy:
    supply_chain:
      pinning: false
  rules:
    - id: atr.test.policy_ignored
      severity: Low
      where: tool_result
      match:
        text_matches:
          - 'xyzzy-policy-test'
      reason: "test rule"
"#;
    e.extend_from_yaml(pack_with_policy).unwrap();
    assert_eq!(
        e.policy.supply_chain.pinning, baseline_pinning,
        "a rule pack must not be able to change policy"
    );
}

/// Run the vendored ATR true-positive / true-negative corpus.
///
/// TP semantics: the named rule must be among the matches for its scope.
/// TN semantics: the named rule must NOT match (other rules in the
/// merged set may legitimately fire on the same text; that is not a
/// failure of THIS rule's precision).
#[test]
fn upstream_corpus_cases_behave_as_labelled() {
    let engine = engine_with_pack();
    let cases: Vec<Case> = serde_json::from_str(CASES).expect("fixture parses");
    assert!(cases.len() > 300, "expected a substantial corpus, got {}", cases.len());

    let mut tp_failures = Vec::new();
    let mut tn_failures = Vec::new();
    for c in &cases {
        let eval = engine.evaluate_scoped_text(
            scope_of(&c.scope),
            None,
            &c.text,
            Adjustments::default(),
        );
        let fired = eval.matches.iter().any(|m| m.rule_id == c.rule_id);
        match c.expect.as_str() {
            "triggered" if !fired => tp_failures.push(format!("{}: {:?}", c.rule_id, c.text)),
            "not_triggered" if fired => tn_failures.push(format!("{}: {:?}", c.rule_id, c.text)),
            _ => {}
        }
    }
    assert!(
        tp_failures.is_empty() && tn_failures.is_empty(),
        "TP misses ({}):\n{}\n\nTN false fires ({}):\n{}",
        tp_failures.len(),
        tp_failures.join("\n"),
        tn_failures.len(),
        tn_failures.join("\n"),
    );
}

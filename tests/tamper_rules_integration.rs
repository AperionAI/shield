//! ATR-style fixtures for the bundled `tamper.*` rules in shieldset.yaml.
//! True-positive / true-negative cases live in `tests/fixtures/tamper_cases.json`.

use aperion_shield::engine::{Adjustments, Engine};

#[derive(serde::Deserialize)]
struct Case {
    tool: String,
    params: serde_json::Value,
    expect_rule: String,
    expect: String,
}

const CASES: &str = include_str!("fixtures/tamper_cases.json");

#[test]
fn tamper_rules_behave_as_labelled() {
    let engine = Engine::builtin_default();
    let cases: Vec<Case> = serde_json::from_str(CASES).expect("tamper fixture parses");
    assert!(cases.len() >= 6, "expected several tamper fixtures, got {}", cases.len());

    let mut tp_failures = Vec::new();
    let mut tn_failures = Vec::new();
    for c in &cases {
        let eval = engine.evaluate(&c.tool, &c.params, Adjustments::default());
        let fired = eval.matches.iter().any(|m| m.rule_id == c.expect_rule);
        match c.expect.as_str() {
            "triggered" if !fired => tp_failures.push(format!(
                "{} on {}: {:?}",
                c.expect_rule, c.tool, c.params
            )),
            "not_triggered" if fired => tn_failures.push(format!(
                "{} on {}: {:?}",
                c.expect_rule, c.tool, c.params
            )),
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

#[test]
fn bundled_defaults_include_tamper_rules() {
    let engine = Engine::builtin_default();
    for id in [
        "tamper.shield_self_paths",
        "tamper.shield_disable",
        "tamper.gateway_admin_api",
        "tamper.admin_secret_read",
    ] {
        assert!(
            engine.rules.iter().any(|r| r.id == id),
            "missing bundled rule {id}"
        );
    }
}

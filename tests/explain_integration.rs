//! End-to-end tests for `aperion-shield --explain`. These exercise the
//! CLI from the outside (spawning the release binary, feeding stdin)
//! to verify the wiring between `clap`, the dispatcher in main.rs,
//! and the rendering code in `src/explain/`.
//!
//! Unit-level coverage of the rendering itself lives in
//! `src/explain/render.rs`; what we want here is "does the CLI shape
//! that users actually type work end-to-end?".

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn aperion_shield_binary() -> PathBuf {
    let dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(dir).join("target/release/aperion-shield");
    assert!(
        path.exists(),
        "expected release binary at {} -- run `cargo build --release` before integration tests",
        path.display()
    );
    path
}

/// Helper: pipe `payload` to `aperion-shield --explain --input -` with
/// optional extra args, return (stdout, exit_code).
fn run_explain(payload: &str, extra: &[&str]) -> (String, i32) {
    let mut cmd = Command::new(aperion_shield_binary());
    cmd.args(["--explain", "--input", "-"]).args(extra);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn aperion-shield --explain");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn explain_text_format_yields_walkthrough_for_blocked_call() {
    let payload = r#"{"name": "shell", "arguments": {"command": "rm -rf /"}}"#;
    let (stdout, exit) = run_explain(payload, &[]);
    assert_eq!(exit, 1, "block should exit 1");
    assert!(stdout.contains("shield --explain"), "got:\n{}", stdout);
    assert!(stdout.contains("decision"));
    assert!(stdout.contains("fs.recursive_delete_root"));
    assert!(
        stdout.contains("BLOCK") || stdout.contains("APPROVAL"),
        "expected BLOCK or APPROVAL banner; got:\n{}",
        stdout
    );
    assert!(stdout.contains("suggest"));
}

#[test]
fn explain_markdown_format_renders_section_tables() {
    let payload = r#"{"name": "shell", "arguments": {"command": "rm -rf /"}}"#;
    let (stdout, _exit) = run_explain(payload, &["--explain-format", "markdown"]);
    assert!(
        stdout.starts_with("### `aperion-shield --explain`"),
        "got:\n{}",
        stdout
    );
    assert!(stdout.contains("**Rules matched"));
    assert!(stdout.contains("**Severities:**"));
    assert!(stdout.contains("**Decision detail:**"));
}

#[test]
fn explain_json_format_is_parseable_and_has_stable_schema() {
    let payload = r#"{"name": "shell", "arguments": {"command": "rm -rf /"}}"#;
    let (stdout, _exit) = run_explain(payload, &["--explain-format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("json parse failed: {}\nstdout was:\n{}", e, stdout));
    assert_eq!(v["tool"], "shell");
    assert!(v.get("rules_matched").is_some());
    assert!(v.get("decision").is_some());
    assert!(v.get("adjustment_signals").is_some());
    assert_eq!(v["severity_final"], "Critical");
    let dec_kind = v["decision"]["kind"].as_str().unwrap_or("");
    assert!(
        matches!(dec_kind, "block" | "approval"),
        "got: {}",
        dec_kind
    );
}

#[test]
fn explain_allow_case_exits_zero_and_omits_decision_detail_block() {
    let payload = r#"{"name": "shell", "arguments": {"command": "echo hi"}}"#;
    let (stdout, exit) = run_explain(payload, &[]);
    assert_eq!(exit, 0, "allow should exit 0");
    assert!(stdout.contains("ALLOW"));
    assert!(!stdout.contains("rule_id"));
}

#[test]
fn explain_force_prod_flag_shows_signal_in_adjustment_block() {
    let payload = r#"{"name": "shell", "arguments": {"command": "echo hi"}}"#;
    let (stdout, _exit) = run_explain(payload, &["--explain-force-prod"]);
    // The signal is "present but unused" (no rules eligible for the
    // benign echo call) -- we still surface it so the user can see
    // what their probe would have inferred.
    assert!(
        stdout.contains("workspace_is_prod"),
        "force-prod should surface the signal in the adjustments section; got:\n{}",
        stdout
    );
}

#[test]
fn explain_legacy_tool_params_shape_is_accepted() {
    // Some upstream tooling still emits the legacy shape
    // {"tool": ..., "params": ...} rather than the MCP-canonical
    // {"name": ..., "arguments": ...}. Keep accepting both so we
    // don't break existing automations.
    let payload = r#"{"tool": "shell", "params": {"command": "rm -rf /"}}"#;
    let (stdout, exit) = run_explain(payload, &[]);
    assert_eq!(exit, 1);
    assert!(
        stdout.contains("fs.recursive_delete_root"),
        "legacy shape should still trigger the rule; got:\n{}",
        stdout
    );
}

#[test]
fn explain_rejects_input_without_a_tool_name() {
    // Missing the required `name` (or legacy `tool`) field -- should
    // refuse with a useful error rather than crashing.
    let payload = r#"{"arguments": {"command": "rm -rf /"}}"#;
    let mut cmd = Command::new(aperion_shield_binary());
    cmd.args(["--explain", "--input", "-"]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "should refuse missing tool name");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("name") || stderr.contains("tool"),
        "error should mention the missing field; got stderr:\n{}",
        stderr
    );
}

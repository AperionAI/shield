//! Integration coverage for `aperion-shield --diff`.
//!
//! Each test invokes the compiled binary against one of the fixture
//! pairs in `tests/diff/` and asserts on the parsed `--format json`
//! payload. The JSON schema is contractual -- it's the public
//! source-compatibility surface with `scripts/shield-diff.py` and
//! with any CI workflow already wired to the Python prototype --
//! so the tests assert against specific fields rather than golden
//! string comparison.
//!
//! Running locally:
//!
//!     cargo test --release --test diff_integration
//!
//! These tests require `cargo build --release` to have produced the
//! binary at `target/release/aperion-shield`. Cargo handles that
//! automatically when you run via `cargo test`; if you ever invoke
//! the test binary directly, build the release binary first.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Resolve the release binary path. Cargo sets `CARGO_BIN_EXE_<name>`
/// for the target's own integration tests, which is the canonical
/// way to reach it without hardcoding paths.
fn shield_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aperion-shield"))
}

/// Invoke `aperion-shield --diff` with the given fixture stem
/// (e.g. "loosen") and return the parsed JSON payload from the
/// `--format json` output. Fails the test loudly on any stderr,
/// nonzero exit, or invalid JSON.
fn run_diff_json(stem: &str) -> Value {
    let dir = "tests/diff";
    let before = format!("{}/{}.before.yaml", dir, stem);
    let after = format!("{}/{}.after.yaml", dir, stem);
    let corpus = format!("{}/{}.corpus.jsonl", dir, stem);

    let output = Command::new(shield_bin())
        .arg("--diff")
        .args(["--rules-before", &before])
        .args(["--rules-after", &after])
        .args(["--corpus", &corpus])
        .args(["--format", "json"])
        .output()
        .expect("failed to run aperion-shield --diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "aperion-shield --diff exited non-zero on `{}`. \
         stderr:\n{}\nstdout:\n{}",
        stem,
        stderr,
        stdout,
    );

    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "aperion-shield --diff produced invalid JSON for `{}`: {}\nstdout:\n{}",
            stem, e, stdout
        )
    })
}

/// Pull the per-rule entry for `rule_id` out of a JSON payload's
/// `rules` array. Returns `None` if the rule isn't listed.
fn find_rule<'a>(payload: &'a Value, rule_id: &str) -> Option<&'a Value> {
    payload
        .get("rules")?
        .as_array()?
        .iter()
        .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(rule_id))
}

/// Count flips matching a `from -> to` direction in the payload.
fn count_flip(payload: &Value, from: &str, to: &str) -> i64 {
    payload
        .get("flips")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|f| {
                    f.get("from").and_then(|v| v.as_str()) == Some(from)
                        && f.get("to").and_then(|v| v.as_str()) == Some(to)
                })
                .filter_map(|f| f.get("count").and_then(|v| v.as_i64()))
                .sum()
        })
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────
// Scenario 1: LOOSEN -- removing a Block-tier rule
// ────────────────────────────────────────────────────────────────────

#[test]
fn loosen_drops_drop_database_and_flips_block_to_allow() {
    let p = run_diff_json("loosen");

    // sql.drop_database is gone in the after-state.
    let dropped = find_rule(&p, "sql.drop_database").expect("sql.drop_database in rules[]");
    assert_eq!(
        dropped.get("status").and_then(|v| v.as_str()),
        Some("removed")
    );
    assert_eq!(
        dropped.get("fires_before").and_then(|v| v.as_i64()),
        Some(1)
    );
    assert_eq!(dropped.get("fires_after").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(
        dropped.get("flipped_caused").and_then(|v| v.as_i64()),
        Some(1),
        "the removed rule should be attributed with the single flipped line"
    );

    // sql.drop_table is unchanged and still fires.
    let kept = find_rule(&p, "sql.drop_table").expect("sql.drop_table in rules[]");
    assert_eq!(
        kept.get("status").and_then(|v| v.as_str()),
        Some("unchanged")
    );
    assert_eq!(kept.get("fires_before"), kept.get("fires_after"));

    // Exactly one block -> allow flip.
    assert_eq!(count_flip(&p, "block", "allow"), 1);
    assert_eq!(
        p.get("loosened_count").and_then(|v| v.as_i64()),
        Some(1),
        "removing a Critical rule must register as loosening"
    );
}

// ────────────────────────────────────────────────────────────────────
// Scenario 2: TIGHTEN -- changing severity Low -> High
// ────────────────────────────────────────────────────────────────────

#[test]
fn tighten_curl_pipe_sh_flips_allow_to_approval() {
    let p = run_diff_json("tighten");

    let r = find_rule(&p, "supply.curl_pipe_sh").expect("rule in payload");
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("modified"));

    assert_eq!(
        count_flip(&p, "allow", "approval"),
        1,
        "tightening Low -> High should push the matching corpus line allow -> approval"
    );
    assert_eq!(
        p.get("loosened_count").and_then(|v| v.as_i64()),
        Some(0),
        "tightening must NOT count as loosening",
    );
}

// ────────────────────────────────────────────────────────────────────
// Scenario 3: NOOP -- identical shieldsets
// ────────────────────────────────────────────────────────────────────

#[test]
fn noop_emits_zero_flips() {
    let p = run_diff_json("noop");

    let flips = p.get("flips").and_then(|v| v.as_array()).expect("flips[]");
    assert!(
        flips.is_empty(),
        "noop scenario must produce zero flips, got {:?}",
        flips
    );
    assert_eq!(p.get("loosened_count").and_then(|v| v.as_i64()), Some(0));

    // Decision distribution must be identical before vs after.
    let before = p.get("decision_before").expect("decision_before");
    let after = p.get("decision_after").expect("decision_after");
    assert_eq!(before, after, "noop must leave decision counts identical");

    // Every rule's status must be "unchanged".
    for r in p.get("rules").unwrap().as_array().unwrap() {
        assert_eq!(
            r.get("status").and_then(|v| v.as_str()),
            Some("unchanged"),
            "all rules must be 'unchanged' in noop scenario, got {:?}",
            r
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Scenario 4: ADDED -- a new rule appears
// ────────────────────────────────────────────────────────────────────

#[test]
fn added_rule_flips_allow_to_approval_and_status_added() {
    let p = run_diff_json("added");

    let r = find_rule(&p, "company.no_prod_writes").expect("new rule listed");
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("added"));
    assert_eq!(r.get("fires_before").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(r.get("fires_after").and_then(|v| v.as_i64()), Some(1));
    assert_eq!(
        r.get("flipped_caused").and_then(|v| v.as_i64()),
        Some(1),
        "the added rule should be attributed with its flipped line"
    );

    assert_eq!(count_flip(&p, "allow", "approval"), 1);
    assert_eq!(p.get("loosened_count").and_then(|v| v.as_i64()), Some(0));
}

// ────────────────────────────────────────────────────────────────────
// Scenario 5: REMOVED -- inverse of added
// ────────────────────────────────────────────────────────────────────

#[test]
fn removed_rule_flips_approval_to_allow_and_counts_as_loosening() {
    let p = run_diff_json("removed");

    let r = find_rule(&p, "company.no_prod_writes").expect("removed rule listed");
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("removed"));
    assert_eq!(r.get("fires_before").and_then(|v| v.as_i64()), Some(1));
    assert_eq!(r.get("fires_after").and_then(|v| v.as_i64()), Some(0));

    assert_eq!(count_flip(&p, "approval", "allow"), 1);
    assert_eq!(
        p.get("loosened_count").and_then(|v| v.as_i64()),
        Some(1),
        "approval -> allow is loosening"
    );
}

// ────────────────────────────────────────────────────────────────────
// Scenario 6: MODIFIED -- existing rule's severity changes
// ────────────────────────────────────────────────────────────────────

#[test]
fn modified_severity_change_flips_warn_to_approval() {
    let p = run_diff_json("modified");

    let r = find_rule(&p, "sql.alter_table_drop_column").expect("modified rule listed");
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("modified"));

    assert_eq!(count_flip(&p, "warn", "approval"), 1);
    assert_eq!(p.get("loosened_count").and_then(|v| v.as_i64()), Some(0));
}

// ────────────────────────────────────────────────────────────────────
// Exit-code policy
// ────────────────────────────────────────────────────────────────────

#[test]
fn fail_if_loosened_returns_exit_1_on_loosening() {
    let out = Command::new(shield_bin())
        .args(["--diff"])
        .args(["--rules-before", "tests/diff/loosen.before.yaml"])
        .args(["--rules-after", "tests/diff/loosen.after.yaml"])
        .args(["--corpus", "tests/diff/loosen.corpus.jsonl"])
        .args(["--format", "json"])
        .arg("--fail-if-loosened")
        .output()
        .expect("run diff");
    assert_eq!(
        out.status.code(),
        Some(1),
        "--fail-if-loosened must exit 1 on a loosening change"
    );
}

#[test]
fn fail_if_flipped_returns_exit_0_on_noop() {
    let out = Command::new(shield_bin())
        .args(["--diff"])
        .args(["--rules-before", "tests/diff/noop.before.yaml"])
        .args(["--rules-after", "tests/diff/noop.after.yaml"])
        .args(["--corpus", "tests/diff/noop.corpus.jsonl"])
        .args(["--format", "json"])
        .arg("--fail-if-flipped")
        .output()
        .expect("run diff");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--fail-if-flipped must exit 0 when nothing flipped"
    );
}

#[test]
fn fail_if_allows_loosened_threshold_honoured() {
    let mut cmd = Command::new(shield_bin());
    cmd.args(["--diff"])
        .args(["--rules-before", "tests/diff/loosen.before.yaml"])
        .args(["--rules-after", "tests/diff/loosen.after.yaml"])
        .args(["--corpus", "tests/diff/loosen.corpus.jsonl"])
        .args(["--format", "json"]);
    let under = cmd
        .args(["--fail-if-allows-loosened", "5"])
        .output()
        .expect("run diff");
    assert_eq!(
        under.status.code(),
        Some(0),
        "threshold 5 with only 1 flip to allow must exit 0"
    );

    let out_over = Command::new(shield_bin())
        .args(["--diff"])
        .args(["--rules-before", "tests/diff/loosen.before.yaml"])
        .args(["--rules-after", "tests/diff/loosen.after.yaml"])
        .args(["--corpus", "tests/diff/loosen.corpus.jsonl"])
        .args(["--format", "json"])
        .args(["--fail-if-allows-loosened", "0"])
        .output()
        .expect("run diff");
    assert_eq!(
        out_over.status.code(),
        Some(1),
        "threshold 0 with 1 flip to allow must exit 1"
    );
}

// ────────────────────────────────────────────────────────────────────
// Format variants
// ────────────────────────────────────────────────────────────────────

#[test]
fn markdown_format_contains_expected_sections() {
    let out = Command::new(shield_bin())
        .args(["--diff"])
        .args(["--rules-before", "tests/diff/loosen.before.yaml"])
        .args(["--rules-after", "tests/diff/loosen.after.yaml"])
        .args(["--corpus", "tests/diff/loosen.corpus.jsonl"])
        .args(["--format", "markdown"])
        .output()
        .expect("run diff");
    assert!(out.status.success(), "markdown render must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("shieldset behavior diff"), "missing header");
    assert!(stdout.contains("| decision |"), "missing decision table");
    assert!(
        stdout.contains("Behavioral impact"),
        "missing behavioral section"
    );
    assert!(stdout.contains("loosened"), "missing loosening warning");
}

#[test]
fn text_format_is_default_and_includes_summary() {
    let out = Command::new(shield_bin())
        .args(["--diff"])
        .args(["--rules-before", "tests/diff/loosen.before.yaml"])
        .args(["--rules-after", "tests/diff/loosen.after.yaml"])
        .args(["--corpus", "tests/diff/loosen.corpus.jsonl"])
        .output()
        .expect("run diff");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("shield-diff:"), "missing text header");
    assert!(stdout.contains("DECISION DISTRIBUTION"));
    assert!(stdout.contains("RULESET CHANGES"));
    assert!(stdout.contains("BEHAVIORAL IMPACT BY RULE"));
    assert!(stdout.contains("SUMMARY"));
}

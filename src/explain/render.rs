//! Output formats for `--explain`.
//!
//! Three render targets, all driven off the same `ExplainReport`
//! captured by `crate::explain::explain`:
//!
//!  * **text** -- terminal-friendly, fixed-width, designed to render
//!    cleanly without ANSI in any 80-column shell.
//!  * **markdown** -- GitHub-flavoured. Drops into a PR review comment
//!    with collapsible details for the rule list.
//!  * **json** -- a stable schema (NOT the engine's internal struct)
//!    suitable for piping into other tooling.

use serde::Serialize;
use serde_json::Value;

use crate::engine::{Adjustments, Evaluation, MatchInfo, Severity};
use crate::explain::{ExplainOptions, ToolCallDescriptor};
use crate::Decision;

/// Output format selector for `--explain-format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainFormat {
    Text,
    Markdown,
    Json,
}

impl ExplainFormat {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "text" | "txt" => Ok(Self::Text),
            "markdown" | "md" => Ok(Self::Markdown),
            "json" => Ok(Self::Json),
            other => Err(anyhow::anyhow!(
                "unknown --explain-format '{}' (expected text|markdown|json)",
                other
            )),
        }
    }
}

/// Everything `--explain` needs to render. Built by `explain::explain`,
/// passed by reference to the format functions. Captured by value so
/// callers can pickle reports across format selections without
/// rebuilding the engine state.
#[derive(Debug, Clone)]
pub struct ExplainReport {
    pub descriptor: ToolCallDescriptor,
    pub adjustments: Adjustments,
    pub evaluation: Evaluation,
    pub decision: Decision,
    pub options: ExplainOptions,
}

impl ExplainReport {
    /// Process exit code for a CLI invocation that's not just looking
    /// for the output. Mirrors `--check-cmd` so users can pipe
    /// `--explain` into the same shell scripts. Allow/Warn → 0,
    /// Block → 1, Approval/IdentityVerification → 2.
    pub fn exit_code(&self) -> u8 {
        match &self.decision {
            Decision::Allow | Decision::Warn { .. } => 0,
            Decision::Block { .. } => 1,
            Decision::Approval { .. } | Decision::IdentityVerification { .. } => 2,
        }
    }
}

pub fn render(report: &ExplainReport, format: ExplainFormat) -> String {
    match format {
        ExplainFormat::Text => render_text(report),
        ExplainFormat::Markdown => render_markdown(report),
        ExplainFormat::Json => render_json(report),
    }
}

// ─────────────────────────────────────────────────────────────────────
// text
// ─────────────────────────────────────────────────────────────────────

fn render_text(r: &ExplainReport) -> String {
    let mut out = String::new();
    out.push_str("shield --explain\n");
    out.push_str("────────────────\n");
    out.push_str(&format!("tool   : {}\n", r.descriptor.tool));
    let args_one_line = r
        .descriptor
        .arguments
        .to_string()
        .chars()
        .take(180)
        .collect::<String>();
    out.push_str(&format!("call   : {}\n", args_one_line));
    out.push('\n');

    // rules matched
    out.push_str(&format!(
        "rules matched ............................. {}\n",
        r.evaluation.matches.len()
    ));
    if r.evaluation.matches.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for m in sorted_matches(&r.evaluation.matches) {
            out.push_str(&format!(
                "  {:<32} {:<10} pts={}\n",
                m.rule_id,
                m.severity.as_str(),
                m.points,
            ));
        }
    }
    out.push('\n');

    // adjustments applied
    let adj_lines = describe_adjustments_text(&r.adjustments, &r.evaluation.adjustments_applied);
    out.push_str(&format!(
        "adjustments applied ....................... {}\n",
        adj_lines.len()
    ));
    if adj_lines.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for line in &adj_lines {
            out.push_str(&format!("  {}\n", line));
        }
    }
    out.push('\n');

    // severities
    out.push_str("severities\n");
    out.push_str(&format!(
        "  raw       : {}\n",
        r.evaluation.raw_severity.as_str()
    ));
    out.push_str(&format!(
        "  composite : {}  (composite_points={})\n",
        r.evaluation.composite_severity.as_str(),
        r.evaluation.composite_points
    ));
    out.push_str(&format!(
        "  final     : {}\n",
        r.evaluation.final_severity.as_str()
    ));
    out.push('\n');

    // decision
    let (label, detail) = describe_decision(&r.decision);
    out.push_str(&format!(
        "decision .................................. {}\n",
        label
    ));
    for (k, v) in detail {
        out.push_str(&format!("  {:<8} : {}\n", k, v));
    }

    out
}

// ─────────────────────────────────────────────────────────────────────
// markdown
// ─────────────────────────────────────────────────────────────────────

fn render_markdown(r: &ExplainReport) -> String {
    let mut out = String::new();
    out.push_str("### `aperion-shield --explain`\n\n");
    out.push_str(&format!(
        "| field | value |\n|---|---|\n| tool | `{}` |\n",
        r.descriptor.tool
    ));
    let args_one_line = r
        .descriptor
        .arguments
        .to_string()
        .chars()
        .take(120)
        .collect::<String>();
    out.push_str(&format!(
        "| call | `{}` |\n",
        md_escape_table(&args_one_line)
    ));
    out.push_str(&format!(
        "| decision | **{}** |\n",
        describe_decision(&r.decision).0
    ));
    out.push_str(&format!(
        "| final severity | `{}` |\n\n",
        r.evaluation.final_severity.as_str()
    ));

    // rules
    out.push_str(&format!(
        "**Rules matched ({}):**\n\n",
        r.evaluation.matches.len()
    ));
    if r.evaluation.matches.is_empty() {
        out.push_str("_(none)_\n\n");
    } else {
        out.push_str("| rule | severity | points | reason |\n|---|---|---|---|\n");
        for m in sorted_matches(&r.evaluation.matches) {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                m.rule_id,
                m.severity.as_str(),
                m.points,
                md_escape_table(&m.reason),
            ));
        }
        out.push('\n');
    }

    // adjustments
    let adj_lines = describe_adjustments_text(&r.adjustments, &r.evaluation.adjustments_applied);
    out.push_str(&format!(
        "**Adjustments applied ({}):**\n\n",
        adj_lines.len()
    ));
    if adj_lines.is_empty() {
        out.push_str("_(none)_\n\n");
    } else {
        for line in &adj_lines {
            out.push_str(&format!("- {}\n", line));
        }
        out.push('\n');
    }

    // severities
    out.push_str("**Severities:**\n\n");
    out.push_str("| stage | severity |\n|---|---|\n");
    out.push_str(&format!(
        "| raw | `{}` |\n",
        r.evaluation.raw_severity.as_str()
    ));
    out.push_str(&format!(
        "| composite (points={}) | `{}` |\n",
        r.evaluation.composite_points,
        r.evaluation.composite_severity.as_str()
    ));
    out.push_str(&format!(
        "| final | `{}` |\n\n",
        r.evaluation.final_severity.as_str()
    ));

    // decision detail
    let (_, detail) = describe_decision(&r.decision);
    if !detail.is_empty() {
        out.push_str("**Decision detail:**\n\n");
        for (k, v) in detail {
            out.push_str(&format!("- **{}**: {}\n", k, v));
        }
        out.push('\n');
    }

    out
}

fn md_escape_table(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

// ─────────────────────────────────────────────────────────────────────
// json
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ExplainJson<'a> {
    pub tool: &'a str,
    pub arguments: &'a Value,
    pub rules_matched: Vec<RuleMatchJson>,
    pub adjustments_applied: Vec<&'static str>,
    pub adjustment_signals: AdjustmentSignalsJson,
    pub severity_raw: &'static str,
    pub severity_composite: &'static str,
    pub severity_final: &'static str,
    pub composite_points: u32,
    pub decision: DecisionJson,
}

#[derive(Debug, Serialize)]
pub struct RuleMatchJson {
    pub rule_id: String,
    pub severity: &'static str,
    pub points: u32,
    pub reason: String,
    pub safer_alternative: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdjustmentSignalsJson {
    pub workspace_is_prod: bool,
    pub burst_in_progress: bool,
    pub fingerprint_repeatedly_approved: bool,
    pub fingerprint_recently_denied: bool,
    pub tainted_secret_in_flight: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum DecisionJson {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "warn")]
    Warn {
        rule_id: String,
        severity: &'static str,
        safer_alternative: Option<String>,
    },
    #[serde(rename = "block")]
    Block {
        rule_id: String,
        severity: &'static str,
        reason: String,
        safer_alternative: Option<String>,
        contributing_rules: Vec<String>,
    },
    #[serde(rename = "approval")]
    Approval {
        rule_id: String,
        severity: &'static str,
        reason: String,
        safer_alternative: Option<String>,
        contributing_rules: Vec<String>,
    },
    #[serde(rename = "identity-verification")]
    IdentityVerification {
        rule_id: String,
        severity: &'static str,
        reason: String,
        safer_alternative: Option<String>,
    },
}

impl DecisionJson {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Warn {
                rule_id,
                severity,
                safer_alternative,
                ..
            } => Self::Warn {
                rule_id: rule_id.clone(),
                severity: severity.as_str(),
                safer_alternative: safer_alternative.clone(),
            },
            Decision::Block {
                rule_id,
                severity,
                reason,
                safer_alternative,
                contributing_rules,
            } => Self::Block {
                rule_id: rule_id.clone(),
                severity: severity.as_str(),
                reason: reason.clone(),
                safer_alternative: safer_alternative.clone(),
                contributing_rules: contributing_rules.clone(),
            },
            Decision::Approval {
                rule_id,
                severity,
                reason,
                safer_alternative,
                contributing_rules,
            } => Self::Approval {
                rule_id: rule_id.clone(),
                severity: severity.as_str(),
                reason: reason.clone(),
                safer_alternative: safer_alternative.clone(),
                contributing_rules: contributing_rules.clone(),
            },
            Decision::IdentityVerification {
                rule_id,
                severity,
                reason,
                safer_alternative,
                ..
            } => Self::IdentityVerification {
                rule_id: rule_id.clone(),
                severity: severity.as_str(),
                reason: reason.clone(),
                safer_alternative: safer_alternative.clone(),
            },
        }
    }
}

fn render_json(r: &ExplainReport) -> String {
    let matches = sorted_matches(&r.evaluation.matches);
    let rules_matched = matches
        .into_iter()
        .map(|m| RuleMatchJson {
            rule_id: m.rule_id,
            severity: m.severity.as_str(),
            points: m.points,
            reason: m.reason,
            safer_alternative: m.safer_alternative,
        })
        .collect();
    let report = ExplainJson {
        tool: &r.descriptor.tool,
        arguments: &r.descriptor.arguments,
        rules_matched,
        adjustments_applied: r.evaluation.adjustments_applied.clone(),
        adjustment_signals: AdjustmentSignalsJson {
            workspace_is_prod: r.adjustments.workspace_is_prod,
            burst_in_progress: r.adjustments.burst_in_progress,
            fingerprint_repeatedly_approved: r.adjustments.fingerprint_repeatedly_approved,
            fingerprint_recently_denied: r.adjustments.fingerprint_recently_denied,
            tainted_secret_in_flight: r.adjustments.tainted_secret_in_flight,
        },
        severity_raw: r.evaluation.raw_severity.as_str(),
        severity_composite: r.evaluation.composite_severity.as_str(),
        severity_final: r.evaluation.final_severity.as_str(),
        composite_points: r.evaluation.composite_points,
        decision: DecisionJson::from(&r.decision),
    };
    serde_json::to_string_pretty(&report).expect("ExplainJson must serialise")
}

// ─────────────────────────────────────────────────────────────────────
// helpers shared across formats
// ─────────────────────────────────────────────────────────────────────

/// Order by severity desc, then points desc, then rule_id asc. Stable
/// so the same input always renders the same output (matters for CI
/// snapshot tests and `git diff` of cached `--explain --format json`
/// outputs).
fn sorted_matches(matches: &[MatchInfo]) -> Vec<MatchInfo> {
    let mut out: Vec<MatchInfo> = matches.to_vec();
    out.sort_by(|a, b| {
        sev_rank(b.severity)
            .cmp(&sev_rank(a.severity))
            .then(b.points.cmp(&a.points))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    out
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

/// Build the "human readable" adjustment lines. Order:
///
///  1. Anything the engine itself reported in `adjustments_applied`
///     (these are the names of adjustments that actually changed the
///     final severity).
///  2. Signals that were present but did NOT alter the outcome --
///     useful for "the burst detector was active but didn't matter
///     here because there were no rules to bump".
fn describe_adjustments_text(adj: &Adjustments, applied: &[&'static str]) -> Vec<String> {
    let mut out = Vec::new();
    for name in applied {
        out.push(format!("APPLIED   {}", name));
    }

    let present_but_unused = |label: &str, applied_name: &str, value: bool| -> Option<String> {
        if value && !applied.iter().any(|a| *a == applied_name) {
            Some(format!("present   {} (no rule was eligible)", label))
        } else {
            None
        }
    };

    if let Some(s) = present_but_unused(
        "workspace_is_prod",
        "workspace_is_prod",
        adj.workspace_is_prod,
    ) {
        out.push(s);
    }
    if let Some(s) = present_but_unused(
        "burst_in_progress",
        "burst_in_progress",
        adj.burst_in_progress,
    ) {
        out.push(s);
    }
    if let Some(s) = present_but_unused(
        "fingerprint_recently_denied",
        "fingerprint_recently_denied",
        adj.fingerprint_recently_denied,
    ) {
        out.push(s);
    }
    if let Some(s) = present_but_unused(
        "fingerprint_repeatedly_approved",
        "fingerprint_repeatedly_approved",
        adj.fingerprint_repeatedly_approved,
    ) {
        out.push(s);
    }
    // taint always injects a synthetic finding, so it is effectively
    // always APPLIED when set; kept here for symmetry with the others.
    if let Some(s) = present_but_unused(
        "tainted_secret_in_flight",
        "tainted_secret_in_flight",
        adj.tainted_secret_in_flight,
    ) {
        out.push(s);
    }

    out
}

fn describe_decision(d: &Decision) -> (&'static str, Vec<(&'static str, String)>) {
    match d {
        Decision::Allow => ("ALLOW", vec![]),
        Decision::Warn {
            rule_id,
            severity,
            safer_alternative,
            ..
        } => (
            "WARN",
            vec![
                ("rule_id", rule_id.clone()),
                ("severity", severity.as_str().to_string()),
                ("suggest", safer_alternative.clone().unwrap_or_default()),
            ],
        ),
        Decision::Block {
            rule_id,
            severity,
            reason,
            safer_alternative,
            ..
        } => (
            "BLOCK",
            vec![
                ("rule_id", rule_id.clone()),
                ("severity", severity.as_str().to_string()),
                ("reason", reason.clone()),
                ("suggest", safer_alternative.clone().unwrap_or_default()),
            ],
        ),
        Decision::Approval {
            rule_id,
            severity,
            reason,
            safer_alternative,
            ..
        } => (
            "APPROVAL",
            vec![
                ("rule_id", rule_id.clone()),
                ("severity", severity.as_str().to_string()),
                ("reason", reason.clone()),
                ("suggest", safer_alternative.clone().unwrap_or_default()),
            ],
        ),
        Decision::IdentityVerification {
            rule_id,
            severity,
            reason,
            safer_alternative,
            ..
        } => (
            "IDENTITY-VERIFICATION",
            vec![
                ("rule_id", rule_id.clone()),
                ("severity", severity.as_str().to_string()),
                ("reason", reason.clone()),
                ("suggest", safer_alternative.clone().unwrap_or_default()),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explain::{explain, ExplainOptions, ToolCallDescriptor};
    use crate::Engine;
    use serde_json::json;

    fn run_with(payload: serde_json::Value) -> ExplainReport {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(payload).unwrap();
        explain(&engine, &d, &ExplainOptions::default()).unwrap()
    }

    #[test]
    fn format_parse_accepts_aliases() {
        assert_eq!(ExplainFormat::parse("text").unwrap(), ExplainFormat::Text);
        assert_eq!(ExplainFormat::parse("txt").unwrap(), ExplainFormat::Text);
        assert_eq!(ExplainFormat::parse("md").unwrap(), ExplainFormat::Markdown);
        assert_eq!(
            ExplainFormat::parse("markdown").unwrap(),
            ExplainFormat::Markdown
        );
        assert_eq!(ExplainFormat::parse("json").unwrap(), ExplainFormat::Json);
        assert!(ExplainFormat::parse("yaml").is_err());
    }

    #[test]
    fn text_output_includes_decision_and_rule_for_block() {
        let report = run_with(json!({"name": "shell", "arguments": {"command": "rm -rf /"}}));
        let text = render(&report, ExplainFormat::Text);
        assert!(text.contains("shield --explain"));
        assert!(text.contains("decision"));
        // Either BLOCK or APPROVAL is acceptable for the bundled
        // shieldset depending on tiering; both surface the rule_id.
        assert!(text.contains("fs.recursive_delete_root"), "got: {}", text);
    }

    #[test]
    fn markdown_output_renders_a_table_per_section() {
        let report = run_with(json!({"name": "shell", "arguments": {"command": "rm -rf /"}}));
        let md = render(&report, ExplainFormat::Markdown);
        assert!(md.starts_with("### `aperion-shield --explain`"));
        assert!(md.contains("**Rules matched"));
        assert!(md.contains("**Severities:**"));
    }

    #[test]
    fn json_output_is_a_stable_schema() {
        let report = run_with(json!({"name": "shell", "arguments": {"command": "rm -rf /"}}));
        let s = render(&report, ExplainFormat::Json);
        let v: Value = serde_json::from_str(&s).expect("json output must parse");
        // Stable schema -- assert specific keys exist.
        assert!(v.get("tool").is_some());
        assert!(v.get("rules_matched").is_some());
        assert!(v.get("decision").is_some());
        assert!(v.get("adjustment_signals").is_some());
        assert!(v.get("severity_final").is_some());
        let dec_kind = v["decision"]["kind"].as_str().unwrap_or("");
        assert!(
            matches!(dec_kind, "block" | "approval"),
            "got dec kind: {} full json: {}",
            dec_kind,
            s
        );
    }

    #[test]
    fn allow_decision_has_no_detail_block_in_text() {
        let report = run_with(json!({"name": "shell", "arguments": {"command": "echo hi"}}));
        let text = render(&report, ExplainFormat::Text);
        assert!(text.contains("ALLOW"));
        // No rule_id line since we didn't match anything.
        assert!(!text.contains("rule_id"));
    }

    #[test]
    fn adjustment_signals_present_but_unused_show_up_in_text() {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(
            json!({"name": "shell", "arguments": {"command": "echo hi"}}),
        )
        .unwrap();
        let mut opts = ExplainOptions::default();
        opts.force_burst = Some(true);
        let report = explain(&engine, &d, &opts).unwrap();
        let text = render(&report, ExplainFormat::Text);
        assert!(
            text.contains("burst_in_progress"),
            "burst signal should appear in adjustments section; got:\n{}",
            text
        );
    }

    #[test]
    fn exit_code_mirrors_check_cmd_policy() {
        let allow = ExplainReport {
            descriptor: ToolCallDescriptor::from_json(json!({"name": "x"})).unwrap(),
            adjustments: Adjustments::default(),
            evaluation: Evaluation {
                matches: vec![],
                composite_points: 0,
                raw_severity: Severity::Low,
                composite_severity: Severity::Low,
                final_severity: Severity::Low,
                adjustments_applied: vec![],
            },
            decision: Decision::Allow,
            options: ExplainOptions::default(),
        };
        assert_eq!(allow.exit_code(), 0);
    }
}

//! In-process corpus evaluation.
//!
//! Equivalent to `aperion-shield --check`, but stripped down for the
//! diff use case:
//!
//!   * memory and burst-detector are **disabled** (`--no-memory`,
//!     `--no-burst` equivalents). Both are stateful, so flipping them
//!     on would make the second engine's evaluation depend on the
//!     first engine's history and give us non-reproducible diffs.
//!     The Python prototype does the same thing.
//!   * Workspace context is still computed once and shared between
//!     the two runs (it's a function of `--workspace`, not the rules).
//!   * Output is in-process structs, not serialised JSON, so no
//!     parse round-trip cost on big corpora.
//!
//! Output schema mirrors the JSON emitted by `--check` for the
//! fields the diff explainer actually consumes. If new fields are
//! added to `--check`'s JSON output, mirror them here only if the
//! diff explainer needs them; otherwise we accumulate stale fields
//! that confuse readers.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_json::{json, Value};

use crate::engine::{decide, Adjustments, Decision, Engine};
use crate::WorkspaceContext;

/// Options that apply equally to both engine runs (before / after).
#[derive(Debug, Clone, Default)]
pub struct EvalOptions {
    /// Override the workspace root for the prod-probe. Same semantics
    /// as `--check --workspace PATH`.
    pub workspace: Option<PathBuf>,
}

/// One evaluation result, mirroring the JSON shape `--check` writes
/// per line. Names are kept stable with the Python prototype's
/// `DecisionLine` so the JSON output schema stays source-compatible.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionLine {
    pub decision: String,
    pub primary_rule_id: Option<String>,
    pub matched_rules: Vec<String>,
    pub raw_severity: String,
    pub composite_severity: String,
    pub composite_points: u32,
    pub reason: String,
    pub input: Value,
}

/// Run the engine at `rules_path` over the JSON-Lines corpus,
/// returning one [`DecisionLine`] per non-blank, non-comment input
/// line in order. Invalid JSON lines map to an "allow" decision with
/// a sentinel `reason` so the index pairing in the diff stays
/// aligned with the corpus.
pub fn evaluate_corpus(
    rules_path: &Path,
    corpus: &str,
    opts: &EvalOptions,
) -> anyhow::Result<Vec<DecisionLine>> {
    let raw = std::fs::read_to_string(rules_path).with_context(|| {
        format!(
            "reading shieldset for evaluation from {}",
            rules_path.display()
        )
    })?;
    let engine = Engine::from_yaml(&raw)
        .with_context(|| format!("loading shieldset from {}", rules_path.display()))?;

    // Workspace probe is shared across runs. Adaptive memory and
    // burst detector are intentionally disabled for diff -- see the
    // module-level docs for why.
    let workspace = {
        let mut policy = engine.policy.clone();
        // Workspace probe stays enabled regardless of the engine's
        // policy block: the diff explainer evaluates a *static*
        // corpus, so we keep all signals that depend on inputs
        // visible. The probe itself is deterministic for a given
        // --workspace path.
        policy.workspace_probe.enabled = true;
        match &opts.workspace {
            Some(p) => WorkspaceContext::probe_at(&policy, p),
            None => WorkspaceContext::probe(&policy),
        }
    };

    let mut out = Vec::new();
    for raw_line in corpus.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let input: Value = match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => v,
            Err(_) => {
                out.push(DecisionLine {
                    decision: "allow".into(),
                    primary_rule_id: None,
                    matched_rules: Vec::new(),
                    raw_severity: "allow".into(),
                    composite_severity: "allow".into(),
                    composite_points: 0,
                    reason: "invalid JSON in corpus line".into(),
                    input: json!({"_raw": trimmed}),
                });
                continue;
            }
        };

        let adj = Adjustments {
            workspace_is_prod: workspace.is_prod,
            ..Default::default()
        };

        // Two input shapes: text (llm_response scope) or tool-call.
        // Identical to run_check_mode in src/main.rs.
        let eval = if let Some(text) = input.get("text").and_then(|v| v.as_str()) {
            engine.evaluate_text(text, adj)
        } else {
            let tool = input.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let params = input.get("params").cloned().unwrap_or(Value::Null);
            let canonical = if params.get("name").is_some() || params.get("arguments").is_some() {
                params.clone()
            } else {
                json!({ "name": tool, "arguments": params })
            };
            engine.evaluate(tool, &canonical, adj)
        };

        let decision = decide(&eval);
        let label = decision.label().to_string();
        let (primary_rule_id, reason) = match &decision {
            Decision::Block {
                rule_id, reason, ..
            }
            | Decision::Approval {
                rule_id, reason, ..
            }
            | Decision::IdentityVerification {
                rule_id, reason, ..
            } => (Some(rule_id.clone()), reason.clone()),
            Decision::Warn {
                rule_id, banner, ..
            } => (Some(rule_id.clone()), banner.clone()),
            Decision::Allow => (None, String::new()),
        };

        out.push(DecisionLine {
            decision: label,
            primary_rule_id,
            matched_rules: eval.matches.iter().map(|m| m.rule_id.clone()).collect(),
            raw_severity: eval.raw_severity.as_str().into(),
            composite_severity: eval.composite_severity.as_str().into(),
            composite_points: eval.composite_points,
            reason,
            input,
        });
    }
    Ok(out)
}

/// Validate the rules path early so we can fail with a clearer error
/// than "reading shieldset failed". Used by `run_diff_mode` when both
/// paths are checked up-front.
#[allow(dead_code)]
pub fn ensure_rules_exists(p: &Path) -> anyhow::Result<()> {
    if !p.is_file() {
        return Err(anyhow!(
            "shieldset not found at {} -- check the --rules-before / --rules-after paths",
            p.display()
        ));
    }
    Ok(())
}

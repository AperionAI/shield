//! `aperion-shield --explain` -- turn any tool-call descriptor into
//! a readable walkthrough of what the engine would decide, and why.
//!
//! ## Why this exists
//!
//! Shield's adaptive scoring (raw severity, composite points,
//! workspace probe, decision memory, burst detector) is a strength of
//! the product and a major source of operator confusion. When a call
//! gets gated, the user wants three things:
//!
//!  1. Which rule(s) tripped?
//!  2. What signals were applied on top? (And in what direction?)
//!  3. What's the safer alternative they should use instead?
//!
//! `--explain` answers all three in one shot, from a JSON descriptor
//! the user can copy out of a CI log, a Cursor exchange, or the
//! `--shadow` audit stream.
//!
//! ## CLI shape
//!
//! ```text
//! aperion-shield --explain --input call.json            # read from file
//! cat call.json | aperion-shield --explain --input -    # read from stdin
//! aperion-shield --explain --input - <<EOF              # heredoc-friendly
//! {"name": "shell", "arguments": {"command": "rm -rf /"}}
//! EOF
//! ```
//!
//! Output is text by default; `--explain-format markdown` gives a
//! GitHub-flavoured markdown block that drops cleanly into a PR
//! review comment; `--explain-format json` gives a stable schema
//! suitable for piping into other tooling.
//!
//! ## Output structure (text/markdown)
//!
//! ```text
//!   shield --explain
//!   ────────────────
//!   tool   : shell
//!   call   : {"command": "rm -rf /"}
//!
//!   rules matched ............................. 1
//!     fs.recursive_delete_root   Critical  pts=8
//!
//!   adjustments applied ....................... 0
//!     (none)
//!
//!   severities
//!     raw       : Critical
//!     composite : Critical
//!     final     : Critical
//!
//!   decision .................................. BLOCK
//!     rule_id  : fs.recursive_delete_root
//!     reason   : rm -rf on filesystem root is forbidden.
//!     suggest  : Scope to a specific subdirectory, e.g. `rm -rf ./build/`.
//! ```
//!
//! The JSON output is a stable, machine-readable schema --
//! intentionally NOT just the engine's internal `Evaluation` struct.
//! See `render::ExplainJson` for the schema.

pub mod render;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::path::PathBuf;

use crate::engine::Engine;
use crate::{decide, Adjustments, BurstDetector, WorkspaceContext};

/// Options that shape an explain run beyond just the input descriptor.
/// Defaults mirror the engine's behaviour on a vanilla `tools/call`
/// in a non-prod workspace with no burst and no recent denies.
#[derive(Debug, Clone, Default)]
pub struct ExplainOptions {
    /// If Some, probe this directory for prod-ness instead of relying
    /// on the workspace defaults baked into the policy.
    pub workspace_root: Option<PathBuf>,
    /// Override workspace prod inference (useful for "what if this
    /// was a prod call?" scenarios). Wins over the probe.
    pub force_workspace_prod: Option<bool>,
    /// Pretend the burst detector says we're in a burst. Useful for
    /// reproducing decisions captured during a high-traffic window.
    pub force_burst: Option<bool>,
    /// Pretend the same fingerprint has been repeatedly approved.
    /// Drives the decision-memory demotion path.
    pub force_repeatedly_approved: bool,
    /// Pretend the same fingerprint had a recent deny. Drives the
    /// decision-memory escalation path.
    pub force_recently_denied: bool,
    /// Pretend a credential-shaped value in these arguments was already
    /// seen leaving another tool/surface. Drives the v1.3 cross-tool
    /// taint escalation path (Approval floor).
    pub force_tainted: bool,
}

/// Parsed shape of the input descriptor. We only require `name` and
/// `arguments` -- additional fields are ignored. This matches both
/// the MCP `tools/call` payload and the canonical JSON the shims
/// produce for `shell` calls.
#[derive(Debug, Clone)]
pub struct ToolCallDescriptor {
    pub tool: String,
    pub arguments: Value,
    /// Pretty-printed `arguments` for the banner. Cached because we
    /// render in multiple places.
    pub arguments_pretty: String,
}

impl ToolCallDescriptor {
    /// Parse the descriptor from a JSON value. Accepts either of:
    ///
    ///  * `{"name": "shell", "arguments": {"command": "..."}}`  (MCP)
    ///  * `{"tool": "shell", "params": {"command": "..."}}`     (legacy)
    pub fn from_json(v: Value) -> Result<Self> {
        let tool = v
            .get("name")
            .or_else(|| v.get("tool"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                anyhow!("input descriptor must have a `name` (or `tool`) string field")
            })?
            .to_string();
        let arguments = v
            .get("arguments")
            .or_else(|| v.get("params"))
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let arguments_pretty = serde_json::to_string_pretty(&arguments)
            .unwrap_or_else(|_| "{}".to_string());
        Ok(Self {
            tool,
            arguments,
            arguments_pretty,
        })
    }
}

/// Run an engine evaluation explicitly preserving the trace, without
/// invoking any of the side-effects the real proxy path has
/// (decision-memory writes, audit-sink fan-out, identity gate checks).
pub fn explain(
    engine: &Engine,
    descriptor: &ToolCallDescriptor,
    opts: &ExplainOptions,
) -> Result<render::ExplainReport> {
    // Build the canonical MCP-style call: `{"name":..., "arguments":...}`.
    // The engine's matcher inspects the raw params, not the wrapped form.
    let canonical = serde_json::json!({
        "name": descriptor.tool,
        "arguments": descriptor.arguments,
    });

    let adj = build_adjustments(engine, opts)?;

    let eval = engine.evaluate(&descriptor.tool, &canonical, adj.clone());
    let decision = decide(&eval);

    Ok(render::ExplainReport {
        descriptor: descriptor.clone(),
        adjustments: adj,
        evaluation: eval,
        decision,
        options: opts.clone(),
    })
}

fn build_adjustments(engine: &Engine, opts: &ExplainOptions) -> Result<Adjustments> {
    let workspace_is_prod = match opts.force_workspace_prod {
        Some(b) => b,
        None => {
            let probe_root = opts
                .workspace_root
                .clone()
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            WorkspaceContext::probe_at(&engine.policy, &probe_root).is_prod
        }
    };

    let burst_in_progress = match opts.force_burst {
        Some(b) => b,
        None => {
            // Fresh BurstDetector with no events is never in a burst,
            // so the only way to surface burst-driven behaviour in
            // --explain is via the force flag. That's intentional --
            // we don't want explain to mutate the user's real burst
            // state.
            BurstDetector::new(engine.policy.burst_detector.clone()).in_burst()
        }
    };

    Ok(Adjustments {
        workspace_is_prod,
        burst_in_progress,
        fingerprint_repeatedly_approved: opts.force_repeatedly_approved,
        fingerprint_recently_denied: opts.force_recently_denied,
        tainted_secret_in_flight: opts.force_tainted,
    })
}

/// Helper for the CLI: read the JSON descriptor from the path given
/// to `--input`. Path `-` reads from stdin.
pub fn read_descriptor_from(path: &str) -> Result<ToolCallDescriptor> {
    let raw = if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("couldn't read stdin")?;
        buf
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("couldn't read --input {}", path))?
    };
    let v: Value = serde_json::from_str(&raw)
        .with_context(|| format!("couldn't parse --input {} as JSON", path))?;
    ToolCallDescriptor::from_json(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn descriptor_parses_mcp_style_shape() {
        let v = json!({"name": "shell", "arguments": {"command": "ls"}});
        let d = ToolCallDescriptor::from_json(v).unwrap();
        assert_eq!(d.tool, "shell");
        assert_eq!(d.arguments, json!({"command": "ls"}));
    }

    #[test]
    fn descriptor_parses_legacy_tool_params_shape() {
        let v = json!({"tool": "execute_sql", "params": {"query": "SELECT 1"}});
        let d = ToolCallDescriptor::from_json(v).unwrap();
        assert_eq!(d.tool, "execute_sql");
        assert_eq!(d.arguments, json!({"query": "SELECT 1"}));
    }

    #[test]
    fn descriptor_rejects_missing_tool_name() {
        let v = json!({"arguments": {"command": "ls"}});
        assert!(ToolCallDescriptor::from_json(v).is_err());
    }

    #[test]
    fn descriptor_tolerates_missing_arguments() {
        let v = json!({"name": "ping"});
        let d = ToolCallDescriptor::from_json(v).unwrap();
        assert_eq!(d.arguments, json!({}));
    }

    #[test]
    fn explain_on_clean_call_yields_allow_with_no_matches() {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(
            json!({"name": "shell", "arguments": {"command": "echo hi"}}),
        )
        .unwrap();
        let report = explain(&engine, &d, &ExplainOptions::default()).unwrap();
        assert!(report.evaluation.matches.is_empty());
        assert!(matches!(report.decision, crate::Decision::Allow));
    }

    #[test]
    fn explain_on_rm_rf_root_yields_block() {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(
            json!({"name": "shell", "arguments": {"command": "rm -rf /"}}),
        )
        .unwrap();
        let report = explain(&engine, &d, &ExplainOptions::default()).unwrap();
        assert!(!report.evaluation.matches.is_empty());
        assert!(matches!(
            report.decision,
            crate::Decision::Block { .. } | crate::Decision::Approval { .. }
        ));
    }

    #[test]
    fn force_workspace_prod_overrides_probe() {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(
            json!({"name": "shell", "arguments": {"command": "ls"}}),
        )
        .unwrap();
        let mut opts = ExplainOptions::default();
        opts.force_workspace_prod = Some(true);
        let report = explain(&engine, &d, &opts).unwrap();
        assert!(report.adjustments.workspace_is_prod);
    }

    #[test]
    fn force_burst_is_honoured() {
        let engine = Engine::builtin_default();
        let d = ToolCallDescriptor::from_json(
            json!({"name": "shell", "arguments": {"command": "ls"}}),
        )
        .unwrap();
        let mut opts = ExplainOptions::default();
        opts.force_burst = Some(true);
        let report = explain(&engine, &d, &opts).unwrap();
        assert!(report.adjustments.burst_in_progress);
    }
}

//! Native agent-hook adapter (v1.5).
//!
//! Claude Code `PreToolUse` and Cursor `preToolUse` send a JSON event on
//! stdin describing the tool about to run (Bash, Write, Read, MCP, …).
//! This module maps that event onto the same engine path `--check-cmd`
//! and the MCP middleman already use, then emits the dialect-specific
//! deny JSON the host expects.
//!
//! Exit-code policy (mirrors `--check-cmd`, with a Claude overlay):
//!
//! | Decision                         | Claude stdout                         | Claude exit | Cursor stdout              | Cursor exit |
//! |----------------------------------|---------------------------------------|-------------|----------------------------|-------------|
//! | Allow / Warn                     | (empty)                               | 0           | `{"permission":"allow"}`   | 0           |
//! | Block / Approval / Identity      | `hookSpecificOutput.permissionDecision: deny` | 2 | `{"permission":"deny"}`    | 2           |
//!
//! APort documents the two JSON shapes as incompatible — we never share
//! one wrapper script between Claude and Cursor.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::engine::{decide, Adjustments, Decision, Engine};
use crate::taint::TaintLedger;
use crate::{BurstDetector, WorkspaceContext};

/// Which host JSON dialect to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDialect {
    Claude,
    Cursor,
}

impl HookDialect {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" | "anthropic" => Ok(Self::Claude),
            "cursor" => Ok(Self::Cursor),
            "auto" => Err(anyhow!("auto is resolved by detect_dialect(), not parse()")),
            other => {
                anyhow::bail!("unknown --hook-dialect '{other}' (expected claude | cursor | auto)")
            }
        }
    }
}

/// Loose stdin payload. Field names differ across Claude Code, Cursor,
/// and experimental Codex/Gemini ports — we accept the aliases that
/// show up in the wild rather than requiring one schema.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HookEvent {
    #[serde(default, alias = "hookEventName", alias = "hook_event_name")]
    pub hook_event_name: Option<String>,
    #[serde(default, alias = "toolName", alias = "tool")]
    pub tool_name: Option<String>,
    #[serde(
        default,
        alias = "toolInput",
        alias = "tool_input",
        alias = "arguments",
        alias = "args"
    )]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub cwd: Option<String>,
}

impl HookEvent {
    pub fn from_json(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("--check-hook requires a JSON event on stdin");
        }
        serde_json::from_str(trimmed).map_err(|e| anyhow!("--check-hook stdin is not JSON: {e}"))
    }

    pub fn tool_name(&self) -> &str {
        self.tool_name.as_deref().unwrap_or("")
    }

    pub fn input(&self) -> &Value {
        self.tool_input.as_ref().unwrap_or(&Value::Null)
    }
}

/// Pick a dialect from the payload when the operator passed `auto`.
pub fn detect_dialect(event: &HookEvent) -> HookDialect {
    let name = event
        .hook_event_name
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "pretooluse" || name == "posttooluse" {
        // Claude Code uses PascalCase PreToolUse; Cursor uses preToolUse.
        // After lowercasing they collide, so look at the original casing
        // if we still have it: Claude's documented field is PreToolUse.
        if event
            .hook_event_name
            .as_deref()
            .map(|s| s.starts_with("Pre") || s.starts_with("Post"))
            .unwrap_or(false)
        {
            return HookDialect::Claude;
        }
        return HookDialect::Cursor;
    }
    if name.is_empty() {
        // Cursor's early hooks.json payloads often omit hook_event_name.
        return HookDialect::Cursor;
    }
    HookDialect::Claude
}

/// Result the CLI uses to print JSON + pick an exit code.
#[derive(Debug, Clone)]
pub struct HookReport {
    pub dialect: HookDialect,
    pub tool_name: String,
    pub canonical_tool: String,
    pub decision: Decision,
    pub primary_rule_id: Option<String>,
    pub reason: String,
    pub stdout: String,
}

impl HookReport {
    pub fn exit_code(&self) -> i32 {
        if self.decision.is_blocking() {
            2
        } else {
            0
        }
    }
}

/// Map a host tool name + input onto an engine `(tool, params)` pair.
///
/// Native IDE tools (Bash/Write/Read) are not in the shieldset
/// whitelist as `Bash` — the YAML uses `shell` / `fs.write` / `fs.read`.
/// MCP tools arrive as `mcp__server__tool`; we strip to the last
/// segment and, when the args look like SQL, also evaluate as
/// `execute_sql` (handled by the caller via [`canonical_calls`]).
pub fn canonical_calls(tool_name: &str, input: &Value) -> Vec<(String, Value)> {
    let lower = tool_name.to_ascii_lowercase();
    let mut out = Vec::new();

    if is_shell_tool(&lower) {
        let cmd = extract_command(input);
        out.push((
            "shell".to_string(),
            json!({"name": "shell", "arguments": {"command": cmd}}),
        ));
        return out;
    }

    if is_write_tool(&lower) {
        let path = extract_path(input);
        // `tee <path>` is a write verb, so `fs.sensitive_path_write_or_delete`
        // (which gates on command_writes) fires for ~/.ssh, .env, etc.
        let synthetic = format!("tee {path}");
        out.push((
            "shell".to_string(),
            json!({"name": "shell", "arguments": {"command": synthetic, "path": path}}),
        ));
        out.push((
            "fs.write".to_string(),
            json!({"name": "fs.write", "arguments": {"path": path}}),
        ));
        return out;
    }

    if is_read_tool(&lower) {
        let path = extract_path(input);
        out.push((
            "fs.read".to_string(),
            json!({"name": "fs.read", "arguments": {"path": path}}),
        ));
        out.push((
            "filesystem.read_file".to_string(),
            json!({"name": "filesystem.read_file", "arguments": {"path": path}}),
        ));
        return out;
    }

    if let Some(rest) = strip_mcp_prefix(tool_name) {
        let last = rest.rsplit("__").next().unwrap_or(rest);
        let dotted = rest.replace("__", ".");
        if looks_like_sql(last, input) {
            out.push((
                "execute_sql".to_string(),
                json!({"name": "execute_sql", "arguments": input}),
            ));
        }
        out.push((last.to_string(), json!({"name": last, "arguments": input})));
        if dotted != last {
            out.push((dotted.clone(), json!({"name": dotted, "arguments": input})));
        }
        return out;
    }

    out.push((
        tool_name.to_string(),
        json!({"name": tool_name, "arguments": input}),
    ));
    out
}

fn is_shell_tool(lower: &str) -> bool {
    matches!(
        lower,
        "bash"
            | "shell"
            | "zsh"
            | "sh"
            | "powershell"
            | "pwsh"
            | "cmd"
            | "terminal"
            | "run_terminal"
            | "execute_command"
            | "exec"
            | "runcommand"
            | "run_command"
    )
}

fn is_write_tool(lower: &str) -> bool {
    matches!(
        lower,
        "write"
            | "edit"
            | "multiedit"
            | "notebookedit"
            | "strreplace"
            | "str_replace"
            | "create"
            | "delete"
            | "fs.write"
            | "filesystem.write_file"
    )
}

fn is_read_tool(lower: &str) -> bool {
    matches!(
        lower,
        "read" | "readfile" | "read_file" | "fs.read" | "filesystem.read_file"
    )
}

fn strip_mcp_prefix(name: &str) -> Option<&str> {
    name.strip_prefix("mcp__")
        .or_else(|| name.strip_prefix("mcp_"))
}

fn looks_like_sql(tool: &str, input: &Value) -> bool {
    let t = tool.to_ascii_lowercase();
    if t.contains("sql") || t.contains("query") || t.contains("postgres") || t.contains("mysql") {
        return true;
    }
    input.get("query").is_some() || input.get("sql").is_some() || input.get("statement").is_some()
}

fn extract_command(input: &Value) -> String {
    for key in ["command", "cmd", "script", "code", "input"] {
        if let Some(s) = input.get(key).and_then(|v| v.as_str()) {
            return s.to_string();
        }
    }
    if let Some(s) = input.as_str() {
        return s.to_string();
    }
    input.to_string()
}

fn extract_path(input: &Value) -> String {
    for key in [
        "path",
        "file_path",
        "filePath",
        "filename",
        "file",
        "target",
    ] {
        if let Some(s) = input.get(key).and_then(|v| v.as_str()) {
            return s.to_string();
        }
    }
    // MultiEdit: first edit's path, or a `edits[0].old_string` file.
    if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
        if let Some(first) = edits.first() {
            if let Some(s) = first.get("path").and_then(|v| v.as_str()) {
                return s.to_string();
            }
        }
    }
    String::new()
}

fn decision_reason(d: &Decision) -> String {
    match d {
        Decision::Allow => String::new(),
        Decision::Warn { banner, .. } => banner.clone(),
        Decision::Approval { reason, .. }
        | Decision::IdentityVerification { reason, .. }
        | Decision::Block { reason, .. } => reason.clone(),
    }
}

fn decision_rule_id(d: &Decision) -> Option<String> {
    match d {
        Decision::Allow => None,
        Decision::Warn { rule_id, .. }
        | Decision::Approval { rule_id, .. }
        | Decision::IdentityVerification { rule_id, .. }
        | Decision::Block { rule_id, .. } => Some(rule_id.clone()),
    }
}

fn render_stdout(
    dialect: HookDialect,
    decision: &Decision,
    reason: &str,
    rule_id: Option<&str>,
) -> String {
    if !decision.is_blocking() {
        return match dialect {
            HookDialect::Claude => String::new(),
            HookDialect::Cursor => json!({"permission": "allow"}).to_string() + "\n",
        };
    }
    let reason_full = match rule_id {
        Some(id) if !reason.is_empty() => format!("[{id}] {reason}"),
        Some(id) => format!("blocked by {id}"),
        None => {
            if reason.is_empty() {
                "blocked by aperion-shield".to_string()
            } else {
                reason.to_string()
            }
        }
    };
    match dialect {
        HookDialect::Claude => {
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason_full,
                }
            })
            .to_string()
                + "\n"
        }
        HookDialect::Cursor => {
            json!({
                "permission": "deny",
                "permissionDecisionReason": reason_full,
            })
            .to_string()
                + "\n"
        }
    }
}

/// Evaluate a parsed hook event against the engine.
pub fn run(
    engine: &Engine,
    event: &HookEvent,
    dialect: HookDialect,
    taint: Option<&TaintLedger>,
) -> Result<HookReport> {
    let tool_name = event.tool_name().to_string();
    if tool_name.is_empty() {
        anyhow::bail!("--check-hook JSON is missing tool_name");
    }

    let cwd = event
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        });
    let workspace = WorkspaceContext::probe_at(&engine.policy, &cwd);
    let burst = BurstDetector::new(engine.policy.burst_detector.clone());

    let calls = canonical_calls(&tool_name, event.input());
    let mut best = Decision::Allow;
    let mut canonical_tool = calls
        .first()
        .map(|(t, _)| t.clone())
        .unwrap_or_else(|| tool_name.clone());

    for (tool, params) in &calls {
        let blob = params.to_string();
        let taint_hit = taint.and_then(|t| t.check(&blob));
        let adj = Adjustments {
            workspace_is_prod: workspace.is_prod,
            burst_in_progress: burst.in_burst(),
            tainted_secret_in_flight: taint_hit.is_some(),
            ..Default::default()
        };
        let eval = engine.evaluate(tool, params, adj);
        let decision = decide(&eval);
        if rank_decision(&decision) > rank_decision(&best) {
            canonical_tool = tool.clone();
            best = decision;
        }
    }

    let reason = decision_reason(&best);
    let primary_rule_id = decision_rule_id(&best);
    let stdout = render_stdout(dialect, &best, &reason, primary_rule_id.as_deref());

    Ok(HookReport {
        dialect,
        tool_name,
        canonical_tool,
        decision: best,
        primary_rule_id,
        reason,
        stdout,
    })
}

fn rank_decision(d: &Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Warn { .. } => 1,
        Decision::Approval { .. } => 2,
        Decision::IdentityVerification { .. } => 3,
        Decision::Block { .. } => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;

    fn engine() -> Engine {
        Engine::builtin_default()
    }

    fn eval_named(tool: &str, input: Value, dialect: HookDialect) -> HookReport {
        let event = HookEvent {
            tool_name: Some(tool.into()),
            tool_input: Some(input),
            ..Default::default()
        };
        run(&engine(), &event, dialect, None).expect("run")
    }

    #[test]
    fn bash_rm_rf_root_blocks_claude() {
        let report = eval_named("Bash", json!({"command": "rm -rf /"}), HookDialect::Claude);
        assert!(
            report.decision.is_blocking(),
            "decision={:?}",
            report.decision
        );
        assert_eq!(report.exit_code(), 2);
        assert!(report.stdout.contains("permissionDecision"));
        assert!(report.stdout.contains("deny"));
        assert!(!report.stdout.contains("\"permission\":"));
    }

    #[test]
    fn bash_ls_allows() {
        let report = eval_named(
            "Bash",
            json!({"command": "ls -la src"}),
            HookDialect::Claude,
        );
        assert!(
            !report.decision.is_blocking(),
            "decision={:?}",
            report.decision
        );
        assert_eq!(report.exit_code(), 0);
        assert!(report.stdout.is_empty());
    }

    #[test]
    fn write_ssh_key_blocks() {
        let report = eval_named(
            "Write",
            json!({"path": "~/.ssh/id_rsa", "contents": "-----BEGIN"}),
            HookDialect::Cursor,
        );
        assert!(
            report.decision.is_blocking(),
            "decision={:?}",
            report.decision
        );
        assert!(
            report.stdout.contains("\"permission\":\"deny\"")
                || report.stdout.contains("\"permission\": \"deny\"")
        );
        assert!(!report.stdout.contains("hookSpecificOutput"));
    }

    #[test]
    fn write_env_blocks() {
        let report = eval_named(
            "Write",
            json!({"path": "/tmp/proj/.env", "contents": "AWS_SECRET=x"}),
            HookDialect::Claude,
        );
        assert!(
            report.decision.is_blocking(),
            "decision={:?} reason={}",
            report.decision,
            report.reason
        );
    }

    #[test]
    fn read_aws_credentials_escalates() {
        let report = eval_named(
            "Read",
            json!({"path": "~/.aws/credentials"}),
            HookDialect::Claude,
        );
        assert!(
            report.decision.is_blocking(),
            "decision={:?} reason={}",
            report.decision,
            report.reason
        );
    }

    #[test]
    fn mcp_postgres_drop_blocks() {
        let report = eval_named(
            "mcp__postgres__query",
            json!({"query": "DROP DATABASE prod"}),
            HookDialect::Claude,
        );
        assert!(
            report.decision.is_blocking(),
            "decision={:?} canonical={}",
            report.decision,
            report.canonical_tool
        );
    }

    #[test]
    fn detect_dialect_prefers_claude_pascal_case() {
        let event = HookEvent {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: Some("Bash".into()),
            ..Default::default()
        };
        assert_eq!(detect_dialect(&event), HookDialect::Claude);
    }

    #[test]
    fn detect_dialect_cursor_when_event_name_missing() {
        let event = HookEvent {
            tool_name: Some("Shell".into()),
            ..Default::default()
        };
        assert_eq!(detect_dialect(&event), HookDialect::Cursor);
    }

    #[test]
    fn parse_event_accepts_aliases() {
        let raw =
            r#"{"toolName":"Bash","toolInput":{"command":"pwd"},"hookEventName":"preToolUse"}"#;
        let event = HookEvent::from_json(raw).unwrap();
        assert_eq!(event.tool_name(), "Bash");
        assert_eq!(event.input()["command"], "pwd");
    }
}

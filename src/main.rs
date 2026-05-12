//! aperion-shield — local MCP guardrail for AI coding agents.
//!
//! Architecture
//! ------------
//!
//! ```text
//! Cursor / Claude Code
//!         │  JSON-RPC over stdio
//!         ▼
//!   aperion-shield      ◄── shield.yaml ruleset
//!         │  intercepts tools/call, evaluates rules
//!         │  Allow / Warn / Approval / Block
//!         ▼
//!   real upstream MCP server (postgres / github / shell …)
//! ```
//!
//! The shield process is a transparent MCP middleman. It speaks MCP on
//! stdin/stdout (so the IDE talks to it like any other MCP server) and
//! forwards every request to the real upstream MCP server (configured
//! at launch). Before forwarding, every `tools/call` is evaluated by
//! the embedded Shield engine. Critical-severity matches are blocked
//! with a structured JSON-RPC error. High-severity matches prompt the
//! human via stderr and wait on stdin-of-an-out-of-band approval file
//! for an OK/NO answer.
//!
//! Free vs paid
//! ------------
//!
//! This binary is the FREE tier. It does not phone home, does not have a
//! shared approval queue, and does not produce a tamper-evident audit
//! chain — those are enterprise-only and live in the Smartflow gateway.
//! Local audit log is JSON Lines to stderr.

mod engine;

use anyhow::{anyhow, Context};
use clap::Parser;
use log::{debug, error, info, warn};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::time::timeout;

use engine::{Decision, Engine};

/// Aperion Shield — local MCP guardrail.
///
/// Wraps an upstream MCP server (specified after `--`) and inspects every
/// `tools/call` for destructive patterns before letting it through.
#[derive(Debug, Parser)]
#[command(name = "aperion-shield", version, about, long_about = None)]
struct Cli {
    /// Path to a YAML shieldset. If omitted, the bundled defaults are used.
    #[arg(long, value_name = "PATH")]
    rules: Option<PathBuf>,

    /// Run in shadow mode: never block; just warn + log. Mirrors the
    /// enterprise `SHIELD_MODE=shadow` behaviour. Default: enforce.
    #[arg(long)]
    shadow: bool,

    /// Auto-deny High-severity (Approval) instead of prompting on stderr.
    /// Useful for CI / unattended scripts. Without this flag, Approval
    /// decisions wait for a human approver to write `approve` or `deny`
    /// to a `.aperion-shield/inbox` file in the working directory.
    #[arg(long)]
    auto_deny_high: bool,

    /// Opt-in to anonymised public telemetry (the "block ticker"). This
    /// feature is **not yet enabled** — it is under legal / DPO review.
    /// Specifying it today prints the review notice and exits. See
    /// docs/shield-public/public-ticker-design.md for the full design.
    #[arg(long, value_name = "MODE", value_parser = ["public", "off"])]
    telemetry: Option<String>,

    /// Trailing args after `--` are the upstream MCP server command.
    /// Example: `aperion-shield -- npx @modelcontextprotocol/server-postgres ...`
    #[arg(trailing_var_arg = true, num_args = 0..)]
    upstream: Vec<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // Initialise logging on stderr — stdout is reserved for MCP frames.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    let cli = Cli::parse();

    // Telemetry gate — see docs/shield-public/public-ticker-design.md.
    // The flag exists so future versions can wire telemetry in cleanly,
    // but we refuse to silently turn anything on. Even passing `off` we
    // exit so the user has unambiguous evidence the feature is not yet
    // available.
    if let Some(mode) = cli.telemetry.as_deref() {
        eprintln!("[shield] --telemetry {} requested.", mode);
        eprintln!("[shield]");
        eprintln!("[shield] Telemetry is not yet available. The public block ticker is");
        eprintln!("[shield] currently under privacy / DPO review. See:");
        eprintln!("[shield]");
        eprintln!("[shield]   https://shield.aperion.ai/ticker/privacy");
        eprintln!("[shield]");
        eprintln!("[shield] Re-run without --telemetry to start Shield.");
        std::process::exit(2);
    }

    if cli.upstream.is_empty() {
        return Err(anyhow!(
            "no upstream MCP server command given. Usage: aperion-shield [--rules PATH] [--shadow] -- <upstream-mcp> [args...]"
        ));
    }

    let engine = load_engine(cli.rules.as_deref())?;
    let mode_label = if cli.shadow { "SHADOW (warn only)" } else { "ENFORCE" };
    warn!(
        "[shield] === aperion-shield starting === mode={} rules={} upstream='{} {}'",
        mode_label,
        engine.rules.len(),
        cli.upstream[0],
        cli.upstream[1..].join(" ")
    );

    let (mut child, mut child_in, child_out) = spawn_upstream(&cli.upstream)?;

    // Two unidirectional pumps: client→child and child→client.
    let engine = Arc::new(engine);
    let shadow = cli.shadow;
    let auto_deny = cli.auto_deny_high;

    let stdin = tokio::io::stdin();
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // Pump 1: client stdin → child stdin, with rule evaluation.
    let stdout_clone = stdout.clone();
    let engine_clone = engine.clone();
    let to_child_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => { debug!("[shield] client EOF"); break; }
                Ok(_) => {}
                Err(e) => { error!("[shield] client read error: {}", e); break; }
            }
            let frame = line.trim_end();
            if frame.is_empty() { continue; }
            debug!("[shield] client → {}", frame);

            // Try to parse as JSON-RPC; if it isn't, pass through verbatim.
            let parsed: Option<Value> = serde_json::from_str(frame).ok();
            if let Some(req) = parsed.as_ref() {
                if let Some(decision_resp) = evaluate_request(req, &engine_clone, shadow, auto_deny).await {
                    // Rule fired — return the decision directly to the
                    // client and DO NOT forward to the child.
                    let mut out = stdout_clone.lock().await;
                    let _ = out.write_all(decision_resp.to_string().as_bytes()).await;
                    let _ = out.write_all(b"\n").await;
                    let _ = out.flush().await;
                    continue;
                }
            }

            // Forward unchanged.
            if let Err(e) = child_in.write_all(line.as_bytes()).await {
                error!("[shield] child stdin write error: {}", e);
                break;
            }
            let _ = child_in.flush().await;
        }
        let _ = child_in.shutdown().await;
    });

    // Pump 2: child stdout → client stdout (no inspection on this path
    // for the standalone — the LLM-response seam is a Smartflow-only
    // feature).
    let stdout_clone2 = stdout.clone();
    let from_child_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(child_out);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => { debug!("[shield] child EOF"); break; }
                Ok(_) => {}
                Err(e) => { error!("[shield] child read error: {}", e); break; }
            }
            debug!("[shield] child → {}", line.trim_end());
            let mut out = stdout_clone2.lock().await;
            if out.write_all(line.as_bytes()).await.is_err() { break; }
            let _ = out.flush().await;
        }
    });

    // Wait for either pump to finish, then tear the other down.
    let _ = to_child_handle.await;
    let _ = from_child_handle.await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    info!("[shield] shutdown complete");
    Ok(())
}

fn load_engine(path: Option<&std::path::Path>) -> anyhow::Result<Engine> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("reading shieldset from {}", p.display()))?;
            Engine::from_yaml(&raw)
        }
        None => Ok(Engine::builtin_default()),
    }
}

fn spawn_upstream(cmd: &[String]) -> anyhow::Result<(Child, ChildStdin, ChildStdout)> {
    let (program, args) = cmd.split_first().expect("non-empty by caller");
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn upstream '{}'", program))?;
    let stdin = child.stdin.take().ok_or_else(|| anyhow!("missing child stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("missing child stdout"))?;
    Ok((child, stdin, stdout))
}

/// Evaluate a JSON-RPC request. Returns `Some(response)` if Shield is
/// returning the response directly (Block, Approval-denied, or
/// Approval-pending). Returns `None` to let the request pass to the
/// upstream MCP server.
async fn evaluate_request(req: &Value, engine: &Engine, shadow: bool, auto_deny: bool) -> Option<Value> {
    let method = req.get("method")?.as_str()?;
    let id = req.get("id").cloned().unwrap_or(Value::Null);

    if method != "tools/call" {
        return None;
    }

    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    let decision = engine.evaluate_tool_call(tool_name, &json!({
        "name": tool_name,
        "arguments": arguments,
    }));

    match decision {
        Decision::Allow => None,
        Decision::Warn { rule_id, severity, banner } => {
            warn!(
                "[shield] WARN rule={} severity={} tool={}: {}",
                rule_id, severity.as_str(), tool_name, banner
            );
            None
        }
        Decision::Block { rule_id, severity, reason } => {
            if shadow {
                warn!(
                    "[shield][shadow] would have BLOCKED rule={} severity={} tool={}: {}",
                    rule_id, severity.as_str(), tool_name, reason
                );
                None
            } else {
                error!(
                    "[shield] BLOCK rule={} severity={} tool={}: {}",
                    rule_id, severity.as_str(), tool_name, reason
                );
                Some(jsonrpc_error(
                    id,
                    -32099,
                    "shield_blocked",
                    json!({
                        "rule_id": rule_id,
                        "severity": severity.as_str(),
                        "reason": reason,
                        "tool": tool_name,
                    }),
                ))
            }
        }
        Decision::Approval { rule_id, severity, reason } => {
            if shadow {
                warn!(
                    "[shield][shadow] would have queued APPROVAL rule={} tool={}: {}",
                    rule_id, tool_name, reason
                );
                return None;
            }
            let ticket = format!("shld_{}", uuid::Uuid::new_v4().simple());
            if auto_deny {
                warn!(
                    "[shield] AUTO-DENY (--auto-deny-high) rule={} ticket={} tool={}",
                    rule_id, ticket, tool_name
                );
                return Some(jsonrpc_error(
                    id,
                    -32098,
                    "shield_approval_denied",
                    json!({
                        "rule_id": rule_id,
                        "severity": severity.as_str(),
                        "ticket_id": ticket,
                        "reason": format!("Auto-denied by --auto-deny-high: {}", reason),
                        "tool": tool_name,
                    }),
                ));
            }
            warn!(
                "[shield] APPROVAL REQUIRED rule={} ticket={} tool={}: {}",
                rule_id, ticket, tool_name, reason
            );
            warn!(
                "[shield] To approve, write 'approve {}' to ./.aperion-shield/inbox  (waiting 60s)",
                ticket
            );
            match wait_for_approval(&ticket).await {
                Ok(true) => {
                    info!("[shield] APPROVED ticket={} — allowing call", ticket);
                    None
                }
                Ok(false) => {
                    info!("[shield] DENIED ticket={} — blocking call", ticket);
                    Some(jsonrpc_error(
                        id,
                        -32098,
                        "shield_approval_denied",
                        json!({
                            "rule_id": rule_id,
                            "severity": severity.as_str(),
                            "ticket_id": ticket,
                            "reason": "Human reviewer denied this request",
                            "tool": tool_name,
                        }),
                    ))
                }
                Err(_) => {
                    warn!("[shield] TIMEOUT ticket={} — defaulting to deny", ticket);
                    Some(jsonrpc_error(
                        id,
                        -32097,
                        "shield_approval_timeout",
                        json!({
                            "rule_id": rule_id,
                            "ticket_id": ticket,
                            "reason": "Approval window elapsed without a human decision",
                        }),
                    ))
                }
            }
        }
    }
}

/// Watch `./.aperion-shield/inbox` for a line starting with `approve` or
/// `deny` followed by the ticket id. Returns `Ok(true)` for approve,
/// `Ok(false)` for deny, `Err(_)` after the timeout window.
async fn wait_for_approval(ticket: &str) -> anyhow::Result<bool> {
    let inbox = PathBuf::from(".aperion-shield/inbox");
    if let Some(parent) = inbox.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&inbox, ""); // create-if-missing, truncate

    let res = timeout(Duration::from_secs(60), async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(body) = std::fs::read_to_string(&inbox) {
                for line in body.lines() {
                    let l = line.trim();
                    if l.is_empty() { continue; }
                    if let Some(rest) = l.strip_prefix("approve") {
                        if rest.trim() == ticket { return Ok::<bool, std::io::Error>(true); }
                    }
                    if let Some(rest) = l.strip_prefix("deny") {
                        if rest.trim() == ticket { return Ok::<bool, std::io::Error>(false); }
                    }
                }
            }
        }
    }).await?;
    Ok(res?)
}

fn jsonrpc_error(id: Value, code: i64, msg: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": msg,
            "data": data,
        }
    })
}

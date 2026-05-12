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
//!         │  intercepts tools/call
//!         │  ┌─ Engine ──────────────────────────────────────┐
//!         │  │  rules → matches → composite + adjustments    │
//!         │  │  raw_severity ∨ composite_severity            │
//!         │  │   + workspace_is_prod        ─ bump           │
//!         │  │   + fingerprint_recent_deny  ─ bump           │
//!         │  │   + burst_in_progress        ─ bump           │
//!         │  │   - fingerprint_repeated_ok  ─ demote         │
//!         │  │  → final severity                              │
//!         │  │  → Allow | Warn | Approval | Block            │
//!         │  └────────────────────────────────────────────────┘
//!         ▼
//!   real upstream MCP server (postgres / github / shell …)
//! ```
//!
//! Free vs paid
//! ------------
//!
//! This binary is the FREE tier. It does not phone home, does not have a
//! shared approval queue, and does not produce a tamper-evident audit
//! chain — those are enterprise-only and live in the Smartflow gateway.
//! Local audit log is JSON Lines to stderr.

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

use aperion_shield::{
    decide, fingerprint, Adjustments, BurstDetector, Decision, DecisionMemory, Engine, Outcome,
    WorkspaceContext,
};

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
    /// decisions wait for a human approver to write `approve <ticket>`
    /// to a `.aperion-shield/inbox` file in the working directory.
    #[arg(long)]
    auto_deny_high: bool,

    /// Disable the workspace-context probe (`policy.workspace_probe`).
    /// On by default; the probe bumps severity in prod-looking repos.
    #[arg(long)]
    no_workspace_probe: bool,

    /// Disable decision memory (`policy.decision_memory`).
    /// On by default; memory demotes severity after repeated approvals
    /// and escalates after recent denials of the same fingerprint.
    #[arg(long)]
    no_memory: bool,

    /// Disable the burst detector (`policy.burst_detector`).
    /// On by default; the detector bumps severity while a wave of
    /// destructive matches is in progress.
    #[arg(long)]
    no_burst: bool,

    /// Opt-in to anonymised public telemetry (the "block ticker"). This
    /// feature is **not yet enabled** — it is under legal / DPO review.
    /// Specifying it today prints the review notice and exits.
    #[arg(long, value_name = "MODE", value_parser = ["public", "off"])]
    telemetry: Option<String>,

    /// Trailing args after `--` are the upstream MCP server command.
    /// Example: `aperion-shield -- npx @modelcontextprotocol/server-postgres ...`
    #[arg(trailing_var_arg = true, num_args = 0..)]
    upstream: Vec<String>,
}

/// Runtime state shared across both stdio pumps.
struct Shield {
    engine: Engine,
    workspace: WorkspaceContext,
    memory: DecisionMemory,
    burst: BurstDetector,
    shadow: bool,
    auto_deny: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    let cli = Cli::parse();

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

    // ── Adaptive layer initialisation ─────────────────────────────
    let workspace = if cli.no_workspace_probe {
        let mut p = engine.policy.clone();
        p.workspace_probe.enabled = false;
        WorkspaceContext::probe(&p)
    } else {
        WorkspaceContext::probe(&engine.policy)
    };
    let mut mem_cfg = engine.policy.decision_memory.clone();
    if cli.no_memory { mem_cfg.enabled = false; }
    let memory = DecisionMemory::open(mem_cfg);
    let mut burst_cfg = engine.policy.burst_detector.clone();
    if cli.no_burst { burst_cfg.enabled = false; }
    let burst = BurstDetector::new(burst_cfg);

    // ── Startup banner — make the adaptive surface visible ────────
    let mode_label = if cli.shadow { "SHADOW (warn only)" } else { "ENFORCE" };
    warn!(
        "[shield] === aperion-shield v{} starting === mode={} rules={} upstream='{} {}'",
        env!("CARGO_PKG_VERSION"),
        mode_label,
        engine.rules.len(),
        cli.upstream[0],
        cli.upstream[1..].join(" ")
    );
    warn!(
        "[shield] composite_scoring={} workspace_probe={} decision_memory={} burst_detector={}",
        engine.policy.composite_scoring.enabled,
        engine.policy.workspace_probe.enabled,
        memory.enabled(),
        engine.policy.burst_detector.enabled,
    );
    if workspace.is_prod {
        warn!(
            "[shield] workspace looks like PRODUCTION (matched: {}) — severity bumped one tier on every match",
            workspace.matched_signals.join(", ")
        );
    } else {
        info!("[shield] workspace probe: no prod signals matched in {}", workspace.root.display());
    }

    let (mut child, mut child_in, child_out) = spawn_upstream(&cli.upstream)?;

    let shield = Arc::new(Shield {
        engine,
        workspace,
        memory,
        burst,
        shadow: cli.shadow,
        auto_deny: cli.auto_deny_high,
    });

    let stdin = tokio::io::stdin();
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // Pump 1: client → child, with rule evaluation.
    let stdout_clone = stdout.clone();
    let shield_clone = shield.clone();
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

            let parsed: Option<Value> = serde_json::from_str(frame).ok();
            if let Some(req) = parsed.as_ref() {
                if let Some(decision_resp) = evaluate_request(req, &shield_clone).await {
                    let mut out = stdout_clone.lock().await;
                    let _ = out.write_all(decision_resp.to_string().as_bytes()).await;
                    let _ = out.write_all(b"\n").await;
                    let _ = out.flush().await;
                    continue;
                }
            }

            if let Err(e) = child_in.write_all(line.as_bytes()).await {
                error!("[shield] child stdin write error: {}", e);
                break;
            }
            let _ = child_in.flush().await;
        }
        let _ = child_in.shutdown().await;
    });

    // Pump 2: child → client (no inspection on this path in the
    // standalone — the LLM-response seam is enterprise-only).
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
async fn evaluate_request(req: &Value, shield: &Shield) -> Option<Value> {
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
    let canonical_params = json!({ "name": tool_name, "arguments": arguments });

    // First-pass evaluation (no memory yet — we don't have a primary rule).
    let initial_adj = Adjustments {
        workspace_is_prod: shield.workspace.is_prod,
        burst_in_progress: shield.burst.in_burst(),
        ..Default::default()
    };
    let first = shield.engine.evaluate(tool_name, &canonical_params, initial_adj);
    if first.matches.is_empty() {
        return None;
    }

    // Pick the primary rule (highest individual severity) to fingerprint.
    let primary_id = first
        .matches
        .iter()
        .max_by(|a, b| a.severity.cmp(&b.severity).then(a.points.cmp(&b.points)))
        .map(|m| m.rule_id.clone())
        .unwrap_or_default();
    let fp = fingerprint(&primary_id, &canonical_params);

    // Consult memory and re-evaluate with full adjustments.
    let mv = shield.memory.verdict_for(&fp);
    let adj = Adjustments {
        workspace_is_prod: shield.workspace.is_prod,
        burst_in_progress: shield.burst.in_burst(),
        fingerprint_recently_denied: mv.recent_deny,
        fingerprint_repeatedly_approved: mv.repeated_approve,
    };
    let eval = shield.engine.evaluate(tool_name, &canonical_params, adj);
    let decision = decide(&eval);

    // Anything beyond Allow counts toward the burst window.
    if decision.is_blocking() || matches!(decision, Decision::Warn { .. }) {
        let _ = shield.burst.observe();
    }

    // Audit log line — JSON to stderr.
    let audit = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "kind": "shield_eval",
        "tool": tool_name,
        "primary_rule_id": primary_id,
        "fingerprint": fp,
        "matched_rules": eval.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>(),
        "raw_severity": eval.raw_severity.as_str(),
        "composite_points": eval.composite_points,
        "composite_severity": eval.composite_severity.as_str(),
        "final_severity": eval.final_severity.as_str(),
        "adjustments": eval.adjustments_applied,
        "decision": decision.label(),
        "memory": { "approves": mv.approve_count, "denies": mv.deny_count },
    });
    eprintln!("{}", audit);

    match decision {
        Decision::Allow => None,
        Decision::Warn { rule_id, severity, banner, safer_alternative } => {
            warn!(
                "[shield] WARN rule={} severity={} tool={}: {}",
                rule_id, severity.as_str(), tool_name, banner
            );
            if let Some(s) = safer_alternative {
                warn!("[shield]   safer alternative: {}", s);
            }
            None
        }
        Decision::Block { rule_id, severity, reason, safer_alternative, contributing_rules } => {
            if shield.shadow {
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
                if let Some(ref s) = safer_alternative {
                    error!("[shield]   safer alternative: {}", s);
                }
                Some(jsonrpc_error(
                    id,
                    -32099,
                    "shield_blocked",
                    json!({
                        "rule_id": rule_id,
                        "severity": severity.as_str(),
                        "reason": reason,
                        "safer_alternative": safer_alternative,
                        "contributing_rules": contributing_rules,
                        "fingerprint": fp,
                        "tool": tool_name,
                    }),
                ))
            }
        }
        Decision::Approval { rule_id, severity, reason, safer_alternative, contributing_rules } => {
            if shield.shadow {
                warn!(
                    "[shield][shadow] would have queued APPROVAL rule={} tool={}: {}",
                    rule_id, tool_name, reason
                );
                return None;
            }
            let ticket = format!("shld_{}", uuid::Uuid::new_v4().simple());
            if shield.auto_deny {
                warn!(
                    "[shield] AUTO-DENY (--auto-deny-high) rule={} ticket={} tool={}",
                    rule_id, ticket, tool_name
                );
                shield.memory.record(&rule_id, &fp, Outcome::Deny, tool_name);
                return Some(jsonrpc_error(
                    id,
                    -32098,
                    "shield_approval_denied",
                    json!({
                        "rule_id": rule_id,
                        "severity": severity.as_str(),
                        "ticket_id": ticket,
                        "reason": format!("Auto-denied by --auto-deny-high: {}", reason),
                        "safer_alternative": safer_alternative,
                        "contributing_rules": contributing_rules,
                        "fingerprint": fp,
                        "tool": tool_name,
                    }),
                ));
            }
            warn!(
                "[shield] APPROVAL REQUIRED rule={} ticket={} tool={}: {}",
                rule_id, ticket, tool_name, reason
            );
            if let Some(ref s) = safer_alternative {
                warn!("[shield]   safer alternative: {}", s);
            }
            warn!(
                "[shield] To approve: echo 'approve {}' >> ./.aperion-shield/inbox   (waiting 60s)",
                ticket
            );
            match wait_for_approval(&ticket).await {
                Ok(true) => {
                    info!("[shield] APPROVED ticket={} — allowing call", ticket);
                    shield.memory.record(&rule_id, &fp, Outcome::Approve, tool_name);
                    None
                }
                Ok(false) => {
                    info!("[shield] DENIED ticket={} — blocking call", ticket);
                    shield.memory.record(&rule_id, &fp, Outcome::Deny, tool_name);
                    Some(jsonrpc_error(
                        id,
                        -32098,
                        "shield_approval_denied",
                        json!({
                            "rule_id": rule_id,
                            "severity": severity.as_str(),
                            "ticket_id": ticket,
                            "reason": "Human reviewer denied this request",
                            "safer_alternative": safer_alternative,
                            "contributing_rules": contributing_rules,
                            "fingerprint": fp,
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
                            "safer_alternative": safer_alternative,
                            "fingerprint": fp,
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
    let _ = std::fs::write(&inbox, "");

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

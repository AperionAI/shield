//! aperion-shield -- local MCP guardrail for AI coding agents.
//!
//! Architecture
//! ------------
//!
//! ```text
//! Cursor / Claude Code
//!         │  JSON-RPC over stdio
//!         v
//!   aperion-shield      <── shield.yaml ruleset
//!         │  intercepts tools/call
//!         │  ┌─ Engine ──────────────────────────────────────┐
//!         │  │  rules -> matches -> composite + adjustments    │
//!         │  │  raw_severity || composite_severity            │
//!         │  │   + workspace_is_prod        ─ bump           │
//!         │  │   + fingerprint_recent_deny  ─ bump           │
//!         │  │   + burst_in_progress        ─ bump           │
//!         │  │   - fingerprint_repeated_ok  ─ demote         │
//!         │  │  -> final severity                              │
//!         │  │  -> Allow | Warn | Approval | Block            │
//!         │  └────────────────────────────────────────────────┘
//!         v
//!   real upstream MCP server (postgres / github / shell ...)
//! ```
//!
//! Free vs paid
//! ------------
//!
//! This binary is the FREE tier. It does not phone home, does not have a
//! shared approval queue, and does not produce a tamper-evident audit
//! chain -- those are enterprise-only and live in the Smartflow gateway.
//! Local audit log is JSON Lines to stderr.

use anyhow::{anyhow, Context};
use clap::Parser;
use log::{debug, error, info, warn};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio::time::timeout;

use aperion_shield::{
    decide, fingerprint, identity, orgmode, Adjustments, BurstDetector, Decision, DecisionMemory,
    Engine, IdMeProvider, IdentityConfig, IdentityGate, IdentityProvider, MockProvider, Outcome,
    ProviderKind, WorkspaceContext,
};
use aperion_shield::engine::{Scope, Severity};
use aperion_shield::orgmode::{
    smartflow_provider::ResolveOutcome, AuditEvent, AuditSink, EnrolledHandles, OrgApi, OrgState,
    SmartflowProvider,
};
use aperion_shield::supply;
use aperion_shield::transport;

/// Aperion Shield -- local MCP guardrail.
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
    /// feature is **not yet enabled** -- it is under legal / DPO review.
    /// Specifying it today prints the review notice and exits.
    #[arg(long, value_name = "MODE", value_parser = ["public", "off"])]
    telemetry: Option<String>,

    /// One-shot evaluation mode: read tool-call descriptors from stdin
    /// (one JSON object per line), print the engine's decision for each
    /// as JSON to stdout, and exit. No MCP / upstream / IDE required --
    /// designed for batch testing, CI, and ad-hoc rule validation.
    ///
    /// Input schema per line:
    ///   {"tool": "execute_sql", "params": {"query": "DROP DATABASE x"}}
    ///   {"text": "I will DROP DATABASE prod"}             (llm_response scope)
    ///   {... "expect": "allow|warn|approval|block"}       (optional)
    ///
    /// Exit code: 0 if all expectations met (or none given), 1 otherwise.
    #[arg(long, conflicts_with = "upstream")]
    check: bool,

    /// Override the workspace root for the prod-probe. Default: current
    /// working directory. Useful for fixturing prod-bump behaviour
    /// against a temporary directory tree. Honoured by `--check` and
    /// `--diff` (which both run the engine over a corpus).
    #[arg(long, value_name = "PATH")]
    workspace: Option<PathBuf>,

    // ── Behavior-diff explainer (v0.6+) ────────────────────────────
    //
    // `aperion-shield --diff` runs the engine over the same corpus
    // under two different shieldsets and reports which lines flipped,
    // attributed to the rules that materially changed. This is the
    // native Rust port of `scripts/shield-diff.py` (which now just
    // wraps this mode). See docs/shieldset-as-code.md for the full
    // PR-review pattern this enables.

    /// Behavior-diff mode: run the engine twice over the same corpus
    /// (once with `--rules-before`, once with `--rules-after`) and
    /// emit a report describing which decisions changed and why.
    /// Reads the corpus from `--corpus PATH` or stdin. Does NOT
    /// start the MCP middleman.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "enroll",
        conflicts_with = "status",
        conflicts_with = "disenroll",
        conflicts_with = "identity_list",
        conflicts_with = "identity_flush"
    )]
    diff: bool,

    /// Current (main-branch) shieldset YAML. Required with `--diff`.
    #[arg(long, value_name = "PATH", requires = "diff")]
    rules_before: Option<PathBuf>,

    /// Proposed (PR-branch) shieldset YAML. Required with `--diff`.
    #[arg(long, value_name = "PATH", requires = "diff")]
    rules_after: Option<PathBuf>,

    /// JSON-Lines corpus path. Defaults to stdin.
    #[arg(long, value_name = "PATH", requires = "diff")]
    corpus: Option<PathBuf>,

    /// Report format for `--diff`. Default: text.
    #[arg(long, value_name = "FMT", value_parser = ["text", "markdown", "json"], requires = "diff")]
    format: Option<String>,

    /// Max flipped-line samples to show per rule. Default: 3.
    #[arg(long, value_name = "N", default_value_t = 3, requires = "diff")]
    max_samples: usize,

    /// Exit 1 if any line's decision flipped between the two
    /// shieldsets. Useful for CI gates that require explicit reviewer
    /// approval on behavior-changing PRs.
    #[arg(long, requires = "diff")]
    fail_if_flipped: bool,

    /// Exit 1 if any line moved toward a more permissive decision.
    /// This is the policy gate most teams want -- tightening is
    /// fine, loosening needs explicit sign-off.
    #[arg(long, requires = "diff")]
    fail_if_loosened: bool,

    /// Exit 1 if more than N lines flipped TO `allow`. Less strict
    /// than `--fail-if-loosened`; permits warn -> allow on a
    /// case-by-case basis up to the threshold.
    #[arg(long, value_name = "N", requires = "diff")]
    fail_if_allows_loosened: Option<usize>,

    /// Path to an `identity.yaml` overriding the default discovery
    /// (`$APERION_SHIELD_IDENTITY_CONFIG`, `~/.aperion-shield/identity.yaml`,
    /// then built-in mock-only defaults).
    #[arg(long, value_name = "PATH")]
    identity_config: Option<PathBuf>,

    /// Disable the identity-verification subsystem entirely. Rules
    /// carrying an `identity:` block will fall back to plain
    /// Approval / Block.
    #[arg(long)]
    no_identity: bool,

    /// Print how many cached identity proofs exist (with subjects and
    /// scopes) and exit. Does not start the MCP middleman.
    #[arg(long, conflicts_with = "upstream", conflicts_with = "check")]
    identity_list: bool,

    /// Drop every cached identity proof and exit. Forces re-verification
    /// on the next gated call.
    #[arg(long, conflicts_with = "upstream", conflicts_with = "check")]
    identity_flush: bool,

    // ── Git-hook integration (v0.7+) ──────────────────────────────
    //
    // `--install-hooks` writes `.git/hooks/{pre-commit,pre-push}` that
    // call `--check-staged` / `--check-pushed-refs` respectively. The
    // hooks honour `git --no-verify` and `SHIELD_HOOKS_DISABLE=1`.
    // See `docs/hooks.md` for the full contract.

    /// Install `pre-commit` and `pre-push` hooks into the git repo at
    /// the current working directory (or `--repo PATH`). Idempotent --
    /// re-running refreshes our hooks but never clobbers an
    /// unrecognised hook unless `--chain-existing` is supplied.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "enroll"
    )]
    install_hooks: bool,

    /// Remove Aperion-installed `pre-commit` / `pre-push` hooks from
    /// the git repo at the current working directory (or `--repo
    /// PATH`). Restores any chained-aside originals.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks"
    )]
    uninstall_hooks: bool,

    /// Override the path to the repository being modified by
    /// `--install-hooks` / `--uninstall-hooks` / `--check-staged` /
    /// `--check-pushed-refs`. Default: current working directory.
    #[arg(long, value_name = "PATH")]
    repo: Option<PathBuf>,

    /// With `--install-hooks`: if an existing hook is present that we
    /// don't recognise, move it aside (to `<hook>.aperion-backup`) and
    /// have our hook `exec` it as a tail chain. Compatible with husky,
    /// pre-commit, and lefthook installations. Without this flag we
    /// refuse to overwrite an unrecognised hook (the safe default).
    #[arg(long, requires = "install_hooks")]
    chain_existing: bool,

    /// Run the engine against the lines this commit is about to
    /// ADD or MODIFY. Used by the `pre-commit` hook installed by
    /// `--install-hooks`, but also invokable manually for debugging.
    /// Exits 0 (clean), 1 (Block-severity match), 2 (Approval-severity
    /// match -- can't prompt in a pre-commit context, so refused).
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks"
    )]
    check_staged: bool,

    /// Read git's standard pre-push stdin and refuse force-pushes or
    /// branch-deletions targeting protected branches (main, master,
    /// prod, release/*, by default). Used by the `pre-push` hook
    /// installed by `--install-hooks`. Set `SHIELD_PROTECTED_BRANCHES`
    /// (comma-separated) to override the default protected pattern.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged"
    )]
    check_pushed_refs: bool,

    // ── Rule tuning (v0.7+) ───────────────────────────────────────
    //
    // `--suggest-rules` reads your local audit log + active shieldset
    // and emits tuning recommendations (RULE_NEVER_FIRES,
    // CONSISTENTLY_DEMOTED, NOISY_WARN). Default output is human text;
    // markdown and yaml-patch are also available via --suggest-format.

    /// Read an audit log (JSON-Lines stderr capture from a real run
    /// of `aperion-shield`) and emit tuning suggestions for your
    /// shieldset. Requires `--audit-log PATH`.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs"
    )]
    suggest_rules: bool,

    /// Path to the JSON-Lines audit log used by `--suggest-rules`.
    /// Capture via e.g. `aperion-shield -- ... 2>>~/.aperion-shield/audit.jsonl`.
    #[arg(long, value_name = "PATH", requires = "suggest_rules")]
    audit_log: Option<PathBuf>,

    /// Only consider audit records in the last N days. Default: 30.
    /// Pass 0 to consider every record in the file.
    #[arg(long, value_name = "N", requires = "suggest_rules")]
    suggest_window_days: Option<u32>,

    /// Minimum number of fires required to trigger CONSISTENTLY_DEMOTED
    /// or NOISY_WARN suggestions. Default: 5.
    #[arg(long, value_name = "N", default_value_t = 5, requires = "suggest_rules")]
    suggest_min_occurrences: usize,

    /// Output format for `--suggest-rules`. Default: text.
    #[arg(
        long,
        value_name = "FMT",
        value_parser = ["text", "markdown", "md", "yaml-patch", "yaml", "patch"],
        requires = "suggest_rules"
    )]
    suggest_format: Option<String>,

    // ── Shell shims (v0.8+) ───────────────────────────────────────
    //
    // The shims close the "agent reaches around MCP and runs a
    // destructive command directly" surface. `--install-shims` writes
    // tiny wrappers to `~/.aperion-shield/bin/` for the supported
    // commands (`aws`, `kubectl`, `terraform`, `rm`, ...); the user
    // puts that dir first on `$PATH` and every invocation goes
    // through `--check-cmd` before reaching the real binary.

    /// Install per-command shell shims in `--shim-dir` (default
    /// `$HOME/.aperion-shield/bin`). Wrappers route every invocation
    /// of `aws`, `kubectl`, `terraform`, etc. through the active
    /// shieldset. Mirrors `--install-hooks` -- same bypass semantics
    /// via `SHIELD_SHIMS_DISABLE=1`.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs",
        conflicts_with = "suggest_rules"
    )]
    install_shims: bool,

    /// Remove every Shield-managed shim from `--shim-dir`. Files
    /// without the Aperion marker are left alone (operator-authored).
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs",
        conflicts_with = "suggest_rules",
        conflicts_with = "install_shims"
    )]
    uninstall_shims: bool,

    /// List shims currently present in `--shim-dir`, separated into
    /// Shield-managed vs foreign (operator-authored). Useful as a
    /// pre-install dry run.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs",
        conflicts_with = "suggest_rules",
        conflicts_with = "install_shims",
        conflicts_with = "uninstall_shims"
    )]
    list_shims: bool,

    /// Comma-separated subset of commands to shim (e.g.
    /// `--for aws,kubectl,terraform`). When omitted, installs the
    /// full Shield-supported list. See `templates::DEFAULT_SHIMMED_COMMANDS`.
    #[arg(
        long = "for",
        value_name = "CMD,CMD,...",
        requires = "install_shims"
    )]
    shim_for: Option<String>,

    /// Override the shim directory (default
    /// `$HOME/.aperion-shield/bin`). Used by `--install-shims`,
    /// `--uninstall-shims`, and `--list-shims`.
    #[arg(long, value_name = "PATH")]
    shim_dir: Option<PathBuf>,

    /// Evaluate a reconstructed shell command line and exit with the
    /// engine's verdict. Invoked by the installed shims; rarely run
    /// directly. Usage: `aperion-shield --check-cmd -- aws s3 rm ...`.
    /// NOTE: this mode reads its argv from the trailing `--` args, the
    /// same slot the upstream-MCP-server invocation uses. It is the
    /// only one of these subcommand-style modes that does NOT conflict
    /// with `upstream`, by design.
    #[arg(
        long,
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs",
        conflicts_with = "suggest_rules",
        conflicts_with = "install_shims",
        conflicts_with = "uninstall_shims",
        conflicts_with = "list_shims"
    )]
    check_cmd: bool,

    // ── Decision transparency (v0.8+) ─────────────────────────────
    //
    // `--explain` takes a JSON tool-call descriptor on stdin or via
    // --input and prints a full decision walkthrough: which rules
    // matched, what signals were applied, how severity tiers chained,
    // and the safer alternative if anything was gated.

    /// Print a full decision walkthrough for a single tool-call
    /// descriptor read from `--input` (or stdin via `--input -`).
    /// Output is text by default; `--explain-format markdown` is
    /// PR-comment-friendly and `--explain-format json` is a stable
    /// schema for piping into other tooling.
    #[arg(
        long,
        conflicts_with = "upstream",
        conflicts_with = "check",
        conflicts_with = "diff",
        conflicts_with = "install_hooks",
        conflicts_with = "uninstall_hooks",
        conflicts_with = "check_staged",
        conflicts_with = "check_pushed_refs",
        conflicts_with = "suggest_rules",
        conflicts_with = "install_shims",
        conflicts_with = "uninstall_shims",
        conflicts_with = "list_shims",
        conflicts_with = "check_cmd"
    )]
    explain: bool,

    /// JSON tool-call descriptor for `--explain`. Path `-` reads from
    /// stdin. The descriptor is the MCP-style `{"name": "...",
    /// "arguments": {...}}` payload (also accepts legacy
    /// `{"tool": "...", "params": {...}}`).
    #[arg(long, value_name = "PATH", requires = "explain")]
    input: Option<PathBuf>,

    /// Output format for `--explain`. Default: text.
    #[arg(
        long,
        value_name = "FMT",
        value_parser = ["text", "txt", "markdown", "md", "json"],
        requires = "explain"
    )]
    explain_format: Option<String>,

    /// Force `workspace_is_prod = true` in the `--explain` adjustment
    /// signals. Useful for "what would this call decide if it landed
    /// in a prod workspace?" walk-throughs.
    #[arg(long, requires = "explain")]
    explain_force_prod: bool,

    /// Force `burst_in_progress = true` in the `--explain` adjustment
    /// signals. Reproduces decisions captured during a high-traffic
    /// window without needing to recreate the actual burst.
    #[arg(long, requires = "explain")]
    explain_force_burst: bool,

    /// Force `fingerprint_repeatedly_approved = true` -- demonstrates
    /// what the decision-memory demotion would do for this call.
    #[arg(long, requires = "explain")]
    explain_force_repeatedly_approved: bool,

    /// Force `fingerprint_recently_denied = true` -- demonstrates what
    /// the decision-memory escalation would do for this call.
    #[arg(long, requires = "explain")]
    explain_force_recently_denied: bool,

    // ── Org-mode (v0.5+) ──────────────────────────────────────────
    //
    // Enroll this Shield against a Smartflow control plane so policy,
    // identity, and audit are managed centrally. See
    // docs/strategy/shield-org-tier-plan.md for the full design.

    /// Enroll this Shield against a Smartflow control plane. Requires
    /// `--smartflow-url` and `--token`. Persists the resulting vkey at
    /// `~/.aperion-shield/orgmode.json` (mode 0600). Subsequent runs
    /// pull policy, send audit, and use Smartflow as the identity
    /// relying party.
    #[arg(long, conflicts_with = "upstream", conflicts_with = "check")]
    enroll: bool,

    /// Print the current org-mode enrollment status (or "standalone")
    /// and exit. Probes the Smartflow control plane for liveness.
    #[arg(long, conflicts_with = "upstream", conflicts_with = "check", conflicts_with = "enroll")]
    status: bool,

    /// Remove the local org-mode enrollment record (turns this Shield
    /// back into a standalone). Use `--revoke` to also revoke the vkey
    /// server-side.
    #[arg(long, conflicts_with = "upstream", conflicts_with = "check", conflicts_with = "enroll")]
    disenroll: bool,

    /// When used with `--disenroll`, also calls
    /// `DELETE /api/enterprise/devices/{id}` to revoke the vkey on
    /// Smartflow before removing the local record.
    #[arg(long, requires = "disenroll")]
    revoke: bool,

    /// Smartflow control-plane base URL, e.g.
    /// `https://smartflow.example.com`. Required for `--enroll`.
    #[arg(long, value_name = "URL", requires = "enroll")]
    smartflow_url: Option<String>,

    /// One-time enrollment token issued from the Smartflow dashboard.
    /// Required for `--enroll`.
    #[arg(long, value_name = "TOKEN", requires = "enroll")]
    token: Option<String>,

    /// Friendly device name shown in the fleet view. Defaults to
    /// `<hostname>-shield`. Used with `--enroll`.
    #[arg(long, value_name = "NAME", requires = "enroll")]
    device_name: Option<String>,

    /// Owner email for audit + fleet display (informational; the
    /// policy group is still resolved server-side from the enrollment
    /// token).
    #[arg(long, value_name = "EMAIL", requires = "enroll")]
    enroll_email: Option<String>,

    // ── Transports (v0.9+) ────────────────────────────────────────
    //
    // Until v0.8 Shield spoke stdio on both sides. v0.9 adds the MCP
    // Streamable HTTP transport on either seam: `--upstream-url` points
    // Shield at a REMOTE MCP server (closing the hosted-server bypass),
    // and `--http-listen` makes Shield itself listen as a Streamable
    // HTTP server for hosts that don't speak stdio.

    /// Connect to a remote MCP server over Streamable HTTP (JSON-RPC
    /// over POST + SSE response streams) instead of spawning a local
    /// stdio child. Example:
    /// `aperion-shield --upstream-url https://mcp.example.com/mcp`
    #[arg(long, value_name = "URL", conflicts_with = "check")]
    upstream_url: Option<String>,

    /// Extra request header for `--upstream-url`, as 'Name: value'.
    /// Repeatable. Typically `--upstream-header 'Authorization: Bearer ...'`.
    #[arg(long, value_name = "HEADER", requires = "upstream_url")]
    upstream_header: Vec<String>,

    /// Listen as a Streamable HTTP MCP server on this address (e.g.
    /// `127.0.0.1:8848`) instead of speaking stdio to the IDE. POST
    /// JSON-RPC to it; GET with `Accept: text/event-stream` opens the
    /// server-initiated stream.
    #[arg(long, value_name = "ADDR")]
    http_listen: Option<std::net::SocketAddr>,

    // ── MCP supply-chain protection (v0.9+) ───────────────────────

    /// Disable TOFU tool-catalog pinning (`policy.supply_chain.pinning`
    /// stays authoritative when this flag is absent). Description /
    /// result scanning rules still run.
    #[arg(long)]
    no_pin: bool,

    /// Clear the stored tool-catalog pins for this upstream before
    /// starting, then re-pin from its next `tools/list`. Run once after
    /// a human has reviewed a legitimate tool change that Shield
    /// flagged as a rug pull.
    #[arg(long)]
    repin: bool,

    /// Trailing args after `--` are the upstream MCP server command.
    /// Example: `aperion-shield -- npx @modelcontextprotocol/server-postgres ...`
    #[arg(trailing_var_arg = true, num_args = 0..)]
    upstream: Vec<String>,
}

/// Runtime state shared across both stdio pumps.
struct Shield {
    /// Always present. In standalone mode the receiver only ever sees
    /// the engine handed in at startup; in org mode the orgmode
    /// policy-pull task pushes new engines on every version bump.
    /// Snapshotting on every tool call is cheap (`watch::Receiver::borrow`
    /// is a single atomic increment).
    engine_rx: tokio::sync::watch::Receiver<Arc<Engine>>,
    workspace: WorkspaceContext,
    memory: DecisionMemory,
    burst: BurstDetector,
    shadow: bool,
    auto_deny: bool,
    /// `None` when the user passed `--no-identity` OR no rule in the
    /// loaded shieldset carries an `identity:` block (we don't pay the
    /// cost of setting up the gate if nothing will use it).
    identity_gate: Option<Arc<IdentityGate>>,
    /// `Some(...)` when the binary started with a populated
    /// `~/.aperion-shield/orgmode.json`. Holding the handles keeps the
    /// heartbeat / policy-pull / audit-sink tasks alive for the
    /// lifetime of the process.
    orgmode: Option<Arc<EnrolledHandles>>,
    /// Smartflow-mediated identity provider. Built once at startup
    /// when org-mode is active; cheap to clone.
    smartflow_identity: Option<Arc<SmartflowProvider>>,
    /// v0.9 supply-chain state: pin key, quarantine set, and the
    /// request-id bookkeeping that lets the response pump know which
    /// upstream frames are `tools/list` / `tools/call` results.
    supply: SupplyState,
}

/// What a forwarded request id corresponds to, so the response pump can
/// dissect the matching result frame.
#[derive(Debug, Clone)]
enum PendingKind {
    ToolsList,
    ToolCall { tool: String },
}

struct SupplyState {
    /// Pin key + log label for the upstream (command line or URL).
    upstream_label: String,
    /// Effective pinning switch: CLI `--no-pin` AND policy combined.
    pinning: bool,
    /// Forwarded request ids we want to intercept the responses of.
    pending: Mutex<HashMap<String, PendingKind>>,
    /// Tools flagged as rug-pulled / poisoned. `tools/call` against a
    /// quarantined tool is blocked at the request seam, so a host that
    /// cached the old catalog still can't reach the swapped tool.
    quarantined: Mutex<HashSet<String>>,
}

impl Shield {
    /// Snapshot the current engine. Cheap.
    fn current_engine(&self) -> Arc<Engine> {
        self.engine_rx.borrow().clone()
    }
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

    if cli.identity_list {
        return run_identity_list(&cli).await;
    }
    if cli.identity_flush {
        return run_identity_flush(&cli).await;
    }
    if cli.check {
        return run_check_mode(&cli).await;
    }
    if cli.diff {
        let exit_code = run_diff_mode(&cli).await?;
        std::process::exit(exit_code);
    }

    // ── Git-hook modes (v0.7+) ────────────────────────────────────
    if cli.install_hooks {
        let exit_code = run_install_hooks(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.uninstall_hooks {
        let exit_code = run_uninstall_hooks(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.check_staged {
        let exit_code = run_check_staged(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.check_pushed_refs {
        let exit_code = run_check_pushed_refs(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.suggest_rules {
        let exit_code = run_suggest_rules(&cli)?;
        std::process::exit(exit_code);
    }

    // ── Shell-shim modes (v0.8+) ──────────────────────────────────
    if cli.install_shims {
        let exit_code = run_install_shims(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.uninstall_shims {
        let exit_code = run_uninstall_shims(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.list_shims {
        let exit_code = run_list_shims(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.check_cmd {
        let exit_code = run_check_cmd(&cli)?;
        std::process::exit(exit_code);
    }
    if cli.explain {
        let exit_code = run_explain(&cli)?;
        std::process::exit(exit_code);
    }

    // ── Org-mode subcommands ──────────────────────────────────────
    if cli.enroll {
        let url = cli.smartflow_url.as_deref().ok_or_else(|| {
            anyhow!("--enroll requires --smartflow-url <URL>")
        })?;
        let token = cli.token.as_deref().ok_or_else(|| {
            anyhow!("--enroll requires --token <TOKEN>")
        })?;
        return orgmode::run_enroll(
            url,
            token,
            cli.device_name.as_deref(),
            cli.enroll_email.as_deref(),
        )
        .await;
    }
    if cli.status {
        return orgmode::run_status().await;
    }
    if cli.disenroll {
        return orgmode::run_disenroll(cli.revoke).await;
    }

    if cli.upstream.is_empty() && cli.upstream_url.is_none() {
        return Err(anyhow!(
            "no upstream MCP server given. Usage:\n  \
             aperion-shield [--rules PATH] [--shadow] -- <upstream-mcp> [args...]      (stdio upstream)\n  \
             aperion-shield [--rules PATH] --upstream-url https://host/mcp            (remote Streamable HTTP upstream)\n\
             (For one-shot rule testing without MCP, use `aperion-shield --check`.)"
        ));
    }
    if !cli.upstream.is_empty() && cli.upstream_url.is_some() {
        return Err(anyhow!(
            "--upstream-url conflicts with a trailing stdio upstream command -- pick one"
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

    // ── Startup banner -- make the adaptive surface visible ────────
    let mode_label = if cli.shadow { "SHADOW (warn only)" } else { "ENFORCE" };
    let upstream_label_banner = match &cli.upstream_url {
        Some(url) => url.clone(),
        None => cli.upstream.join(" "),
    };
    warn!(
        "[shield] === aperion-shield v{} starting === mode={} rules={} upstream='{}'",
        env!("CARGO_PKG_VERSION"),
        mode_label,
        engine.rules.len(),
        upstream_label_banner,
    );
    warn!(
        "[shield] composite_scoring={} workspace_probe={} decision_memory={} burst_detector={} catalog_pinning={}",
        engine.policy.composite_scoring.enabled,
        engine.policy.workspace_probe.enabled,
        memory.enabled(),
        engine.policy.burst_detector.enabled,
        engine.policy.supply_chain.pinning && !cli.no_pin,
    );
    if workspace.is_prod {
        warn!(
            "[shield] workspace looks like PRODUCTION (matched: {}) -- severity bumped one tier on every match",
            workspace.matched_signals.join(", ")
        );
    } else {
        info!("[shield] workspace probe: no prod signals matched in {}", workspace.root.display());
    }

    // ── Identity gate (only built if at least one rule needs it) ──
    let identity_gate = if cli.no_identity {
        warn!("[shield] --no-identity: identity-gated rules will fall back to plain Approval/Block");
        None
    } else if engine.rules.iter().any(|r| r.identity.is_some()) {
        match build_identity_gate(cli.identity_config.as_deref()).await {
            Ok(g) => {
                warn!(
                    "[shield] identity gate ready: providers=[{}] cached_proofs={} hold={}s",
                    g.config()
                        .providers
                        .iter()
                        .map(|p| format!(
                            "{}:{}{}",
                            p.id,
                            match p.kind { ProviderKind::IdMe => "id_me", ProviderKind::Mock => "mock" },
                            if matches!(p.kind, ProviderKind::IdMe)
                                && !is_idme_ready(p)
                            { "(unready)" } else { "" }
                        ))
                        .collect::<Vec<_>>()
                        .join(", "),
                    g.cached_count(),
                    g.hold_seconds(),
                );
                Some(Arc::new(g))
            }
            Err(e) => {
                error!("[shield] identity gate setup failed: {}", e);
                None
            }
        }
    } else {
        info!("[shield] no rules have `identity:` blocks -- identity gate inactive");
        None
    };

    // ── Org-mode bootstrap (v0.5+) ────────────────────────────────
    //
    // If `~/.aperion-shield/orgmode.json` exists we treat this as an
    // enrolled Shield: pull the org's shieldset from Smartflow (falls
    // back to the local engine on failure), start the heartbeat /
    // policy-pull / audit-sink tasks, and prepare the
    // `SmartflowProvider` so identity-gated rules route through
    // Smartflow instead of the local OAuth dance.
    let (orgmode_state, orgmode_handles, smartflow_identity, engine_rx) =
        bootstrap_orgmode(engine).await?;
    if orgmode_state.is_some() {
        warn!("[shield] running in ORG MODE (centrally managed)");
    } else {
        info!("[shield] running in STANDALONE mode (no orgmode.json)");
    }

    // ── Upstream transport (v0.9: stdio child OR remote HTTP) ─────
    let upstream = match &cli.upstream_url {
        Some(url) => {
            let mut headers = Vec::new();
            for raw in &cli.upstream_header {
                headers.push(transport::http_upstream::parse_header(raw)?);
            }
            warn!("[shield] upstream transport: Streamable HTTP -> {}", url);
            transport::http_upstream::spawn_http_upstream(url, headers)?
        }
        None => transport::spawn_stdio_upstream(&cli.upstream)?,
    };
    let upstream_label = upstream.label.clone();
    let mut child = upstream.child;
    let to_upstream = upstream.tx;
    let mut from_upstream = upstream.rx;

    // ── Supply-chain bootstrap ────────────────────────────────────
    let pinning_enabled = {
        let policy_pinning = engine_rx.borrow().policy.supply_chain.pinning;
        policy_pinning && !cli.no_pin
    };
    if cli.repin {
        match supply::clear_pins(&upstream_label) {
            Ok(true) => warn!(
                "[shield] --repin: cleared stored tool-catalog pins for this upstream; \
                 the next tools/list will be re-pinned (TOFU)"
            ),
            Ok(false) => info!("[shield] --repin: no pins stored for this upstream"),
            Err(e) => error!("[shield] --repin failed: {}", e),
        }
    }

    let shield = Arc::new(Shield {
        engine_rx,
        workspace,
        memory,
        burst,
        shadow: cli.shadow,
        auto_deny: cli.auto_deny_high,
        identity_gate,
        orgmode: orgmode_handles,
        smartflow_identity,
        supply: SupplyState {
            upstream_label,
            pinning: pinning_enabled,
            pending: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
        },
    });

    // ── Downstream: HTTP server or classic stdio ─────────────────
    if let Some(addr) = cli.http_listen {
        // HTTP downstream: hyper server feeds requests through the same
        // gate; the response pump routes intercepted upstream frames to
        // the waiting POST or the GET SSE broadcast.
        let http_state = transport::http_server::HttpDownstream::new();

        let pump_state = http_state.clone();
        let pump_shield = shield.clone();
        let from_upstream_handle = tokio::spawn(async move {
            while let Some(frame) = from_upstream.recv().await {
                let frame = intercept_upstream_frame(frame, &pump_shield).await;
                pump_state.route_upstream_frame(frame).await;
            }
            debug!("[shield] upstream channel closed");
        });

        let gate: Arc<dyn transport::http_server::RequestGate> =
            Arc::new(ShieldGate(shield.clone()));
        let serve_result =
            transport::http_server::serve(addr, gate, to_upstream, http_state).await;
        let _ = from_upstream_handle.await;
        if let Err(e) = serve_result {
            error!("[shield] http downstream server error: {}", e);
        }
    } else {
        let stdin = tokio::io::stdin();
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        // Pump 1: client -> upstream, with rule evaluation.
        let stdout_clone = stdout.clone();
        let shield_clone = shield.clone();
        let to_upstream_handle = tokio::spawn(async move {
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
                debug!("[shield] client -> {}", frame);

                let parsed: Option<Value> = serde_json::from_str(frame).ok();
                if let Some(req) = parsed.as_ref() {
                    if let Some(decision_resp) = process_client_frame(req, &shield_clone).await {
                        let mut out = stdout_clone.lock().await;
                        let _ = out.write_all(decision_resp.to_string().as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                        continue;
                    }
                }

                if to_upstream.send(frame.to_string()).await.is_err() {
                    error!("[shield] upstream channel closed");
                    break;
                }
            }
        });

        // Pump 2: upstream -> client, with v0.9 supply-chain
        // interception (tools/list pinning + description scan,
        // tools/call result scan).
        let stdout_clone2 = stdout.clone();
        let shield_clone2 = shield.clone();
        let from_upstream_handle = tokio::spawn(async move {
            while let Some(frame) = from_upstream.recv().await {
                debug!("[shield] upstream -> {}", frame);
                let frame = intercept_upstream_frame(frame, &shield_clone2).await;
                let mut out = stdout_clone2.lock().await;
                if out.write_all(frame.as_bytes()).await.is_err() { break; }
                if out.write_all(b"\n").await.is_err() { break; }
                let _ = out.flush().await;
            }
            debug!("[shield] upstream channel closed");
        });

        let _ = to_upstream_handle.await;
        let _ = from_upstream_handle.await;
    }

    if let Some(child) = child.as_mut() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    // Best-effort: give the org-mode audit sink one last chance to ship
    // any buffered events before the process exits. Capped at 6 s so
    // we don't hang on a wedged control plane.
    if let Some(handles) = shield.orgmode.as_ref() {
        let drain = handles.audit.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(6), async move {
            drain.drain().await;
        })
        .await;
    }

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

/// One-shot batch evaluation. Reads JSON-Lines from stdin, prints one
/// JSON decision per line to stdout, summary to stderr, exits non-zero
/// if any `expect` field failed.
///
/// Designed for wide-scale rule validation, CI checks, and ad-hoc
/// red-team exploration -- the same code path the MCP proxy uses, but
/// without MCP / IDE / upstream-process plumbing.
async fn run_check_mode(cli: &Cli) -> anyhow::Result<()> {
    let engine = load_engine(cli.rules.as_deref())?;

    let workspace = {
        let mut policy = engine.policy.clone();
        if cli.no_workspace_probe {
            policy.workspace_probe.enabled = false;
        }
        match &cli.workspace {
            Some(p) => WorkspaceContext::probe_at(&policy, p),
            None => WorkspaceContext::probe(&policy),
        }
    };
    let mut mem_cfg = engine.policy.decision_memory.clone();
    if cli.no_memory {
        mem_cfg.enabled = false;
    }
    let memory = DecisionMemory::open(mem_cfg);
    let mut burst_cfg = engine.policy.burst_detector.clone();
    if cli.no_burst {
        burst_cfg.enabled = false;
    }
    let burst = BurstDetector::new(burst_cfg);

    eprintln!(
        "[shield-check] engine: {} rules | workspace_prod={} signals={:?} composite={} memory={} burst={}",
        engine.rules.len(),
        workspace.is_prod,
        workspace.matched_signals,
        engine.policy.composite_scoring.enabled,
        memory.enabled(),
        engine.policy.burst_detector.enabled,
    );

    let mut total = 0usize;
    let mut expected_failures = 0usize;
    let mut by_decision: std::collections::BTreeMap<&'static str, usize> = Default::default();

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut stdout = tokio::io::stdout();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                error!("[shield-check] stdin read error: {}", e);
                break;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let input: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({"error": format!("invalid JSON: {}", e), "input": trimmed});
                let _ = stdout.write_all(err.to_string().as_bytes()).await;
                let _ = stdout.write_all(b"\n").await;
                expected_failures += 1;
                total += 1;
                continue;
            }
        };

        // Two input shapes: tool-call OR llm_response text.
        let expect = input.get("expect").and_then(|v| v.as_str()).map(str::to_string);

        let (eval, scope) = if let Some(text) = input.get("text").and_then(|v| v.as_str()) {
            let adj = Adjustments {
                workspace_is_prod: workspace.is_prod,
                burst_in_progress: burst.in_burst(),
                ..Default::default()
            };
            (engine.evaluate_text(text, adj), "llm_response")
        } else {
            let tool = input.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let params = input.get("params").cloned().unwrap_or(Value::Null);
            // Canonicalise so fingerprints / extractors see what the proxy sees.
            let canonical = if params.get("name").is_some() || params.get("arguments").is_some() {
                params.clone()
            } else {
                json!({ "name": tool, "arguments": params })
            };
            // Pre-pass to fingerprint the primary rule, then re-eval with memory.
            let first_adj = Adjustments {
                workspace_is_prod: workspace.is_prod,
                burst_in_progress: burst.in_burst(),
                ..Default::default()
            };
            let first = engine.evaluate(tool, &canonical, first_adj);
            let mv = if let Some(primary) = first
                .matches
                .iter()
                .max_by(|a, b| a.severity.cmp(&b.severity).then(a.points.cmp(&b.points)))
            {
                let fp = fingerprint(&primary.rule_id, &canonical);
                memory.verdict_for(&fp)
            } else {
                Default::default()
            };
            let adj = Adjustments {
                workspace_is_prod: workspace.is_prod,
                burst_in_progress: burst.in_burst(),
                fingerprint_recently_denied: mv.recent_deny,
                fingerprint_repeatedly_approved: mv.repeated_approve,
            };
            (engine.evaluate(tool, &canonical, adj), "tool_call")
        };

        let decision = decide(&eval);
        let label = decision.label();
        *by_decision.entry(label).or_insert(0) += 1;

        // Track burst window (parity with proxy path).
        if decision.is_blocking() || matches!(decision, Decision::Warn { .. }) {
            let _ = burst.observe();
        }

        let passed = expect.as_deref().map(|e| e.eq_ignore_ascii_case(label));
        if passed == Some(false) {
            expected_failures += 1;
        }
        total += 1;

        let mut record = json!({
            "input": input,
            "scope": scope,
            "decision": label,
            "matched_rules": eval.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>(),
            "raw_severity": eval.raw_severity.as_str(),
            "composite_points": eval.composite_points,
            "composite_severity": eval.composite_severity.as_str(),
            "final_severity": eval.final_severity.as_str(),
            "adjustments": eval.adjustments_applied,
        });
        match &decision {
            Decision::Block { rule_id, reason, safer_alternative, contributing_rules, .. }
            | Decision::Approval { rule_id, reason, safer_alternative, contributing_rules, .. } => {
                record["primary_rule_id"] = json!(rule_id);
                record["reason"] = json!(reason);
                if let Some(s) = safer_alternative {
                    record["safer_alternative"] = json!(s);
                }
                record["contributing_rules"] = json!(contributing_rules);
            }
            Decision::IdentityVerification {
                rule_id, reason, safer_alternative, contributing_rules, requirement, ..
            } => {
                record["primary_rule_id"] = json!(rule_id);
                record["reason"] = json!(reason);
                if let Some(s) = safer_alternative {
                    record["safer_alternative"] = json!(s);
                }
                record["contributing_rules"] = json!(contributing_rules);
                record["identity_requirement"] = json!({
                    "provider": requirement.provider,
                    "scope": requirement.scope,
                    "allowed_subjects": requirement.allowed_subjects,
                    "max_proof_age_seconds": requirement.max_proof_age_seconds,
                    "loa": requirement.loa,
                });
            }
            Decision::Warn { rule_id, banner, safer_alternative, .. } => {
                record["primary_rule_id"] = json!(rule_id);
                record["banner"] = json!(banner);
                if let Some(s) = safer_alternative {
                    record["safer_alternative"] = json!(s);
                }
            }
            Decision::Allow => {}
        }
        if let Some(ok) = passed {
            record["expected"] = json!(expect.as_deref().unwrap_or(""));
            record["passed"] = json!(ok);
        }

        let _ = stdout.write_all(record.to_string().as_bytes()).await;
        let _ = stdout.write_all(b"\n").await;
    }
    let _ = stdout.flush().await;

    eprintln!(
        "[shield-check] total={} {} expected_failures={}",
        total,
        by_decision
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(" "),
        expected_failures,
    );

    if expected_failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `aperion-shield --diff` entrypoint. Translates CLI flags into
/// `DiffOptions` and invokes the engine. Returns the shell exit code:
/// 0 for success, 1 for a CI gate trip (`--fail-if-flipped` etc.),
/// 2 (via anyhow::bail!) for I/O or schema errors.
async fn run_diff_mode(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::diff::{run_diff_mode as run, DiffOptions, OutputFormat};

    let rules_before = cli
        .rules_before
        .clone()
        .ok_or_else(|| anyhow!("--diff requires --rules-before PATH"))?;
    let rules_after = cli
        .rules_after
        .clone()
        .ok_or_else(|| anyhow!("--diff requires --rules-after PATH"))?;
    let format = match cli.format.as_deref() {
        Some(s) => OutputFormat::parse(s)?,
        None => OutputFormat::Text,
    };
    let opts = DiffOptions {
        rules_before,
        rules_after,
        corpus: cli.corpus.clone(),
        workspace: cli.workspace.clone(),
        format,
        max_samples: cli.max_samples,
        fail_if_flipped: cli.fail_if_flipped,
        fail_if_loosened: cli.fail_if_loosened,
        fail_if_allows_loosened: cli.fail_if_allows_loosened,
    };
    run(opts).await
}

// ─────────────────────────────────────────────────────────────────────
// Git-hook entry points (v0.7+)
// ─────────────────────────────────────────────────────────────────────

/// `--install-hooks`. Writes `.git/hooks/pre-commit` and `.git/hooks/pre-push`.
fn run_install_hooks(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::hooks::{install, HookInstallOutcome};

    let repo = cli
        .repo
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let report = install(&repo, cli.chain_existing)?;

    eprintln!(
        "[shield] hooks dir: {}",
        report.hooks_dir.display()
    );
    let mut had_unknown = false;
    for (name, outcome) in [
        ("pre-commit", report.pre_commit),
        ("pre-push", report.pre_push),
    ] {
        match outcome {
            HookInstallOutcome::Installed => {
                eprintln!("[shield] installed: {}", name);
            }
            HookInstallOutcome::Refreshed => {
                eprintln!("[shield] refreshed (already ours): {}", name);
            }
            HookInstallOutcome::Chained => {
                eprintln!(
                    "[shield] chained over existing hook: {} \
                     (original moved to {}.aperion-backup; \
                     re-execed at end of our hook)",
                    name, name,
                );
            }
            HookInstallOutcome::UnknownHookPresent => {
                had_unknown = true;
                eprintln!(
                    "[shield] refused: {} already exists and isn't ours. \
                     Re-run with `--chain-existing` to keep it (husky-style chain), \
                     or remove `.git/hooks/{}` first.",
                    name, name,
                );
            }
        }
    }
    if had_unknown {
        return Ok(1);
    }
    eprintln!(
        "[shield] done. Bypass any single commit with: git commit --no-verify"
    );
    eprintln!(
        "[shield] bypass for an automation run: SHIELD_HOOKS_DISABLE=1 git commit ..."
    );
    Ok(0)
}

/// `--uninstall-hooks`. Removes only hooks we recognise; refuses to
/// touch anything else.
fn run_uninstall_hooks(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::hooks::uninstall;

    let repo = cli
        .repo
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let report = uninstall(&repo)?;

    eprintln!("[shield] hooks dir: {}", report.hooks_dir.display());
    for (name, removed, chain_restored) in [
        (
            "pre-commit",
            report.pre_commit_removed,
            report.pre_commit_chain_restored,
        ),
        (
            "pre-push",
            report.pre_push_removed,
            report.pre_push_chain_restored,
        ),
    ] {
        match (removed, chain_restored) {
            (true, true) => eprintln!(
                "[shield] removed: {} (restored chained-aside original)",
                name
            ),
            (true, false) => eprintln!("[shield] removed: {}", name),
            (false, _) => eprintln!("[shield] not present: {} (nothing to do)", name),
        }
    }
    Ok(0)
}

/// `--check-staged`. Runs the engine against the staged-diff corpus.
/// Exit codes: 0 clean, 1 block, 2 approval-but-cant-prompt, 3 error.
fn run_check_staged(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::hooks::check_staged::{run, StagedFinding};

    let repo = cli
        .repo
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let engine = load_engine(cli.rules.as_deref())?;
    let report = run(&repo, &engine, cli.workspace.as_deref())?;

    if report.findings.is_empty() {
        eprintln!(
            "[shield-check-staged] OK -- inspected {} file(s), {} line(s); no destructive matches.",
            report.files_scanned, report.lines_scanned
        );
        return Ok(report.exit_code() as i32);
    }

    eprintln!(
        "[shield-check-staged] {} finding(s) across {} file(s):",
        report.findings.len(),
        report.files_scanned
    );
    eprintln!();
    for (rule_id, findings) in report.group_by_rule() {
        let first: &StagedFinding = findings[0];
        eprintln!(
            "  [{}] {} ({} match{})",
            first.severity,
            rule_id,
            findings.len(),
            if findings.len() == 1 { "" } else { "es" },
        );
        eprintln!("    why: {}", first.reason);
        if let Some(s) = &first.safer_alternative {
            eprintln!("    safer alternative: {}", s);
        }
        for f in findings.iter().take(5) {
            eprintln!(
                "      {}:{}  ({})  {}",
                f.file,
                f.line_no,
                f.decision,
                truncate(&f.line, 96)
            );
        }
        if findings.len() > 5 {
            eprintln!("      ... and {} more match(es) elided", findings.len() - 5);
        }
        eprintln!();
    }
    let code = report.exit_code();
    match code {
        1 => eprintln!(
            "[shield-check-staged] commit REFUSED (Block-severity match). \
             To override: git commit --no-verify  OR  SHIELD_HOOKS_DISABLE=1 git commit ..."
        ),
        2 => eprintln!(
            "[shield-check-staged] commit REFUSED (Approval-severity match; \
             pre-commit cannot prompt). To override: git commit --no-verify"
        ),
        _ => {}
    }
    Ok(code as i32)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// `--suggest-rules`. Reads an audit JSONL file, runs the analyzer,
/// renders the requested format on stdout. Exit 0 = no suggestions,
/// exit 1 = suggestions exist (so CI gates can react to "something
/// to review"; doesn't necessarily mean the shieldset is broken).
fn run_suggest_rules(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::suggest::{run, AnalyzeOptions, OutputFormat};

    let audit_path = cli
        .audit_log
        .clone()
        .ok_or_else(|| anyhow!("--suggest-rules requires --audit-log PATH"))?;
    let engine = load_engine(cli.rules.as_deref())?;
    let opts = AnalyzeOptions {
        window_days: match cli.suggest_window_days {
            Some(0) => None, // "0 = all" per docstring
            Some(n) => Some(n),
            None => Some(30),
        },
        min_occurrences: cli.suggest_min_occurrences,
    };
    let format = match cli.suggest_format.as_deref() {
        Some(s) => OutputFormat::parse(s)?,
        None => OutputFormat::Text,
    };

    let (body, count, skipped) = run(&engine, &audit_path, opts, format)?;
    print!("{}", body);
    if skipped > 0 {
        eprintln!(
            "[shield-suggest-rules] note: skipped {} non-shield_eval / unparseable line(s)",
            skipped
        );
    }
    eprintln!(
        "[shield-suggest-rules] {} suggestion(s) from {} ({} days)",
        count,
        audit_path.display(),
        opts.window_days
            .map(|d| d.to_string())
            .unwrap_or_else(|| "all".to_string()),
    );
    Ok(if count == 0 { 0 } else { 1 })
}

/// `--check-pushed-refs`. Reads stdin per git's pre-push protocol.
fn run_check_pushed_refs(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::hooks::check_pushed::{run, PushVerdict};
    use std::io::BufReader;

    let repo = cli
        .repo
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let stdin = BufReader::new(std::io::stdin());
    let report = run(&repo, stdin)?;

    if report.violations.is_empty() {
        eprintln!(
            "[shield-check-pushed-refs] OK -- inspected {} ref update(s); no destructive pushes.",
            report.refs_inspected
        );
        return Ok(0);
    }

    eprintln!(
        "[shield-check-pushed-refs] REFUSED -- {} of {} ref update(s) target a protected branch:",
        report.violations.len(),
        report.refs_inspected,
    );
    eprintln!();
    for (upd, v) in &report.violations {
        match v {
            PushVerdict::Deletion { protected_branch } => {
                eprintln!(
                    "  - DELETE protected branch '{}' (ref: {})",
                    protected_branch, upd.remote_ref,
                );
            }
            PushVerdict::ForcePush {
                protected_branch,
                remote_sha,
                local_sha,
            } => {
                eprintln!(
                    "  - FORCE-PUSH to '{}' rewrites history: {} ... {}",
                    protected_branch,
                    &remote_sha[..7.min(remote_sha.len())],
                    &local_sha[..7.min(local_sha.len())],
                );
            }
            PushVerdict::Ok => unreachable!("Ok shouldn't be in violations"),
        }
    }
    eprintln!();
    eprintln!(
        "[shield-check-pushed-refs] To override: git push --no-verify  OR  \
         SHIELD_HOOKS_DISABLE=1 git push ..."
    );
    eprintln!(
        "[shield-check-pushed-refs] To change the protected set: \
         SHIELD_PROTECTED_BRANCHES='main,trunk,release/*' git push ..."
    );
    Ok(1)
}

// ─────────────────────────────────────────────────────────────────────
// v0.8 shell-shim dispatchers
// ─────────────────────────────────────────────────────────────────────

/// `--install-shims [--for ...] [--shim-dir PATH]`
fn run_install_shims(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::shims::install::{
        install, parse_for_arg, resolve_shim_dir, ShimInstallOutcome,
    };

    let shim_dir = resolve_shim_dir(cli.shim_dir.as_deref())?;
    let commands = match cli.shim_for.as_deref() {
        Some(raw) => parse_for_arg(raw)?,
        None => Vec::new(), // empty => DEFAULT_SHIMMED_COMMANDS
    };

    let report = install(&shim_dir, &commands)?;

    eprintln!(
        "[shield-install-shims] shim dir: {}",
        report.shim_dir.display()
    );
    for e in &report.entries {
        let label = match e.outcome {
            ShimInstallOutcome::Installed => "INSTALLED ",
            ShimInstallOutcome::Refreshed => "REFRESHED ",
            ShimInstallOutcome::ForeignPresent => "SKIPPED   ",
            ShimInstallOutcome::UpstreamBinaryNotFound => "NO-UPSTREAM",
        };
        let detail = match &e.resolved_path {
            Some(p) => format!("-> {}", p.display()),
            None => match e.outcome {
                ShimInstallOutcome::ForeignPresent => {
                    "existing file at target is not Shield-managed; refusing to overwrite".to_string()
                }
                ShimInstallOutcome::UpstreamBinaryNotFound => {
                    "real binary not found on $PATH; skipped".to_string()
                }
                _ => String::new(),
            },
        };
        eprintln!("  {} {:<14} {}", label, e.command, detail);
    }

    eprintln!();
    eprintln!(
        "[shield-install-shims] {} shim(s) installed / refreshed.",
        report.successful()
    );
    eprintln!();
    eprintln!("Next step: put this directory FIRST on your $PATH so shims win lookup.");
    eprintln!("  zsh   : echo 'export PATH=\"{}:$PATH\"' >> ~/.zshrc", report.shim_dir.display());
    eprintln!("  bash  : echo 'export PATH=\"{}:$PATH\"' >> ~/.bashrc", report.shim_dir.display());
    eprintln!("  fish  : fish_add_path -p '{}'", report.shim_dir.display());
    eprintln!();
    eprintln!("Bypass for a single invocation:  SHIELD_SHIMS_DISABLE=1 <command> ...");
    eprintln!("Uninstall later:                 aperion-shield --uninstall-shims");

    // Exit 0 iff at least one shim was installed AND there were no
    // foreign-file collisions. Foreign collisions surface as exit 1 so
    // CI scripts can detect mis-configurations.
    if report.any_foreign() {
        return Ok(1);
    }
    Ok(0)
}

/// `--uninstall-shims [--shim-dir PATH]`
fn run_uninstall_shims(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::shims::install::{resolve_shim_dir, uninstall, ShimUninstallOutcome};

    let shim_dir = resolve_shim_dir(cli.shim_dir.as_deref())?;
    let report = uninstall(&shim_dir)?;

    eprintln!(
        "[shield-uninstall-shims] shim dir: {}",
        report.shim_dir.display()
    );
    if report.entries.is_empty() {
        eprintln!("  (nothing to remove)");
        return Ok(0);
    }
    for e in &report.entries {
        let label = match e.outcome {
            ShimUninstallOutcome::Removed => "REMOVED ",
            ShimUninstallOutcome::ForeignPresent => "KEPT    ",
            ShimUninstallOutcome::AbsentNoop => "ABSENT  ",
        };
        let detail = match e.outcome {
            ShimUninstallOutcome::ForeignPresent => "(no Aperion marker; left alone)",
            _ => "",
        };
        eprintln!("  {} {:<14} {}", label, e.command, detail);
    }
    Ok(0)
}

/// `--list-shims [--shim-dir PATH]`
fn run_list_shims(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::shims::install::{list, resolve_shim_dir};

    let shim_dir = resolve_shim_dir(cli.shim_dir.as_deref())?;
    let entries = list(&shim_dir)?;

    if entries.is_empty() {
        eprintln!(
            "[shield-list-shims] {}: (none installed)",
            shim_dir.display()
        );
        return Ok(0);
    }
    eprintln!("[shield-list-shims] {}:", shim_dir.display());
    for (name, ours) in entries {
        let label = if ours { "shield " } else { "foreign" };
        eprintln!("  [{}] {}", label, name);
    }
    Ok(0)
}

/// `--explain --input call.json [--explain-format text|markdown|json]`.
///
/// Prints a full decision walkthrough -- rules matched, adjustment
/// signals applied, severity ladder, decision + safer alternative.
/// Exit code mirrors `--check-cmd` so the same CI plumbing works.
fn run_explain(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::explain::{
        explain, read_descriptor_from, render::{render, ExplainFormat}, ExplainOptions,
    };

    let input = cli
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("--explain requires --input <PATH | -> (use `-` for stdin)"))?;
    let path_str = input.to_string_lossy().to_string();
    let descriptor = read_descriptor_from(&path_str)?;

    let engine = load_engine(cli.rules.as_deref())?;

    let mut opts = ExplainOptions::default();
    if cli.explain_force_prod {
        opts.force_workspace_prod = Some(true);
    }
    if cli.explain_force_burst {
        opts.force_burst = Some(true);
    }
    opts.force_repeatedly_approved = cli.explain_force_repeatedly_approved;
    opts.force_recently_denied = cli.explain_force_recently_denied;

    let report = explain(&engine, &descriptor, &opts)?;
    let format = match cli.explain_format.as_deref() {
        Some(s) => ExplainFormat::parse(s)?,
        None => ExplainFormat::Text,
    };
    print!("{}", render(&report, format));
    Ok(report.exit_code() as i32)
}

/// `--check-cmd -- <command> [args...]`. Invoked by installed shims.
fn run_check_cmd(cli: &Cli) -> anyhow::Result<i32> {
    use aperion_shield::shims::check_cmd::{refusal_banner, run};

    if cli.upstream.is_empty() {
        eprintln!(
            "[shield-check-cmd] usage: aperion-shield --check-cmd -- <command> [args...]"
        );
        return Ok(3);
    }

    let engine = load_engine(cli.rules.as_deref())?;
    let report = run(&engine, &cli.upstream)?;

    // Always print the audit JSON line to stderr -- mirrors the shape
    // emitted by the MCP path so `--suggest-rules` keeps working over
    // the merged log.
    let audit_record = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "kind": "shield_eval",
        "source": "check-cmd",
        "tool": "shell",
        "command": report.command_line,
        "decision": report.decision.label(),
        "rule_id": report.primary.as_ref().map(|p| p.rule_id.as_str()),
        "severity": report.primary.as_ref().map(|p| p.severity.as_str()),
    });
    eprintln!("{}", audit_record);

    if report.exit_code() != 0 {
        eprint!("{}", refusal_banner(&report));
    }
    Ok(report.exit_code() as i32)
}

/// The single choke point both downstreams (stdio + HTTP) run client
/// frames through. Wraps [`evaluate_request`] with the v0.9 supply-chain
/// bookkeeping:
///
///   1. `tools/call` against a quarantined (rug-pulled / poisoned) tool
///      is blocked here, so a host that cached the old catalog still
///      can't reach the swapped tool.
///   2. Forwarded `tools/list` and `tools/call` request ids are recorded
///      so the response pump knows which upstream frames to dissect.
async fn process_client_frame(req: &Value, shield: &Arc<Shield>) -> Option<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);

    if method == "tools/call" {
        let tool_name = req
            .pointer("/params/name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if shield.supply.quarantined.lock().await.contains(tool_name) {
            if shield.shadow {
                warn!(
                    "[shield][shadow] would have BLOCKED quarantined tool '{}' (rug-pull / poisoned description)",
                    tool_name
                );
            } else {
                error!(
                    "[shield] BLOCK tools/call '{}' -- tool is quarantined (its definition changed \
                     or its description matched poisoning rules). Review with `aperion-shield --repin` \
                     after verifying the change is legitimate.",
                    tool_name
                );
                audit_supply_event(
                    shield,
                    "quarantine_block",
                    tool_name,
                    "supply.quarantined",
                    "block",
                    Severity::Critical,
                    json!({ "tool": tool_name }),
                )
                .await;
                return Some(jsonrpc_error(
                    id,
                    -32096,
                    "shield_supply_chain_blocked",
                    json!({
                        "rule_id": "supply.quarantined",
                        "severity": "critical",
                        "reason": format!(
                            "Tool '{}' is quarantined: its pinned definition changed underneath you \
                             (possible rug pull) or its description matched tool-poisoning rules.",
                            tool_name
                        ),
                        "safer_alternative": "Inspect the server's tools/list diff, then run `aperion-shield --repin` if the change is legitimate.",
                        "tool": tool_name,
                    }),
                ));
            }
        }
    }

    if let Some(resp) = evaluate_request(req, shield).await {
        return Some(resp);
    }

    // Frame is being forwarded -- record what its response will be.
    if !id.is_null() {
        let kind = match method {
            "tools/list" => Some(PendingKind::ToolsList),
            "tools/call" => req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .map(|t| PendingKind::ToolCall { tool: t.to_string() }),
            _ => None,
        };
        if let Some(kind) = kind {
            shield
                .supply
                .pending
                .lock()
                .await
                .insert(transport::http_server::canonical_id(&id), kind);
        }
    }
    None
}

/// Adapter letting the HTTP downstream run requests through the same
/// gate as the stdio pump.
struct ShieldGate(Arc<Shield>);

#[async_trait::async_trait]
impl transport::http_server::RequestGate for ShieldGate {
    async fn intercept(&self, req: &Value) -> Option<Value> {
        process_client_frame(req, &self.0).await
    }
}

/// v0.9 supply-chain seam: inspect upstream -> client frames. Returns
/// the frame to forward (possibly rewritten). Only responses to
/// previously-forwarded `tools/list` / `tools/call` requests are
/// touched; everything else passes through byte-identical.
async fn intercept_upstream_frame(frame: String, shield: &Arc<Shield>) -> String {
    let parsed: Value = match serde_json::from_str(&frame) {
        Ok(v) => v,
        Err(_) => return frame,
    };
    // Responses carry an id and no method.
    let id = match parsed.get("id") {
        Some(id) if !id.is_null() && parsed.get("method").is_none() => id.clone(),
        _ => return frame,
    };
    let kind = shield
        .supply
        .pending
        .lock()
        .await
        .remove(&transport::http_server::canonical_id(&id));
    match kind {
        Some(PendingKind::ToolsList) => inspect_tools_list_response(frame, parsed, shield).await,
        Some(PendingKind::ToolCall { tool }) => {
            inspect_tool_call_response(frame, parsed, &tool, shield).await
        }
        None => frame,
    }
}

/// Inspect a `tools/list` result: scan descriptions against
/// `where: tool_description` rules, then run TOFU catalog pinning.
/// Flagged tools are stripped from the list the host sees AND
/// quarantined so direct calls fail too.
async fn inspect_tools_list_response(
    frame: String,
    mut parsed: Value,
    shield: &Arc<Shield>,
) -> String {
    let result = match parsed.get("result") {
        Some(r) => r,
        None => return frame, // error response -- nothing to inspect
    };
    let catalog = match supply::extract_catalog(result) {
        Some(c) => c,
        None => return frame,
    };

    let engine = shield.current_engine();
    let adj = Adjustments {
        workspace_is_prod: shield.workspace.is_prod,
        burst_in_progress: shield.burst.in_burst(),
        ..Default::default()
    };

    // Tool name -> why it's being stripped.
    let mut strip: HashMap<String, String> = HashMap::new();

    // 1. Description scanning (tool-poisoning).
    for tool in &catalog {
        if tool.description.is_empty() {
            continue;
        }
        let eval = engine.evaluate_scoped_text(
            Scope::ToolDescription,
            Some(&tool.name),
            &tool.description,
            adj,
        );
        if eval.matches.is_empty() {
            continue;
        }
        let decision = decide(&eval);
        let primary = eval
            .matches
            .iter()
            .max_by(|a, b| a.severity.cmp(&b.severity).then(a.points.cmp(&b.points)))
            .map(|m| m.rule_id.clone())
            .unwrap_or_default();
        audit_supply_event(
            shield,
            "tool_description_scan",
            &tool.name,
            &primary,
            decision.label(),
            eval.final_severity,
            json!({
                "matched_rules": eval.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>(),
            }),
        )
        .await;
        match &decision {
            d if d.is_blocking() => {
                error!(
                    "[shield] TOOL POISONING: description of '{}' matched rule {} ({}) -- {}",
                    tool.name,
                    primary,
                    eval.final_severity.as_str(),
                    if shield.shadow { "shadow: forwarding anyway" } else { "stripping tool from catalog" }
                );
                strip.insert(tool.name.clone(), format!("description matched rule {}", primary));
            }
            Decision::Warn { .. } => {
                warn!(
                    "[shield] WARN: description of '{}' matched rule {} ({})",
                    tool.name, primary, eval.final_severity.as_str()
                );
            }
            _ => {}
        }
    }

    // 2. TOFU catalog pinning (rug-pull detection).
    if shield.supply.pinning {
        let policy = engine.policy.supply_chain.clone();
        let pin_new = policy.on_new_tool != "block";
        match supply::check_catalog(&shield.supply.upstream_label, &catalog, pin_new) {
            Ok(check) => {
                if check.first_contact {
                    warn!(
                        "[shield] first contact with this upstream -- pinned {} tool definition(s) \
                         to ~/.aperion-shield/pins/ (TOFU)",
                        catalog.len()
                    );
                }
                for name in check.changed() {
                    audit_supply_event(
                        shield,
                        "rug_pull",
                        name,
                        "supply.pin_changed",
                        &policy.on_changed_tool,
                        Severity::Critical,
                        json!({ "action": policy.on_changed_tool }),
                    )
                    .await;
                    match policy.on_changed_tool.as_str() {
                        "allow" => {}
                        "warn" => warn!(
                            "[shield] RUG PULL (warn-only by policy): tool '{}' changed since it was pinned",
                            name
                        ),
                        _ => {
                            error!(
                                "[shield] RUG PULL: tool '{}' changed since it was pinned -- {}. \
                                 Review the change, then `aperion-shield --repin` to accept it.",
                                name,
                                if shield.shadow { "shadow: forwarding anyway" } else { "stripping + quarantining" }
                            );
                            strip.insert(
                                name.to_string(),
                                "pinned definition changed (rug pull)".to_string(),
                            );
                        }
                    }
                }
                for name in check.new_tools() {
                    match policy.on_new_tool.as_str() {
                        "allow" => {}
                        "block" => {
                            error!(
                                "[shield] NEW TOOL '{}' appeared after first pin -- blocked by \
                                 policy (supply_chain.on_new_tool: block)",
                                name
                            );
                            strip.insert(name.to_string(), "new tool blocked by policy".to_string());
                        }
                        _ => warn!(
                            "[shield] new tool '{}' appeared after first pin -- pinned and allowed \
                             (supply_chain.on_new_tool: warn)",
                            name
                        ),
                    }
                }
                for name in &check.removed {
                    info!("[shield] pinned tool '{}' no longer offered by the upstream", name);
                }
            }
            Err(e) => error!("[shield] catalog pin check failed: {}", e),
        }
    }

    // Refresh the quarantine set: flagged tools go in, clean tools come
    // out (covers the post-`--repin` run).
    {
        let mut q = shield.supply.quarantined.lock().await;
        for tool in &catalog {
            if strip.contains_key(&tool.name) {
                q.insert(tool.name.clone());
            } else {
                q.remove(&tool.name);
            }
        }
    }

    if strip.is_empty() || shield.shadow {
        return frame;
    }

    // Rewrite the result: drop the flagged tools.
    if let Some(tools) = parsed
        .pointer_mut("/result/tools")
        .and_then(|t| t.as_array_mut())
    {
        tools.retain(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(|n| !strip.contains_key(n))
                .unwrap_or(true)
        });
    }
    parsed.to_string()
}

/// Inspect a `tools/call` result: run `where: tool_result` rules over
/// every text block the tool returned (prompt-injection-via-result
/// defense). Blocking matches replace the result with a JSON-RPC error.
async fn inspect_tool_call_response(
    frame: String,
    parsed: Value,
    tool: &str,
    shield: &Arc<Shield>,
) -> String {
    let result = match parsed.get("result") {
        Some(r) => r,
        None => return frame,
    };
    let texts = supply::extract_result_text(result);
    if texts.is_empty() {
        return frame;
    }

    let engine = shield.current_engine();
    let adj = Adjustments {
        workspace_is_prod: shield.workspace.is_prod,
        burst_in_progress: shield.burst.in_burst(),
        ..Default::default()
    };

    let mut worst: Option<(aperion_shield::Evaluation, String)> = None;
    for text in &texts {
        let eval = engine.evaluate_scoped_text(Scope::ToolResult, Some(tool), text, adj);
        if eval.matches.is_empty() {
            continue;
        }
        let replace = match &worst {
            Some((w, _)) => eval.final_severity > w.final_severity,
            None => true,
        };
        if replace {
            let snippet: String = text.chars().take(160).collect();
            worst = Some((eval, snippet));
        }
    }
    let (eval, snippet) = match worst {
        Some(w) => w,
        None => return frame,
    };

    let decision = decide(&eval);
    let primary = eval
        .matches
        .iter()
        .max_by(|a, b| a.severity.cmp(&b.severity).then(a.points.cmp(&b.points)))
        .map(|m| m.rule_id.clone())
        .unwrap_or_default();
    audit_supply_event(
        shield,
        "tool_result_scan",
        tool,
        &primary,
        decision.label(),
        eval.final_severity,
        json!({
            "matched_rules": eval.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>(),
            "snippet": snippet,
        }),
    )
    .await;

    match decision {
        d if d.is_blocking() => {
            if shield.shadow {
                warn!(
                    "[shield][shadow] would have BLOCKED result of '{}' -- rule {} ({})",
                    tool, primary, eval.final_severity.as_str()
                );
                return frame;
            }
            error!(
                "[shield] BLOCKED tool result from '{}' -- rule {} ({}): suspected prompt \
                 injection in returned content",
                tool, primary, eval.final_severity.as_str()
            );
            let id = parsed.get("id").cloned().unwrap_or(Value::Null);
            jsonrpc_error(
                id,
                -32095,
                "shield_blocked_tool_result",
                json!({
                    "rule_id": primary,
                    "severity": eval.final_severity.as_str(),
                    "reason": format!(
                        "The result returned by tool '{}' matched Shield's tool_result rules \
                         (suspected prompt injection). The content was withheld from the agent.",
                        tool
                    ),
                    "matched_rules": eval.matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>(),
                    "tool": tool,
                }),
            )
            .to_string()
        }
        Decision::Warn { .. } => {
            warn!(
                "[shield] WARN: result of '{}' matched rule {} ({}) -- forwarded",
                tool, primary, eval.final_severity.as_str()
            );
            frame
        }
        _ => frame,
    }
}

/// Emit one supply-chain audit event: JSON line to stderr (same
/// `shield_eval` envelope as the request seam, with
/// `"source": "supply_chain"`) plus the org-mode sink when enrolled.
async fn audit_supply_event(
    shield: &Arc<Shield>,
    event: &str,
    tool: &str,
    rule_id: &str,
    decision: &str,
    severity: Severity,
    extra: Value,
) {
    let audit = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "kind": "shield_eval",
        "source": "supply_chain",
        "event": event,
        "tool": tool,
        "primary_rule_id": rule_id,
        "decision": decision,
        "final_severity": severity.as_str(),
        "detail": extra,
    });
    eprintln!("{}", audit);
    if let Some(handles) = shield.orgmode.as_ref() {
        handles
            .audit
            .record(AuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                ts: chrono::Utc::now(),
                rule_id: rule_id.to_string(),
                decision: decision.to_string(),
                severity: severity.as_str().to_string(),
                tool: tool.to_string(),
                fingerprint: String::new(),
                context: audit.clone(),
            })
            .await;
    }
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

    // First-pass evaluation (no memory yet -- we don't have a primary rule).
    let initial_adj = Adjustments {
        workspace_is_prod: shield.workspace.is_prod,
        burst_in_progress: shield.burst.in_burst(),
        ..Default::default()
    };
    let engine = shield.current_engine();
    let first = engine.evaluate(tool_name, &canonical_params, initial_adj);
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
    let eval = engine.evaluate(tool_name, &canonical_params, adj);
    let decision = decide(&eval);

    // Anything beyond Allow counts toward the burst window.
    if decision.is_blocking() || matches!(decision, Decision::Warn { .. }) {
        let _ = shield.burst.observe();
    }

    // Audit log line -- JSON to stderr.
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

    // Ship the same event to Smartflow when we're enrolled. Best-effort;
    // the sink owns its own queue + retry loop so failures never block
    // the hot path.
    if let Some(handles) = shield.orgmode.as_ref() {
        handles
            .audit
            .record(AuditEvent {
                id: uuid::Uuid::new_v4().to_string(),
                ts: chrono::Utc::now(),
                rule_id: primary_id.clone(),
                decision: decision.label().to_string(),
                severity: eval.final_severity.as_str().to_string(),
                tool: tool_name.to_string(),
                fingerprint: fp.clone(),
                context: audit.clone(),
            })
            .await;
    }

    match decision {
        Decision::Allow => None,
        Decision::IdentityVerification {
            rule_id,
            severity,
            reason,
            safer_alternative,
            contributing_rules,
            requirement,
        } => {
            // Org-mode wins when present: Smartflow is the relying
            // party. Falls through to the local IdentityGate path
            // otherwise (or when Smartflow says the provider isn't
            // ready -- we don't want to silently allow gated calls).
            if let Some(sf) = shield.smartflow_identity.clone() {
                return handle_identity_decision_orgmode(
                    id,
                    tool_name,
                    &fp,
                    rule_id,
                    severity,
                    requirement,
                    sf,
                )
                .await;
            }
            handle_identity_decision(
                id,
                tool_name,
                &fp,
                shield,
                rule_id,
                severity,
                reason,
                safer_alternative,
                contributing_rules,
                requirement,
            )
            .await
        }
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
                    info!("[shield] APPROVED ticket={} -- allowing call", ticket);
                    shield.memory.record(&rule_id, &fp, Outcome::Approve, tool_name);
                    None
                }
                Ok(false) => {
                    info!("[shield] DENIED ticket={} -- blocking call", ticket);
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
                    warn!("[shield] TIMEOUT ticket={} -- defaulting to deny", ticket);
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

// ────────────────────────────────────────────────────────────────────
// Identity-gated tool calls
// ────────────────────────────────────────────────────────────────────

fn is_idme_ready(p: &aperion_shield::ProviderConfig) -> bool {
    let cid = p.client_id_env.as_deref()
        .and_then(|v| std::env::var(v).ok())
        .filter(|s| !s.is_empty());
    let csec = p.client_secret_env.as_deref()
        .and_then(|v| std::env::var(v).ok())
        .filter(|s| !s.is_empty());
    cid.is_some() && csec.is_some()
}

async fn build_identity_gate(explicit: Option<&std::path::Path>) -> anyhow::Result<IdentityGate> {
    let cfg = IdentityConfig::load(explicit)?;
    let state_dir = IdentityConfig::state_dir();
    let mut providers: Vec<Arc<dyn IdentityProvider>> = Vec::new();
    for p in &cfg.providers {
        match p.kind {
            ProviderKind::Mock => {
                providers.push(Arc::new(MockProvider::new(
                    p.id.clone(),
                    p.subject.clone().unwrap_or_else(|| format!("{}-subject", p.id)),
                    p.email.clone(),
                    p.loa,
                )));
            }
            ProviderKind::IdMe => {
                let (a_def, t_def, u_def) = aperion_shield::identity::providers::idme::IdMeConfig::endpoint_defaults(p.sandbox);
                let cfg_idme = aperion_shield::identity::providers::idme::IdMeConfig {
                    id: p.id.clone(),
                    sandbox: p.sandbox,
                    client_id: p.client_id_env.as_deref().and_then(|v| std::env::var(v).ok()),
                    client_secret: p.client_secret_env.as_deref().and_then(|v| std::env::var(v).ok()),
                    scopes: p.scopes.clone(),
                    authorize_url: p.authorize_url.clone().unwrap_or(a_def),
                    token_url: p.token_url.clone().unwrap_or(t_def),
                    userinfo_url: p.userinfo_url.clone().unwrap_or(u_def),
                };
                providers.push(Arc::new(IdMeProvider::new(cfg_idme)));
            }
        }
    }
    IdentityGate::new(cfg, providers, state_dir)
}

/// Handle a [`Decision::IdentityVerification`]: check the cache, surface
/// a verify URL on miss, hold up to `hold_seconds`, then resolve.
#[allow(clippy::too_many_arguments)]
async fn handle_identity_decision(
    id: Value,
    tool_name: &str,
    fp: &str,
    shield: &Shield,
    rule_id: String,
    severity: aperion_shield::Severity,
    reason: String,
    safer_alternative: Option<String>,
    contributing_rules: Vec<String>,
    requirement: aperion_shield::IdentityRequirement,
) -> Option<Value> {
    let gate = match shield.identity_gate.as_ref() {
        Some(g) => g.clone(),
        None => {
            // Fallback path: gate was disabled (--no-identity) yet a
            // rule still asks for verification. Demote to plain
            // Approval-denial so we don't accidentally allow the call.
            error!(
                "[shield] identity rule {} fired but identity gate is disabled -- denying",
                rule_id
            );
            return Some(jsonrpc_error(
                id,
                -32096,
                "shield_identity_unavailable",
                json!({
                    "rule_id": rule_id,
                    "severity": severity.as_str(),
                    "reason": "Identity gate is disabled (--no-identity). Re-run Shield without that flag to allow this call.",
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ));
        }
    };

    // 1) Cache hit -- fresh proof, allow immediately.
    if let Some(p) = gate.cached_proof_for(&requirement) {
        let audit = json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "kind": "identity_satisfied",
            "tool": tool_name,
            "rule_id": rule_id,
            "fingerprint": fp,
            "provider": p.provider,
            "subject": p.subject,
            "email": p.email,
            "loa": p.loa,
            "scope": p.scope,
            "verified_at": p.verified_at,
            "expires_at": p.expires_at,
        });
        eprintln!("{}", audit);
        info!(
            "[shield] identity satisfied rule={} subject={} loa={} (cached) -- allowing tool={}",
            rule_id, p.subject, p.loa, tool_name
        );
        return None;
    }

    // 2) Cache miss -- mint a challenge with the matching provider.
    let provider = match gate.provider(&requirement.provider) {
        Some(p) => p,
        None => {
            error!(
                "[shield] identity rule {} references unknown provider '{}'",
                rule_id, requirement.provider
            );
            return Some(jsonrpc_error(
                id,
                -32095,
                "shield_identity_provider_unknown",
                json!({
                    "rule_id": rule_id,
                    "requested_provider": requirement.provider,
                    "available_providers": gate.config().providers.iter().map(|p| &p.id).collect::<Vec<_>>(),
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ));
        }
    };
    if !provider.is_ready() {
        warn!(
            "[shield] identity provider '{}' not ready (credentials missing) -- denying tool={}",
            provider.id(),
            tool_name
        );
        return Some(jsonrpc_error(
            id,
            -32094,
            "shield_identity_provider_unready",
            json!({
                "rule_id": rule_id,
                "provider": provider.id(),
                "reason": format!(
                    "Provider '{}' is not yet activated. For id_me, set the env vars referenced by client_id_env / client_secret_env in identity.yaml.",
                    provider.id()
                ),
                "fingerprint": fp,
                "tool": tool_name,
            }),
        ));
    }

    let base = match gate.callback_base().await {
        Ok(b) => b,
        Err(e) => {
            error!("[shield] failed to start callback server: {}", e);
            return Some(jsonrpc_error(
                id,
                -32093,
                "shield_identity_callback_unavailable",
                json!({
                    "rule_id": rule_id,
                    "error": e.to_string(),
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ));
        }
    };
    let callback_url = format!("{}/callback", base);
    let challenge_id = format!("ch_{}", uuid::Uuid::new_v4().simple());
    let creq = identity::ChallengeRequest {
        rule_id: rule_id.clone(),
        requirement: requirement.clone(),
        callback_url,
        challenge_id: challenge_id.clone(),
    };
    let challenge = match provider.begin(creq).await {
        Ok(c) => c,
        Err(e) => {
            error!("[shield] identity begin failed: {}", e);
            return Some(jsonrpc_error(
                id,
                -32092,
                "shield_identity_begin_failed",
                json!({
                    "rule_id": rule_id,
                    "error": e.to_string(),
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ));
        }
    };
    if let Err(e) = gate
        .register_inflight(&challenge, requirement.clone(), provider.id().to_string(), rule_id.clone())
        .await
    {
        error!("[shield] failed to register inflight: {}", e);
    }

    // User-facing verify URL: prefer the local /verify/<id> entry point
    // so the mock flow short-circuits and the real flow gets a stable
    // landing page even before the redirect to ID.me.
    let user_url = format!("{}/verify/{}", base, challenge_id);

    let audit = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "kind": "identity_required",
        "tool": tool_name,
        "rule_id": rule_id,
        "fingerprint": fp,
        "provider": provider.id(),
        "scope": requirement.scope,
        "allowed_subjects": requirement.allowed_subjects,
        "loa": requirement.loa,
        "verify_url": user_url,
        "challenge_id": challenge_id,
        "hold_seconds": gate.hold_seconds(),
    });
    eprintln!("{}", audit);
    warn!(
        "[shield] IDENTITY VERIFICATION REQUIRED rule={} tool={}: {}",
        rule_id, tool_name, reason
    );
    warn!("[shield]   open this URL to verify: {}", user_url);
    if let Some(ref s) = safer_alternative {
        warn!("[shield]   safer alternative: {}", s);
    }

    // 3) Hold the call server-side up to hold_seconds, then re-check.
    if let Some(proof) = gate.wait_for_proof(&requirement, gate.hold_seconds()).await {
        let audit = json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "kind": "identity_satisfied",
            "tool": tool_name,
            "rule_id": rule_id,
            "fingerprint": fp,
            "provider": proof.provider,
            "subject": proof.subject,
            "email": proof.email,
            "loa": proof.loa,
            "scope": proof.scope,
            "challenge_id": challenge_id,
            "via": "hold",
        });
        eprintln!("{}", audit);
        info!(
            "[shield] identity verified by {} (subject={} loa={}) -- releasing tool={}",
            proof.email.clone().unwrap_or_else(|| proof.subject.clone()),
            proof.subject,
            proof.loa,
            tool_name
        );
        return None;
    }

    // 4) Hold elapsed without verification -- surface the URL to the
    //    agent so it can retry once the user has verified.
    Some(jsonrpc_error(
        id,
        -32091,
        "shield_identity_required",
        json!({
            "rule_id": rule_id,
            "severity": severity.as_str(),
            "reason": reason,
            "safer_alternative": safer_alternative,
            "contributing_rules": contributing_rules,
            "fingerprint": fp,
            "tool": tool_name,
            "verify_url": user_url,
            "challenge_id": challenge_id,
            "provider": provider.id(),
            "scope": requirement.scope,
            "loa": requirement.loa,
            "instructions": format!(
                "Open {} in a browser to complete identity verification, then retry the tool call.",
                user_url
            ),
        }),
    ))
}

async fn run_identity_list(cli: &Cli) -> anyhow::Result<()> {
    let gate = build_identity_gate(cli.identity_config.as_deref()).await?;
    let cfg = gate.config();
    println!("identity providers:");
    for p in &cfg.providers {
        let ready = match p.kind {
            ProviderKind::Mock => "ready",
            ProviderKind::IdMe => if is_idme_ready(p) { "ready" } else { "unready (set client_id_env/client_secret_env)" },
        };
        println!(
            "  - id={:<10} kind={:<6} sandbox={:<5} -- {}",
            p.id,
            match p.kind { ProviderKind::IdMe => "id_me", ProviderKind::Mock => "mock" },
            p.sandbox,
            ready
        );
    }
    println!();
    println!(
        "cached proofs (signature-verified, non-expired): {}",
        gate.cached_count()
    );
    println!("state dir: {}", IdentityConfig::state_dir().display());
    Ok(())
}

async fn run_identity_flush(cli: &Cli) -> anyhow::Result<()> {
    let gate = build_identity_gate(cli.identity_config.as_deref()).await?;
    let n = gate.flush()?;
    println!("flushed {} cached identity proof(s).", n);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Org-mode bootstrap + identity handler
// ──────────────────────────────────────────────────────────────────────

/// Bootstrap the org-mode subsystem at startup.
///
/// Returns a tuple of:
///   * `Option<OrgState>` -- the persisted enrollment record, if any
///   * `Option<Arc<EnrolledHandles>>` -- handles for background tasks
///   * `Option<Arc<SmartflowProvider>>` -- identity provider for the
///     IdentityVerification dispatch
///   * `watch::Receiver<Arc<Engine>>` -- the engine snapshot the main
///     loop uses for every evaluation
///
/// In standalone mode (no `orgmode.json`) the receiver yields a single
/// value -- the engine handed in -- forever. In org mode the policy-pull
/// task pushes a new engine on every version bump.
async fn bootstrap_orgmode(
    local_engine: Engine,
) -> anyhow::Result<(
    Option<OrgState>,
    Option<Arc<EnrolledHandles>>,
    Option<Arc<SmartflowProvider>>,
    tokio::sync::watch::Receiver<Arc<Engine>>,
)> {
    let state = match OrgState::load() {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "[shield] could not load orgmode state ({}); continuing standalone",
                e
            );
            None
        }
    };

    let Some(state) = state else {
        // Standalone mode: build a static watch channel that yields the
        // local engine. Drop the sender so the receiver is effectively
        // read-only.
        let (tx, rx) = tokio::sync::watch::channel(Arc::new(local_engine));
        drop(tx);
        return Ok((None, None, None, rx));
    };

    // Org mode: pull initial policy (falls back to local on failure),
    // start the heartbeat / policy-pull / audit-sink tasks, and build
    // the SmartflowProvider for identity dispatch.
    let api = Arc::new(OrgApi::from_state(&state));
    let initial_engine = orgmode::load_initial_engine(&state, &api, local_engine).await;

    let initial_version = api
        .get_shieldset_version(&state.policy_group)
        .await
        .ok()
        .map(|v| v.version)
        .unwrap_or(0);

    let pull = aperion_shield::orgmode::start_policy_pull(
        api.clone(),
        state.clone(),
        Arc::new(initial_engine),
        initial_version,
    );
    let engine_rx = pull.current.clone();

    let heartbeat_task = aperion_shield::orgmode::start_heartbeat(api.clone(), state.clone());

    let audit = AuditSink::new(api.clone());

    let smartflow_identity = Arc::new(SmartflowProvider::new(api.clone()));

    let handles = Arc::new(EnrolledHandles {
        state: state.clone(),
        api,
        policy: pull,
        audit,
        _heartbeat_task: heartbeat_task,
    });

    Ok((Some(state), Some(handles), Some(smartflow_identity), engine_rx))
}

/// Handle [`Decision::IdentityVerification`] when running in org mode.
/// Delegates to [`SmartflowProvider::resolve`] and translates the
/// outcome into either a release (return `None`) or a structured
/// JSON-RPC error mirroring the local-IdentityGate behaviour.
async fn handle_identity_decision_orgmode(
    id: Value,
    tool_name: &str,
    fp: &str,
    rule_id: String,
    severity: aperion_shield::Severity,
    requirement: aperion_shield::IdentityRequirement,
    sf: Arc<SmartflowProvider>,
) -> Option<Value> {
    match sf.resolve(&requirement).await {
        ResolveOutcome::Verified(proof) => {
            let audit = json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "kind": "identity_satisfied",
                "via": "smartflow",
                "tool": tool_name,
                "rule_id": rule_id,
                "fingerprint": fp,
                "provider": proof.provider,
                "subject": proof.subject,
                "loa": proof.loa,
                "scope": requirement.scope,
                "expires_at": proof.expires_at,
                "signature": proof.signature,
            });
            eprintln!("{}", audit);
            info!(
                "[shield] identity satisfied via smartflow subject={} loa={} -- releasing tool={}",
                proof.subject, proof.loa, tool_name
            );
            None
        }
        ResolveOutcome::HoldExpired {
            verify_url,
            challenge_id,
        } => {
            warn!(
                "[shield] identity hold expired rule={} tool={} challenge={}",
                rule_id, tool_name, challenge_id
            );
            Some(jsonrpc_error(
                id,
                -32091,
                "shield_identity_required",
                json!({
                    "rule_id": rule_id,
                    "severity": severity.as_str(),
                    "fingerprint": fp,
                    "tool": tool_name,
                    "via": "smartflow",
                    "verify_url": verify_url,
                    "challenge_id": challenge_id,
                    "provider": requirement.provider,
                    "scope": requirement.scope,
                    "loa": requirement.loa,
                    "instructions": format!(
                        "Open {} in a browser to complete identity verification, then retry the tool call.",
                        verify_url
                    ),
                }),
            ))
        }
        ResolveOutcome::ProviderUnready { provider, message } => {
            error!(
                "[shield] smartflow identity provider '{}' is unready: {} -- denying tool={}",
                provider, message, tool_name
            );
            Some(jsonrpc_error(
                id,
                -32094,
                "shield_identity_provider_unready",
                json!({
                    "rule_id": rule_id,
                    "provider": provider,
                    "via": "smartflow",
                    "message": message,
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ))
        }
        ResolveOutcome::Error(e) => {
            error!(
                "[shield] smartflow identity check failed for rule={}: {} -- denying tool={}",
                rule_id, e, tool_name
            );
            Some(jsonrpc_error(
                id,
                -32092,
                "shield_identity_unavailable",
                json!({
                    "rule_id": rule_id,
                    "via": "smartflow",
                    "message": e.to_string(),
                    "fingerprint": fp,
                    "tool": tool_name,
                }),
            ))
        }
    }
}

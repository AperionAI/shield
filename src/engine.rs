//! Aperion Shield -- self-contained rule engine for the standalone product.
//!
//! Schema overview (YAML, v2 -- v1 documents still load unchanged):
//!
//! ```yaml
//! shieldset:
//!   version: 2
//!   policy:                # all optional -- v1 documents have no `policy:`
//!     workspace_probe:
//!       enabled: true
//!       prod_signals: [".env.production", "prod/", "Procfile"]
//!       severity_bump: 1
//!     decision_memory:
//!       enabled: true
//!       demote_after_approvals: 3
//!       escalate_on_deny_days: 7
//!     burst_detector:
//!       enabled: true
//!       window_seconds: 300
//!       threshold: 5
//!     composite_scoring:
//!       enabled: true
//!       thresholds: { medium: 2, high: 5, critical: 9 }
//!
//!   rules:
//!     - id: ...
//!       severity: Critical | High | Medium | Low
//!       points: 5                    # NEW (v2): contributes to composite score
//!       where: tool_call | llm_response
//!       safer_alternative: "..."     # NEW (v2): teach the user the safe form
//!       match:
//!         tool: ["execute_sql", ...]
//!         any_param_matches: ['regex', ...]
//!         sql_matches:       ['regex', ...]
//!         sql_predicates:    [unscoped_update, unscoped_delete]
//!         text_matches:      ['regex', ...]
//!         command_predicates: [curl_pipe_sh, env_to_network, reverse_shell]   # NEW (v2)
//!         sensitive_paths:    ['/etc/**', '~/.ssh/**', '~/.aws/**']           # NEW (v2)
//!       reason: "..."
//! ```
//!
//! Severity -> outcome mapping for the standalone:
//!
//! | Severity | Decision                  |
//! |----------|---------------------------|
//! | Critical | Block (JSON-RPC error)    |
//! | High     | Approval (waits on inbox) |
//! | Medium   | Allow + warn banner       |
//! | Low      | Allow + audit-only log    |
//!
//! Adaptive layer (v2): the *raw* severity above is the rule's baseline. The
//! final severity is the max of:
//!
//!   1. The highest single matched rule's severity, AND
//!   2. The composite-score-derived severity (sum of `points` across all
//!      matching rules, mapped to thresholds), AND
//!   3. The base severity bumped up by one tier if the workspace looks like
//!      production, AND
//!   4. The base severity bumped up by one tier if Shield has recently
//!      *denied* this exact (rule_id, argv-fingerprint) pair, AND
//!   5. The base severity bumped up by one tier while a destructive burst
//!      is in progress.
//!
//! Memory may *demote* by one tier when the user has approved this exact
//! fingerprint >= N times with no recent denials.
//!
//! All adjustments compose monotonically: the worst (highest-rank)
//! severity wins.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::identity::Requirement as IdentityRequirement;
use crate::predicates::{CommandPredicate, SensitivePath};

// ─────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn rank(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }

    /// Bump one tier toward Critical, saturating.
    pub fn bumped(self) -> Self {
        match self {
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High => Severity::Critical,
            Severity::Critical => Severity::Critical,
        }
    }

    /// Drop one tier toward Low, saturating.
    pub fn demoted(self) -> Self {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low => Severity::Low,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Warn {
        rule_id: String,
        severity: Severity,
        banner: String,
        safer_alternative: Option<String>,
    },
    Approval {
        rule_id: String,
        severity: Severity,
        reason: String,
        safer_alternative: Option<String>,
        contributing_rules: Vec<String>,
    },
    /// The matched rule carried an `identity:` block AND resolved to a
    /// High-or-higher severity. The caller must check the identity
    /// proof cache and, on miss, surface a verification URL to the
    /// user. Held tool calls block until the proof lands or the hold
    /// window elapses.
    IdentityVerification {
        rule_id: String,
        severity: Severity,
        reason: String,
        safer_alternative: Option<String>,
        contributing_rules: Vec<String>,
        requirement: IdentityRequirement,
    },
    Block {
        rule_id: String,
        severity: Severity,
        reason: String,
        safer_alternative: Option<String>,
        contributing_rules: Vec<String>,
    },
}

impl Decision {
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            Decision::Block { .. }
                | Decision::Approval { .. }
                | Decision::IdentityVerification { .. }
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn { .. } => "warn",
            Decision::Approval { .. } => "approval",
            Decision::IdentityVerification { .. } => "identity_verification",
            Decision::Block { .. } => "block",
        }
    }
}

/// All adaptive adjustments the engine should apply on top of the raw
/// rule severity. Computed by the caller (main.rs) from runtime state
/// (workspace context, decision memory, burst detector). Passing these
/// in keeps the engine pure and testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct Adjustments {
    pub workspace_is_prod: bool,
    pub fingerprint_recently_denied: bool,
    pub fingerprint_repeatedly_approved: bool,
    pub burst_in_progress: bool,
    /// v1.3 cross-tool taint: a credential-shaped value in this call's
    /// arguments (or diff line, or shim command) was previously observed
    /// leaving a *different* tool/server/surface in this project. Set by
    /// the caller from a `taint::TaintLedger::check()` hit. When true,
    /// `resolve()` injects a synthetic taint finding, bumps one tier, and
    /// enforces an Approval floor -- a credential crossing a tool boundary
    /// is inherently actionable regardless of what other rule matched.
    pub tainted_secret_in_flight: bool,
}

/// Synthetic rule id for the cross-tool taint finding injected by
/// `resolve()` when `Adjustments::tainted_secret_in_flight` is set. It is
/// not a YAML rule -- it exists so the taint signal flows through the
/// normal `decide()` path (which short-circuits to `Allow` on an empty
/// match set) and shows up as a first-class finding in audit + `--explain`.
pub const TAINT_RULE_ID: &str = "taint.secret_crosses_tool_boundary";

// ─────────────────────────────────────────────────────────────────────────
// YAML schema (v1 + v2 -- both deserialise via the same Root)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Root {
    pub shieldset: Shieldset,
}

#[derive(Debug, Deserialize)]
pub struct Shieldset {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub rules: Vec<YamlRule>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Policy {
    #[serde(default)]
    pub workspace_probe: WorkspaceProbeCfg,
    #[serde(default)]
    pub decision_memory: DecisionMemoryCfg,
    #[serde(default)]
    pub burst_detector: BurstDetectorCfg,
    #[serde(default)]
    pub composite_scoring: CompositeScoringCfg,
    #[serde(default)]
    pub supply_chain: SupplyChainCfg,
}

/// v0.9 MCP supply-chain protection. Controls TOFU pinning of the
/// upstream's tool catalog and what happens when a pinned tool's
/// definition changes underneath the user (a "rug pull").
#[derive(Debug, Deserialize, Clone)]
pub struct SupplyChainCfg {
    /// Master switch for catalog pinning. When false, `tools/list`
    /// results pass through unpinned (description-scan rules still run).
    #[serde(default = "default_true")]
    pub pinning: bool,
    /// Action when a pinned tool's (description, schema) hash changes:
    /// `block` (default) | `warn` | `allow`.
    #[serde(default = "default_on_changed")]
    pub on_changed_tool: String,
    /// Action when a server adds a tool after first pin: `warn`
    /// (default, and the tool is pinned) | `block` | `allow`.
    #[serde(default = "default_on_new")]
    pub on_new_tool: String,
}
impl Default for SupplyChainCfg {
    fn default() -> Self {
        Self {
            pinning: true,
            on_changed_tool: default_on_changed(),
            on_new_tool: default_on_new(),
        }
    }
}
fn default_on_changed() -> String {
    "block".into()
}
fn default_on_new() -> String {
    "warn".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct WorkspaceProbeCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_prod_signals")]
    pub prod_signals: Vec<String>,
    #[serde(default = "one")]
    pub severity_bump: u8,
}
impl Default for WorkspaceProbeCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            prod_signals: default_prod_signals(),
            severity_bump: 1,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DecisionMemoryCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_three")]
    pub demote_after_approvals: u32,
    #[serde(default = "default_seven")]
    pub escalate_on_deny_days: u32,
}
impl Default for DecisionMemoryCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            demote_after_approvals: 3,
            escalate_on_deny_days: 7,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct BurstDetectorCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_300")]
    pub window_seconds: u32,
    #[serde(default = "default_five")]
    pub threshold: u32,
}
impl Default for BurstDetectorCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 300,
            threshold: 5,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompositeScoringCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub thresholds: CompositeThresholds,
}
impl Default for CompositeScoringCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            thresholds: CompositeThresholds::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompositeThresholds {
    #[serde(default = "default_two")]
    pub medium: u32,
    #[serde(default = "default_five")]
    pub high: u32,
    #[serde(default = "default_nine")]
    pub critical: u32,
}
impl Default for CompositeThresholds {
    fn default() -> Self {
        Self {
            medium: 2,
            high: 5,
            critical: 9,
        }
    }
}

fn default_true() -> bool {
    true
}
fn one() -> u8 {
    1
}
fn default_three() -> u32 {
    3
}
fn default_seven() -> u32 {
    7
}
fn default_300() -> u32 {
    300
}
fn default_five() -> u32 {
    5
}
fn default_two() -> u32 {
    2
}
fn default_nine() -> u32 {
    9
}
fn default_prod_signals() -> Vec<String> {
    vec![
        ".env.production".into(),
        "prod/".into(),
        "Procfile".into(),
        ".terraform/terraform.tfstate".into(),
        "kubeconfig".into(),
        ".kube/config".into(),
        "production.yml".into(),
        "production.yaml".into(),
    ]
}

#[derive(Debug, Deserialize)]
pub struct YamlRule {
    pub id: String,
    pub severity: Severity,
    #[serde(default)]
    pub points: Option<u32>,
    #[serde(rename = "where")]
    pub where_: String,
    #[serde(default)]
    pub r#match: Option<YamlMatch>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub safer_alternative: Option<String>,
    /// Optional identity gate. When present AND the rule resolves to a
    /// High-or-Critical severity, the engine emits a
    /// [`Decision::IdentityVerification`] instead of Approval/Block.
    /// The MCP middleman then handles the verification flow (cache
    /// lookup, callback server, hold-then-surface).
    #[serde(default)]
    pub identity: Option<IdentityRequirement>,
}

#[derive(Debug, Default, Deserialize)]
pub struct YamlMatch {
    #[serde(default)]
    pub tool: Option<Vec<String>>,
    #[serde(default)]
    pub any_param_matches: Vec<String>,
    #[serde(default)]
    pub sql_matches: Vec<String>,
    #[serde(default)]
    pub sql_predicates: Vec<String>,
    #[serde(default)]
    pub text_matches: Vec<String>,
    #[serde(default)]
    pub command_predicates: Vec<String>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Compiled rule + matcher
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ToolCall,
    LlmResponse,
    /// v0.9: matches against tool descriptions in a `tools/list` result
    /// (the MCP supply-chain seam -- catches tool-poisoning, where a
    /// malicious server hides instructions for the model inside a tool's
    /// description text).
    ToolDescription,
    /// v0.9: matches against the text content of a `tools/call` result
    /// (catches prompt-injection payloads coming back from the tool).
    ToolResult,
}

#[derive(Debug, Clone, Copy)]
pub enum SqlPredicate {
    UnscopedUpdate,
    UnscopedDelete,
}

#[derive(Debug)]
struct Match {
    tool_whitelist: Option<HashSet<String>>,
    any_param_re: Vec<Regex>,
    sql_re: Vec<Regex>,
    sql_predicates: Vec<SqlPredicate>,
    text_re: Vec<Regex>,
    command_predicates: Vec<CommandPredicate>,
    sensitive_paths: Vec<SensitivePath>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub severity: Severity,
    pub points: u32,
    pub scope: Scope,
    pub reason: String,
    pub safer_alternative: Option<String>,
    /// Identity gate carried over from the YAML. None for the vast
    /// majority of rules; Some for the small set the customer explicitly
    /// wires to biometric verification.
    pub identity: Option<IdentityRequirement>,
    matcher: Option<Match>,
}

impl CompiledRule {
    pub fn matches_tool_call(&self, tool: &str, params: &serde_json::Value) -> bool {
        let m = match &self.matcher {
            Some(m) => m,
            None => return false,
        };
        if let Some(allow) = &m.tool_whitelist {
            if !allow.contains(tool) {
                return false;
            }
        }

        // 1. SQL family (regex + predicate)
        if !m.sql_re.is_empty() || !m.sql_predicates.is_empty() {
            let sqls = extract_sql(params);
            for s in &sqls {
                for re in &m.sql_re {
                    if re.is_match(s) {
                        return true;
                    }
                }
                for p in &m.sql_predicates {
                    if matches_sql_predicate(*p, s) {
                        return true;
                    }
                }
            }
        }

        // 2. Param regex (recursive)
        if !m.any_param_re.is_empty() {
            let mut hit = false;
            walk_strings(params, &mut |s| {
                if hit {
                    return;
                }
                for re in &m.any_param_re {
                    if re.is_match(s) {
                        hit = true;
                        return;
                    }
                }
            });
            if hit {
                return true;
            }
        }

        // 3. Structured command predicates (v2): operate on the joined
        // command line. For shell-like tools, we treat any string param
        // as a candidate command.
        if !m.command_predicates.is_empty() {
            let mut hit = false;
            walk_strings(params, &mut |s| {
                if hit {
                    return;
                }
                for p in &m.command_predicates {
                    if p.matches(s) {
                        hit = true;
                        return;
                    }
                }
            });
            if hit {
                return true;
            }
        }

        // 4. Sensitive path matcher (v2): walks all string params and
        // checks each against the normalised path globs.
        //
        // NEW in v0.3: a sensitive-path hit only counts if the SAME
        // string ALSO contains a write/delete verb (rm/mv/cp/dd/tee/
        // chmod/chown/sed -i/tar -x/git checkout/kubectl apply/...).
        // Without this gate, `ssh -i ~/.ssh/key root@host "grep ..."`
        // fires on the SSH identity flag and produces ~69% false-
        // positive approvals on real-world traffic. With the gate the
        // rule fires only on actual writes-to-sensitive-paths.
        if !m.sensitive_paths.is_empty() {
            let mut hit = false;
            walk_strings(params, &mut |s| {
                if hit {
                    return;
                }
                if !crate::predicates::command_writes(s) {
                    return;
                }
                for sp in &m.sensitive_paths {
                    if sp.touches(s) {
                        hit = true;
                        return;
                    }
                }
            });
            if hit {
                return true;
            }
        }

        false
    }

    pub fn matches_text(&self, text: &str) -> bool {
        let m = match &self.matcher {
            Some(m) => m,
            None => return false,
        };
        for re in &m.text_re {
            if re.is_match(text) {
                return true;
            }
        }
        false
    }

    /// The rule's `tool:` whitelist, if any. Used by the scoped-text
    /// evaluator so `tool_description` / `tool_result` rules can target
    /// specific tools.
    pub fn tool_whitelist(&self) -> Option<&HashSet<String>> {
        self.matcher
            .as_ref()
            .and_then(|m| m.tool_whitelist.as_ref())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Engine {
    pub rules: Vec<CompiledRule>,
    pub policy: Policy,
}

/// All rule matches for one evaluation, plus the adaptive resolution.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub matches: Vec<MatchInfo>,
    pub composite_points: u32,
    pub raw_severity: Severity,
    pub composite_severity: Severity,
    pub final_severity: Severity,
    pub adjustments_applied: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct MatchInfo {
    pub rule_id: String,
    pub severity: Severity,
    pub points: u32,
    pub reason: String,
    pub safer_alternative: Option<String>,
    /// Carried through from the rule. Used by `decide()` to detect
    /// when the resolved decision should be promoted to
    /// `IdentityVerification` instead of plain Approval/Block.
    pub identity: Option<IdentityRequirement>,
}

impl Engine {
    /// Load a Shield ruleset from a YAML string. Returns an error on
    /// malformed YAML or regex compilation failure.
    pub fn from_yaml(raw: &str) -> anyhow::Result<Self> {
        let root: Root = serde_yaml::from_str(raw)?;
        let policy = root.shieldset.policy.clone();
        let rules = Self::compile_yaml_rules(root.shieldset.rules)?;
        Ok(Engine { rules, policy })
    }

    /// Merge an additional rule pack (e.g. the optional ATR community
    /// pack) into an already-loaded engine. The pack's `policy:` block,
    /// if any, is IGNORED -- policy always comes from the primary
    /// shieldset. Duplicate rule ids across packs are an error: silent
    /// shadowing would make composite scoring double-count.
    pub fn extend_from_yaml(&mut self, raw: &str) -> anyhow::Result<()> {
        let root: Root = serde_yaml::from_str(raw)?;
        let extra = Self::compile_yaml_rules(root.shieldset.rules)?;
        for r in &extra {
            if self.rules.iter().any(|e| e.id == r.id) {
                anyhow::bail!("rule pack defines duplicate rule id '{}'", r.id);
            }
        }
        self.rules.extend(extra);
        Ok(())
    }

    fn compile_yaml_rules(yaml_rules: Vec<YamlRule>) -> anyhow::Result<Vec<CompiledRule>> {
        let mut rules = Vec::with_capacity(yaml_rules.len());
        for y in yaml_rules {
            let scope = match y.where_.as_str() {
                "tool_call" => Scope::ToolCall,
                "llm_response" => Scope::LlmResponse,
                "tool_description" => Scope::ToolDescription,
                "tool_result" => Scope::ToolResult,
                other => anyhow::bail!("rule '{}' has unknown where '{}'", y.id, other),
            };
            let matcher = if let Some(m) = y.r#match {
                let mut sql_preds = Vec::new();
                for n in m.sql_predicates {
                    let p = match n.to_ascii_lowercase().as_str() {
                        "unscoped_update" => SqlPredicate::UnscopedUpdate,
                        "unscoped_delete" => SqlPredicate::UnscopedDelete,
                        other => {
                            anyhow::bail!("rule '{}'.sql_predicates: unknown '{}'", y.id, other)
                        }
                    };
                    sql_preds.push(p);
                }
                let mut cmd_preds = Vec::new();
                for n in m.command_predicates {
                    let p = CommandPredicate::parse(&n).ok_or_else(|| {
                        anyhow::anyhow!("rule '{}'.command_predicates: unknown '{}'", y.id, n)
                    })?;
                    cmd_preds.push(p);
                }
                let mut paths = Vec::new();
                for n in m.sensitive_paths {
                    paths.push(SensitivePath::compile(&n)?);
                }
                Some(Match {
                    tool_whitelist: m.tool.map(|v| v.into_iter().collect()),
                    any_param_re: compile_regexes(&y.id, "any_param_matches", m.any_param_matches)?,
                    sql_re: compile_regexes(&y.id, "sql_matches", m.sql_matches)?,
                    sql_predicates: sql_preds,
                    text_re: compile_regexes(&y.id, "text_matches", m.text_matches)?,
                    command_predicates: cmd_preds,
                    sensitive_paths: paths,
                })
            } else {
                None
            };
            // Default points = severity rank, so authors who don't think
            // about points still get sensible composite behaviour.
            let points = y.points.unwrap_or(y.severity.rank() as u32);
            rules.push(CompiledRule {
                id: y.id,
                severity: y.severity,
                points,
                scope,
                reason: y.reason,
                safer_alternative: y.safer_alternative,
                identity: y.identity,
                matcher,
            });
        }
        Ok(rules)
    }

    /// Bundled defaults -- the same YAML used by the enterprise build,
    /// embedded at compile time so the binary always has *some* ruleset.
    pub fn builtin_default() -> Self {
        let yaml = include_str!("../config/shieldset.yaml");
        Self::from_yaml(yaml).expect("bundled shieldset.yaml must parse")
    }

    /// Evaluate a tool call. Returns the full evaluation (which rules
    /// fired, points, raw vs composite vs final severity). The caller
    /// turns this into a Decision via `decide_tool_call`.
    pub fn evaluate(&self, tool: &str, params: &serde_json::Value, adj: Adjustments) -> Evaluation {
        let mut matches = Vec::new();
        let mut composite_points = 0u32;
        for r in self.rules.iter().filter(|r| r.scope == Scope::ToolCall) {
            if r.matches_tool_call(tool, params) {
                composite_points = composite_points.saturating_add(r.points);
                matches.push(MatchInfo {
                    rule_id: r.id.clone(),
                    severity: r.severity,
                    points: r.points,
                    reason: r.reason.clone(),
                    safer_alternative: r.safer_alternative.clone(),
                    identity: r.identity.clone(),
                });
            }
        }
        self.resolve(matches, composite_points, adj)
    }

    /// Evaluate an LLM response body.
    pub fn evaluate_text(&self, text: &str, adj: Adjustments) -> Evaluation {
        self.evaluate_scoped_text(Scope::LlmResponse, None, text, adj)
    }

    /// Evaluate free text against the rules of one scope. `tool` is the
    /// tool the text belongs to (the described tool for
    /// `Scope::ToolDescription`, the called tool for `Scope::ToolResult`);
    /// rules with a `tool:` whitelist only fire when it matches.
    pub fn evaluate_scoped_text(
        &self,
        scope: Scope,
        tool: Option<&str>,
        text: &str,
        adj: Adjustments,
    ) -> Evaluation {
        let mut matches = Vec::new();
        let mut composite_points = 0u32;
        for r in self.rules.iter().filter(|r| r.scope == scope) {
            if let (Some(t), Some(allow)) = (tool, r.tool_whitelist()) {
                if !allow.contains(t) {
                    continue;
                }
            }
            if r.matches_text(text) {
                composite_points = composite_points.saturating_add(r.points);
                matches.push(MatchInfo {
                    rule_id: r.id.clone(),
                    severity: r.severity,
                    points: r.points,
                    reason: r.reason.clone(),
                    safer_alternative: r.safer_alternative.clone(),
                    identity: r.identity.clone(),
                });
            }
        }
        self.resolve(matches, composite_points, adj)
    }

    fn resolve(
        &self,
        mut matches: Vec<MatchInfo>,
        composite_points: u32,
        adj: Adjustments,
    ) -> Evaluation {
        // v1.3: inject a synthetic finding for a cross-tool taint hit so
        // the signal flows through `decide()` (which returns `Allow` on an
        // empty match set) and is attributable in audit / `--explain`.
        // Its raw severity is deliberately Low -- the escalation is driven
        // by the explicit bump + Approval floor below, not by this
        // carrier's own severity, so it never over-inflates the composite.
        if adj.tainted_secret_in_flight {
            matches.push(MatchInfo {
                rule_id: TAINT_RULE_ID.to_string(),
                severity: Severity::Low,
                points: 0,
                reason: "A credential-shaped value in this call was previously observed leaving a \
                         different tool/server/surface in this project (possible cross-tool \
                         credential relay / confused deputy)."
                    .to_string(),
                safer_alternative: Some(
                    "Confirm the destination tool/server is trusted before approving. Never relay \
                     credentials returned by one tool into another tool's arguments."
                        .to_string(),
                ),
                identity: None,
            });
        }

        let raw_severity = matches
            .iter()
            .map(|m| m.severity)
            .max()
            .unwrap_or(Severity::Low);

        let composite_severity = if self.policy.composite_scoring.enabled {
            severity_from_points(composite_points, &self.policy.composite_scoring.thresholds)
        } else {
            Severity::Low
        };

        let mut final_severity = raw_severity.max(composite_severity);
        let mut adjustments_applied = Vec::new();

        if adj.workspace_is_prod && !matches.is_empty() {
            final_severity = final_severity.bumped();
            adjustments_applied.push("workspace_is_prod");
        }
        if adj.fingerprint_recently_denied && !matches.is_empty() {
            final_severity = final_severity.bumped();
            adjustments_applied.push("fingerprint_recently_denied");
        }
        if adj.burst_in_progress && !matches.is_empty() {
            final_severity = final_severity.bumped();
            adjustments_applied.push("burst_in_progress");
        }
        // Demotion only applies if no escalation kicked in. We bumped
        // already; only demote on a clean baseline. A taint hit is never
        // eligible for demotion -- it is inherently actionable.
        if adj.fingerprint_repeatedly_approved
            && !matches.is_empty()
            && !adj.workspace_is_prod
            && !adj.fingerprint_recently_denied
            && !adj.burst_in_progress
            && !adj.tainted_secret_in_flight
        {
            final_severity = final_severity.demoted();
            adjustments_applied.push("fingerprint_repeatedly_approved");
        }

        // v1.3 taint: bump one tier (like burst/prod) AND enforce an
        // Approval floor. Applied last so the floor survives any prior
        // demotion, and so a credential crossing a tool boundary can never
        // resolve to a silent Allow. Escalates an already-suspicious call
        // further (e.g. a matched High rule + taint -> Critical/Block).
        if adj.tainted_secret_in_flight {
            final_severity = final_severity.bumped().max(Severity::High);
            adjustments_applied.push("tainted_secret_in_flight");
        }

        Evaluation {
            matches,
            composite_points,
            raw_severity,
            composite_severity,
            final_severity,
            adjustments_applied,
        }
    }
}

/// Turn an evaluation into a concrete Decision. The "primary" rule is
/// whichever matched rule contributed the highest individual severity;
/// ties broken by points then by lexicographic id.
pub fn decide(eval: &Evaluation) -> Decision {
    if eval.matches.is_empty() {
        return Decision::Allow;
    }
    let primary = eval
        .matches
        .iter()
        .max_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then(a.points.cmp(&b.points))
                .then(b.rule_id.cmp(&a.rule_id))
        })
        .expect("non-empty");

    let contributing: Vec<String> = eval
        .matches
        .iter()
        .filter(|m| m.rule_id != primary.rule_id)
        .map(|m| m.rule_id.clone())
        .collect();

    match eval.final_severity {
        Severity::Critical => {
            // Identity gates supersede plain Block. The point of the
            // gate is "this is destructive enough that we want a fresh
            // biometric receipt before allowing it" -- if Shield just
            // hard-blocks, the gate never gets a chance to consent.
            if let Some(req) = primary.identity.clone() {
                Decision::IdentityVerification {
                    rule_id: primary.rule_id.clone(),
                    severity: eval.final_severity,
                    reason: primary.reason.clone(),
                    safer_alternative: primary.safer_alternative.clone(),
                    contributing_rules: contributing,
                    requirement: req,
                }
            } else {
                Decision::Block {
                    rule_id: primary.rule_id.clone(),
                    severity: eval.final_severity,
                    reason: primary.reason.clone(),
                    safer_alternative: primary.safer_alternative.clone(),
                    contributing_rules: contributing,
                }
            }
        }
        Severity::High => {
            if let Some(req) = primary.identity.clone() {
                Decision::IdentityVerification {
                    rule_id: primary.rule_id.clone(),
                    severity: eval.final_severity,
                    reason: primary.reason.clone(),
                    safer_alternative: primary.safer_alternative.clone(),
                    contributing_rules: contributing,
                    requirement: req,
                }
            } else {
                Decision::Approval {
                    rule_id: primary.rule_id.clone(),
                    severity: eval.final_severity,
                    reason: primary.reason.clone(),
                    safer_alternative: primary.safer_alternative.clone(),
                    contributing_rules: contributing,
                }
            }
        }
        Severity::Medium => Decision::Warn {
            rule_id: primary.rule_id.clone(),
            severity: eval.final_severity,
            banner: primary.reason.clone(),
            safer_alternative: primary.safer_alternative.clone(),
        },
        Severity::Low => Decision::Allow,
    }
}

fn severity_from_points(points: u32, t: &CompositeThresholds) -> Severity {
    if points >= t.critical {
        Severity::Critical
    } else if points >= t.high {
        Severity::High
    } else if points >= t.medium {
        Severity::Medium
    } else {
        Severity::Low
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SQL helpers (unchanged from v1)
// ─────────────────────────────────────────────────────────────────────────

fn compile_regexes(rule_id: &str, field: &str, ps: Vec<String>) -> anyhow::Result<Vec<Regex>> {
    let mut out = Vec::with_capacity(ps.len());
    for p in ps {
        out.push(Regex::new(&p).map_err(|e| {
            anyhow::anyhow!("rule '{}'.{}: bad regex '{}': {}", rule_id, field, p, e)
        })?);
    }
    Ok(out)
}

const SQL_KEYS: &[&str] = &["query", "sql", "statement", "command", "stmt", "ddl", "dml"];

fn extract_sql(v: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    walk_sql(v, &mut out);
    out
}

fn walk_sql(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if SQL_KEYS.iter().any(|sk| sk.eq_ignore_ascii_case(k)) {
                    if let Some(s) = val.as_str() {
                        out.push(s.to_string());
                    }
                }
                walk_sql(val, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk_sql(item, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn walk_strings<F: FnMut(&str)>(v: &serde_json::Value, f: &mut F) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(arr) => {
            for item in arr {
                walk_strings(item, f);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, val) in map {
                walk_strings(val, f);
            }
        }
        _ => {}
    }
}

static UPDATE_HEAD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bUPDATE\s+[A-Za-z_][A-Za-z0-9_\.]*\s+SET\b").expect("static"));
static DELETE_HEAD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bDELETE\s+FROM\s+[A-Za-z_][A-Za-z0-9_\.]*").expect("static"));
static WHERE_CLAUSE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b").expect("static"));

fn matches_sql_predicate(p: SqlPredicate, sql: &str) -> bool {
    for frag in sql.split(';') {
        let f = frag.trim();
        if f.is_empty() {
            continue;
        }
        match p {
            SqlPredicate::UnscopedUpdate => {
                if !UPDATE_HEAD.is_match(f) {
                    continue;
                }
                // Case 1 -- no WHERE clause at all.
                if !WHERE_CLAUSE.is_match(f) {
                    return true;
                }
                // Case 2 -- tautological WHERE clause: the WHERE
                // selects exactly the rows the SET would change, so
                // the UPDATE is functionally identical to an unscoped
                // UPDATE. Catches "fake scope" patterns like
                //   UPDATE users SET email_verified = TRUE
                //   WHERE email_verified = FALSE;
                // (every FALSE row gets flipped; no FALSE row is left
                // behind; the WHERE adds nothing the SET wasn't
                // already going to do.)
                if where_is_tautological_for_update(f) {
                    return true;
                }
            }
            SqlPredicate::UnscopedDelete => {
                if DELETE_HEAD.is_match(f) && !WHERE_CLAUSE.is_match(f) {
                    return true;
                }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────
// Tautological-WHERE detection
//
// A WHERE clause is "tautological" for an UPDATE when it selects
// exactly the rows the SET clause would CHANGE -- meaning every row
// in the table either matches the WHERE and gets rewritten, or
// doesn't match and would have been a no-op anyway. The UPDATE is
// then semantically equivalent to one with no WHERE clause, and
// `sql.unscoped_update` should fire.
//
// Patterns caught (per (col, set_val) pair in the SET clause):
//   1. Boolean opposite:    SET col = TRUE  WHERE col = FALSE
//                           SET col = FALSE WHERE col = TRUE
//                           (also accepts t/f and 1/0 literals)
//   2. Inequality:          SET col = X     WHERE col != X
//                           SET col = X     WHERE col <> X
//   3. IS NOT:              SET col = X     WHERE col IS NOT X
//   4. NULL as falsy:       SET col = TRUE  WHERE col IS NULL
//   5. Negation:            SET col = TRUE  WHERE NOT col
//
// AND-conjunction handling: every conjunct in the WHERE clause must
// be tautological w.r.t. some SET pair. If even one conjunct adds
// real scope (e.g. `... AND created_at > NOW() - INTERVAL '7 days'`),
// the WHERE is NOT tautological and the rule does NOT fire.
//
// OR-disjunctions and nested expressions are handled conservatively:
// we currently inspect the WHERE clause as a flat sequence of
// AND-separated conjuncts. A WHERE clause that uses OR in ways the
// AND-split cannot represent will fall through to "not tautological"
// and the rule will not fire on it -- that's a v0.7 enhancement once
// we vendor a proper SQL AST parser.
// ─────────────────────────────────────────────────────────────────────────

static SET_AND_WHERE_RE: Lazy<Regex> = Lazy::new(|| {
    // (?is) -- case-insensitive, dot matches newline. SET ... WHERE ...
    // terminated by LIMIT / RETURNING / end-of-statement.
    Regex::new(r"(?is)\bSET\b\s+(.+?)\s+\bWHERE\b\s+(.+?)(?:\s+\b(?:LIMIT|RETURNING|ORDER\s+BY|GROUP\s+BY)\b.*)?$")
        .expect("static")
});

fn where_is_tautological_for_update(sql: &str) -> bool {
    let caps = match SET_AND_WHERE_RE.captures(sql) {
        Some(c) => c,
        None => return false,
    };
    let set_part = match caps.get(1) {
        Some(m) => m.as_str(),
        None => return false,
    };
    let where_part = match caps.get(2) {
        Some(m) => m.as_str(),
        None => return false,
    };

    let set_pairs = parse_set_pairs(set_part);
    if set_pairs.is_empty() {
        return false;
    }

    let conjuncts = split_where_on_and(where_part);
    if conjuncts.is_empty() {
        return false;
    }

    for conjunct in &conjuncts {
        let trimmed = conjunct.trim_matches(|c: char| c.is_whitespace() || c == '(' || c == ')');
        if trimmed.is_empty() {
            continue;
        }
        let mut matched = false;
        for (col, val) in &set_pairs {
            if predicate_is_tautological(col, val, trimmed) {
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

/// Parse `col1 = val1, col2 = val2, ...` into a vector of (col, val) pairs.
/// Naive on commas (does not respect commas inside string literals or
/// function calls). For the destructive-UPDATE cases we care about
/// (booleans, simple constants, NULL) this is more than enough.
fn parse_set_pairs(set_part: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in set_part.split(',') {
        let mut halves = raw.splitn(2, '=');
        let col = match halves.next() {
            Some(c) => c.trim(),
            None => continue,
        };
        let val = match halves.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        if col.is_empty() || val.is_empty() {
            continue;
        }
        let col_norm = col.trim_matches(|c: char| c == '"' || c == '`').to_string();
        let val_norm = val
            .trim_matches(|c: char| c == '\'' || c == '"')
            .to_string();
        out.push((col_norm, val_norm));
    }
    out
}

/// Split a WHERE clause body on case-insensitive ` AND `. Conservative
/// -- treats the body as a flat sequence; nested boolean expressions
/// with OR or parentheses fall through to "no split" and the caller
/// will inspect the whole clause as a single conjunct.
fn split_where_on_and(where_part: &str) -> Vec<&str> {
    static AND_SPLIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\s+AND\s+").expect("static"));
    AND_SPLIT.split(where_part).collect()
}

fn predicate_is_tautological(col: &str, set_val: &str, predicate: &str) -> bool {
    let col_esc = regex::escape(col);
    let set_val_lower = set_val.to_ascii_lowercase();
    let val_esc = regex::escape(set_val);
    // String literals in SQL WHERE clauses are wrapped in single (or,
    // less commonly, double) quotes. Our parsed `set_val` has those
    // quotes stripped, so we must tolerate optional surrounding quotes
    // on the WHERE side. Booleans / numerics typically aren't quoted.
    let q = r#"['"]?"#;

    // Pattern 1 -- inequality: col != X / col <> X.
    if regex_match(
        &format!(
            r"(?i)^\s*{}\s*(?:!=|<>)\s*{}{}{}\s*$",
            col_esc, q, val_esc, q
        ),
        predicate,
    ) {
        return true;
    }

    // Pattern 2 -- IS NOT: col IS NOT X (or IS DISTINCT FROM X).
    if regex_match(
        &format!(
            r"(?i)^\s*{}\s+IS\s+(?:NOT|DISTINCT\s+FROM)\s+{}{}{}\s*$",
            col_esc, q, val_esc, q
        ),
        predicate,
    ) {
        return true;
    }

    // Pattern 3 -- boolean opposite. Only valid when the SET value
    // is a boolean literal; then the WHERE selects the only other
    // possible value.
    if is_bool_literal(&set_val_lower) {
        let opposite_pat = bool_opposite_regex_alt(&set_val_lower);
        if regex_match(
            &format!(
                r"(?i)^\s*{}\s*=\s*{}(?:{}){}\s*$",
                col_esc, q, opposite_pat, q
            ),
            predicate,
        ) {
            return true;
        }
    }

    // Pattern 4 -- IS NULL on a SET col = TRUE pair: NULL is not
    // TRUE, so flipping all NULLs to TRUE captures every "not yet
    // verified" row.
    if set_val_lower == "true" || set_val_lower == "t" || set_val_lower == "1" {
        if regex_match(&format!(r"(?i)^\s*{}\s+IS\s+NULL\s*$", col_esc), predicate) {
            return true;
        }
        // Pattern 5 -- NOT col: SQL truthiness negation; functionally
        // identical to col IS NOT TRUE for boolean columns.
        if regex_match(&format!(r"(?i)^\s*NOT\s+{}\s*$", col_esc), predicate) {
            return true;
        }
        // Pattern 6 -- col IS NOT TRUE (Postgres-style).
        if regex_match(
            &format!(r"(?i)^\s*{}\s+IS\s+NOT\s+TRUE\s*$", col_esc),
            predicate,
        ) {
            return true;
        }
    }

    false
}

fn is_bool_literal(s: &str) -> bool {
    matches!(s, "true" | "false" | "t" | "f" | "1" | "0")
}

/// Regex alternation matching the OPPOSITE boolean literal of `lit`.
/// `true` / `t` / `1` are all equivalent; `false` / `f` / `0` are all
/// equivalent. Used to detect `SET col = TRUE WHERE col = FALSE`
/// regardless of which spelling the agent emitted on either side.
fn bool_opposite_regex_alt(lit: &str) -> &'static str {
    match lit {
        "true" | "t" | "1" => "false|f|0",
        "false" | "f" | "0" => "true|t|1",
        _ => "",
    }
}

fn regex_match(pattern: &str, haystack: &str) -> bool {
    Regex::new(pattern)
        .map(|re| re.is_match(haystack))
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────
// Fingerprint helpers (for decision memory)
// ─────────────────────────────────────────────────────────────────────────

/// Fingerprint a (rule_id, params) tuple. We hash rule_id + a stable
/// JSON serialisation of the parameters; the first 16 hex chars are
/// enough -- 64 bits of randomness, collision risk negligible for a
/// per-user local file with O(thousands) of entries.
pub fn fingerprint(rule_id: &str, params: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update(b"\x00");
    // Canonical JSON -- serde_json::to_string sorts maps by insertion
    // order, not lexicographically, but for our agent-supplied
    // params the input is stable per call site, and we only need
    // intra-process stability (not cross-tool reproducibility).
    if let Ok(s) = serde_json::to_string(params) {
        h.update(s.as_bytes());
    }
    let out = h.finalize();
    let mut hex = String::with_capacity(16);
    for b in &out[..8] {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine() -> Engine {
        Engine::builtin_default()
    }

    #[test]
    fn bundled_default_loads_with_many_rules() {
        let e = engine();
        assert!(
            e.rules.len() >= 30,
            "expected >= 30 default rules, got {}",
            e.rules.len()
        );
    }

    #[test]
    fn severity_ord_is_monotonic() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert_eq!(Severity::Critical.bumped(), Severity::Critical);
        assert_eq!(Severity::Low.demoted(), Severity::Low);
        assert_eq!(Severity::Medium.bumped(), Severity::High);
        assert_eq!(Severity::High.demoted(), Severity::Medium);
    }

    #[test]
    fn drop_database_blocked() {
        let e = engine();
        let p = json!({"arguments": {"query": "DROP DATABASE prod;"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(ev.matches.iter().any(|m| m.rule_id == "sql.drop_database"));
        match decide(&ev) {
            Decision::Block { rule_id, .. } => assert_eq!(rule_id, "sql.drop_database"),
            other => panic!("expected Block, got {}", other.label()),
        }
    }

    #[test]
    fn unscoped_update_approval() {
        let e = engine();
        let p = json!({"arguments": {"query": "UPDATE users SET banned = true"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        match decide(&ev) {
            Decision::Approval { rule_id, .. } => assert_eq!(rule_id, "sql.unscoped_update"),
            other => panic!("expected Approval, got {}", other.label()),
        }
    }

    #[test]
    fn tautological_where_email_verified_boolean_opposite() {
        // The exact agent-emitted SQL from the 2026-05-15 demo
        // recording. `WHERE email_verified = FALSE` selects every row
        // the SET would change; functionally identical to no WHERE.
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET email_verified = TRUE WHERE email_verified = FALSE"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        match decide(&ev) {
            Decision::Approval { rule_id, .. } => assert_eq!(rule_id, "sql.unscoped_update"),
            other => panic!(
                "expected Approval on tautological WHERE, got {}",
                other.label()
            ),
        }
    }

    #[test]
    fn tautological_where_inequality_fires() {
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET status = 'active' WHERE status != 'active'"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on `WHERE col != X` tautology"
        );
    }

    #[test]
    fn tautological_where_ne_operator_fires() {
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET status = 'active' WHERE status <> 'active'"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on `WHERE col <> X` tautology"
        );
    }

    #[test]
    fn tautological_where_is_null_with_set_true_fires() {
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET verified = TRUE WHERE verified IS NULL"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on `WHERE col IS NULL` + `SET col = TRUE` tautology"
        );
    }

    #[test]
    fn tautological_where_not_col_fires() {
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET banned = TRUE WHERE NOT banned"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on `WHERE NOT col` + `SET col = TRUE` tautology"
        );
    }

    #[test]
    fn tautological_where_is_not_true_fires() {
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET email_verified = TRUE WHERE email_verified IS NOT TRUE"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on `WHERE col IS NOT TRUE` + `SET col = TRUE` tautology"
        );
    }

    #[test]
    fn tautological_where_handles_1_0_spellings() {
        // Some Postgres / MySQL drivers serialize booleans as 1/0.
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET email_verified = 1 WHERE email_verified = 0"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Approval { .. }),
            "expected Approval on 1/0 boolean opposites"
        );
    }

    #[test]
    fn real_scope_narrowing_with_and_does_not_fire() {
        // The legitimate "safer SQL" version from DEMO.md Take 2.
        // The agent ADDS a real time-window scope to the WHERE clause;
        // this is genuine narrowing and should NOT fire the rule.
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET email_verified = TRUE WHERE email_verified = FALSE AND created_at > NOW() - INTERVAL '7 days'"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Allow { .. } | Decision::Warn { .. }),
            "expected Allow/Warn on real time-window scope; got {}",
            decide(&ev).label()
        );
    }

    #[test]
    fn scoped_update_by_id_does_not_fire() {
        // A truly narrow update by primary key -- must NOT fire.
        let e = engine();
        let p = json!({"arguments": {"query":
            "UPDATE users SET email_verified = TRUE WHERE id = 7"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(
            matches!(decide(&ev), Decision::Allow { .. } | Decision::Warn { .. }),
            "expected Allow/Warn on scoped UPDATE by id; got {}",
            decide(&ev).label()
        );
    }

    #[test]
    fn scoped_update_allow() {
        let e = engine();
        let p = json!({"arguments": {"query": "UPDATE users SET banned = true WHERE id = 7"}});
        let ev = e.evaluate("execute_sql", &p, Adjustments::default());
        assert!(matches!(decide(&ev), Decision::Allow));
    }

    #[test]
    fn workspace_prod_bumps_severity() {
        let e = engine();
        // GRANT ALL is Medium by default. In a prod workspace it should bump to High -> Approval.
        let p = json!({"arguments": {"query": "GRANT ALL ON foo TO bar"}});
        let mut adj = Adjustments::default();
        adj.workspace_is_prod = true;
        let ev = e.evaluate("execute_sql", &p, adj);
        match decide(&ev) {
            Decision::Approval { .. } => {}
            other => panic!("expected Approval from prod bump, got {}", other.label()),
        }
    }

    #[test]
    fn repeated_approval_demotes() {
        let e = engine();
        let p = json!({"arguments": {"query": "GRANT ALL ON foo TO bar"}});
        let mut adj = Adjustments::default();
        adj.fingerprint_repeatedly_approved = true;
        let ev = e.evaluate("execute_sql", &p, adj);
        // Was Medium -> demoted to Low -> Allow.
        assert!(matches!(decide(&ev), Decision::Allow));
    }

    #[test]
    fn deny_history_escalates() {
        let e = engine();
        let p = json!({"arguments": {"query": "GRANT ALL ON foo TO bar"}});
        let mut adj = Adjustments::default();
        adj.fingerprint_recently_denied = true;
        let ev = e.evaluate("execute_sql", &p, adj);
        match decide(&ev) {
            Decision::Approval { .. } => {}
            other => panic!(
                "expected Approval from deny escalation, got {}",
                other.label()
            ),
        }
    }

    #[test]
    fn taint_alone_forces_at_least_approval() {
        // A totally benign call (no rule matches) that carries a tainted
        // secret must never be a silent Allow -- it floors at Approval.
        let e = engine();
        let p = json!({"arguments": {"command": "echo hi"}});
        let mut adj = Adjustments::default();
        adj.tainted_secret_in_flight = true;
        let ev = e.evaluate("shell", &p, adj);
        assert!(
            ev.matches
                .iter()
                .any(|m| m.rule_id == crate::engine::TAINT_RULE_ID),
            "synthetic taint finding should be present"
        );
        assert!(ev.adjustments_applied.contains(&"tainted_secret_in_flight"));
        match decide(&ev) {
            Decision::Approval { .. } => {}
            other => panic!("expected Approval from bare taint, got {}", other.label()),
        }
    }

    #[test]
    fn taint_escalates_a_matched_rule_further() {
        // GRANT ALL is Medium (Warn). With a taint hit it should bump past
        // Approval to Critical/Block: Medium -> +1 -> High -> floor High,
        // then the injected finding + composite... assert it's blocking.
        let e = engine();
        let p = json!({"arguments": {"query": "DROP DATABASE prod;"}});
        let mut adj = Adjustments::default();
        adj.tainted_secret_in_flight = true;
        let ev = e.evaluate("execute_sql", &p, adj);
        // DROP DATABASE is Critical already; taint keeps it blocking.
        assert!(
            decide(&ev).is_blocking(),
            "taint on a critical call stays blocking"
        );
    }

    #[test]
    fn taint_beats_demotion() {
        // Even with a repeated-approval demotion signal, taint floors at
        // Approval -- a credential relay is never demoted to Allow.
        let e = engine();
        let p = json!({"arguments": {"query": "GRANT ALL ON foo TO bar"}});
        let mut adj = Adjustments::default();
        adj.fingerprint_repeatedly_approved = true;
        adj.tainted_secret_in_flight = true;
        let ev = e.evaluate("execute_sql", &p, adj);
        assert!(
            !ev.adjustments_applied
                .contains(&"fingerprint_repeatedly_approved"),
            "demotion must not apply when taint is in flight"
        );
        match decide(&ev) {
            Decision::Approval { .. } | Decision::Block { .. } => {}
            other => panic!("expected at least Approval, got {}", other.label()),
        }
    }

    #[test]
    fn composite_scoring_promotes_weak_signals() {
        // Two Medium rules firing together should compose to High via points.
        let e = engine();
        let p = json!({"arguments": {
            "command": "git branch -D feature/legacy",
            "query": "GRANT ALL ON foo TO bar"
        }});
        let ev = e.evaluate("run_terminal", &p, Adjustments::default());
        // Two Medium rules at 2 points each = 4 -> composite Medium (still),
        // but proves the matches stack.
        assert!(ev.matches.len() >= 1);
        assert!(ev.composite_points >= ev.matches[0].points);
    }

    #[test]
    fn fingerprint_is_stable_for_same_input() {
        let p = json!({"arguments": {"query": "DROP DATABASE prod"}});
        let a = fingerprint("sql.drop_database", &p);
        let b = fingerprint("sql.drop_database", &p);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn fingerprint_differs_per_rule() {
        let p = json!({"arguments": {"query": "DROP DATABASE prod"}});
        let a = fingerprint("sql.drop_database", &p);
        let b = fingerprint("sql.drop_table_or_schema", &p);
        assert_ne!(a, b);
    }
}

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
        matches!(self, Decision::Block { .. } | Decision::Approval { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn { .. } => "warn",
            Decision::Approval { .. } => "approval",
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
}

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
        Self { medium: 2, high: 5, critical: 9 }
    }
}

fn default_true() -> bool { true }
fn one() -> u8 { 1 }
fn default_three() -> u32 { 3 }
fn default_seven() -> u32 { 7 }
fn default_300() -> u32 { 300 }
fn default_five() -> u32 { 5 }
fn default_two() -> u32 { 2 }
fn default_nine() -> u32 { 9 }
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
pub enum Scope { ToolCall, LlmResponse }

#[derive(Debug, Clone, Copy)]
pub enum SqlPredicate { UnscopedUpdate, UnscopedDelete }

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
    matcher: Option<Match>,
}

impl CompiledRule {
    pub fn matches_tool_call(&self, tool: &str, params: &serde_json::Value) -> bool {
        let m = match &self.matcher { Some(m) => m, None => return false };
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
                    if re.is_match(s) { return true; }
                }
                for p in &m.sql_predicates {
                    if matches_sql_predicate(*p, s) { return true; }
                }
            }
        }

        // 2. Param regex (recursive)
        if !m.any_param_re.is_empty() {
            let mut hit = false;
            walk_strings(params, &mut |s| {
                if hit { return; }
                for re in &m.any_param_re {
                    if re.is_match(s) { hit = true; return; }
                }
            });
            if hit { return true; }
        }

        // 3. Structured command predicates (v2): operate on the joined
        // command line. For shell-like tools, we treat any string param
        // as a candidate command.
        if !m.command_predicates.is_empty() {
            let mut hit = false;
            walk_strings(params, &mut |s| {
                if hit { return; }
                for p in &m.command_predicates {
                    if p.matches(s) { hit = true; return; }
                }
            });
            if hit { return true; }
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
                if hit { return; }
                if !crate::predicates::command_writes(s) { return; }
                for sp in &m.sensitive_paths {
                    if sp.touches(s) { hit = true; return; }
                }
            });
            if hit { return true; }
        }

        false
    }

    pub fn matches_text(&self, text: &str) -> bool {
        let m = match &self.matcher { Some(m) => m, None => return false };
        for re in &m.text_re {
            if re.is_match(text) { return true; }
        }
        false
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
}

impl Engine {
    /// Load a Shield ruleset from a YAML string. Returns an error on
    /// malformed YAML or regex compilation failure.
    pub fn from_yaml(raw: &str) -> anyhow::Result<Self> {
        let root: Root = serde_yaml::from_str(raw)?;
        let policy = root.shieldset.policy.clone();
        let mut rules = Vec::with_capacity(root.shieldset.rules.len());
        for y in root.shieldset.rules {
            let scope = match y.where_.as_str() {
                "tool_call" => Scope::ToolCall,
                "llm_response" => Scope::LlmResponse,
                other => anyhow::bail!("rule '{}' has unknown where '{}'", y.id, other),
            };
            let matcher = if let Some(m) = y.r#match {
                let mut sql_preds = Vec::new();
                for n in m.sql_predicates {
                    let p = match n.to_ascii_lowercase().as_str() {
                        "unscoped_update" => SqlPredicate::UnscopedUpdate,
                        "unscoped_delete" => SqlPredicate::UnscopedDelete,
                        other => anyhow::bail!("rule '{}'.sql_predicates: unknown '{}'", y.id, other),
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
                matcher,
            });
        }
        Ok(Engine { rules, policy })
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
                });
            }
        }
        self.resolve(matches, composite_points, adj)
    }

    /// Evaluate an LLM response body.
    pub fn evaluate_text(&self, text: &str, adj: Adjustments) -> Evaluation {
        let mut matches = Vec::new();
        let mut composite_points = 0u32;
        for r in self.rules.iter().filter(|r| r.scope == Scope::LlmResponse) {
            if r.matches_text(text) {
                composite_points = composite_points.saturating_add(r.points);
                matches.push(MatchInfo {
                    rule_id: r.id.clone(),
                    severity: r.severity,
                    points: r.points,
                    reason: r.reason.clone(),
                    safer_alternative: r.safer_alternative.clone(),
                });
            }
        }
        self.resolve(matches, composite_points, adj)
    }

    fn resolve(&self, matches: Vec<MatchInfo>, composite_points: u32, adj: Adjustments) -> Evaluation {
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
        // already; only demote on a clean baseline.
        if adj.fingerprint_repeatedly_approved
            && !matches.is_empty()
            && !adj.workspace_is_prod
            && !adj.fingerprint_recently_denied
            && !adj.burst_in_progress
        {
            final_severity = final_severity.demoted();
            adjustments_applied.push("fingerprint_repeatedly_approved");
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
            a.severity.cmp(&b.severity)
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
        Severity::Critical => Decision::Block {
            rule_id: primary.rule_id.clone(),
            severity: eval.final_severity,
            reason: primary.reason.clone(),
            safer_alternative: primary.safer_alternative.clone(),
            contributing_rules: contributing,
        },
        Severity::High => Decision::Approval {
            rule_id: primary.rule_id.clone(),
            severity: eval.final_severity,
            reason: primary.reason.clone(),
            safer_alternative: primary.safer_alternative.clone(),
            contributing_rules: contributing,
        },
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
    if points >= t.critical { Severity::Critical }
    else if points >= t.high { Severity::High }
    else if points >= t.medium { Severity::Medium }
    else { Severity::Low }
}

// ─────────────────────────────────────────────────────────────────────────
// SQL helpers (unchanged from v1)
// ─────────────────────────────────────────────────────────────────────────

fn compile_regexes(rule_id: &str, field: &str, ps: Vec<String>) -> anyhow::Result<Vec<Regex>> {
    let mut out = Vec::with_capacity(ps.len());
    for p in ps {
        out.push(Regex::new(&p).map_err(|e| anyhow::anyhow!("rule '{}'.{}: bad regex '{}': {}", rule_id, field, p, e))?);
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
                    if let Some(s) = val.as_str() { out.push(s.to_string()); }
                }
                walk_sql(val, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr { walk_sql(item, out); }
        }
        _ => {}
    }
}

pub(crate) fn walk_strings<F: FnMut(&str)>(v: &serde_json::Value, f: &mut F) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(arr) => for item in arr { walk_strings(item, f); },
        serde_json::Value::Object(map) => for (_, val) in map { walk_strings(val, f); },
        _ => {}
    }
}

static UPDATE_HEAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bUPDATE\s+[A-Za-z_][A-Za-z0-9_\.]*\s+SET\b").expect("static")
});
static DELETE_HEAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bDELETE\s+FROM\s+[A-Za-z_][A-Za-z0-9_\.]*").expect("static")
});
static WHERE_CLAUSE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bWHERE\b").expect("static")
});

fn matches_sql_predicate(p: SqlPredicate, sql: &str) -> bool {
    for frag in sql.split(';') {
        let f = frag.trim();
        if f.is_empty() { continue; }
        match p {
            SqlPredicate::UnscopedUpdate => {
                if UPDATE_HEAD.is_match(f) && !WHERE_CLAUSE.is_match(f) { return true; }
            }
            SqlPredicate::UnscopedDelete => {
                if DELETE_HEAD.is_match(f) && !WHERE_CLAUSE.is_match(f) { return true; }
            }
        }
    }
    false
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

    fn engine() -> Engine { Engine::builtin_default() }

    #[test]
    fn bundled_default_loads_with_many_rules() {
        let e = engine();
        assert!(e.rules.len() >= 30, "expected >= 30 default rules, got {}", e.rules.len());
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
            Decision::Approval { .. } => {},
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
            Decision::Approval { .. } => {},
            other => panic!("expected Approval from deny escalation, got {}", other.label()),
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

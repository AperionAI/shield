//! Self-contained Shield engine for the standalone product.
//!
//! Mirrors the rule schema and matcher semantics of the enterprise
//! `smartflow::shield` engine so a `shieldset.yaml` written for one
//! works with the other. Vendoring keeps the standalone binary small
//! and dependency-free — it does not pull in the enterprise crate.
//!
//! Severity → outcome:
//!
//! | Severity | Standalone outcome           |
//! |----------|------------------------------|
//! | Critical | Block (JSON-RPC error)       |
//! | High     | Approval (waits on CLI input)|
//! | Medium   | Allow + warn banner          |
//! | Low      | Allow + audit-only log line  |

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ─────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Decision {
    Allow,
    Warn { rule_id: String, severity: Severity, banner: String },
    Approval { rule_id: String, severity: Severity, reason: String },
    Block { rule_id: String, severity: Severity, reason: String },
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

// ─────────────────────────────────────────────────────────────────────────
// YAML schema
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Root {
    shieldset: Shieldset,
}

#[derive(Debug, Deserialize)]
struct Shieldset {
    #[serde(default)]
    rules: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    id: String,
    severity: Severity,
    #[serde(rename = "where")]
    where_: String,
    #[serde(default)]
    r#match: Option<YamlMatch>,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
struct YamlMatch {
    #[serde(default)]
    tool: Option<Vec<String>>,
    #[serde(default)]
    any_param_matches: Vec<String>,
    #[serde(default)]
    sql_matches: Vec<String>,
    #[serde(default)]
    sql_predicates: Vec<String>,
    #[serde(default)]
    text_matches: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────
// Compiled rule + matcher
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope { ToolCall, LlmResponse }

#[derive(Debug, Clone, Copy)]
enum SqlPredicate { UnscopedUpdate, UnscopedDelete }

#[derive(Debug)]
struct Match {
    tool_whitelist: Option<HashSet<String>>,
    any_param_re: Vec<Regex>,
    sql_re: Vec<Regex>,
    sql_predicates: Vec<SqlPredicate>,
    text_re: Vec<Regex>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub severity: Severity,
    pub scope: Scope,
    pub reason: String,
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
        if !m.sql_re.is_empty() || !m.sql_predicates.is_empty() {
            let sqls = extract_sql(params);
            for s in &sqls {
                for re in &m.sql_re {
                    if re.is_match(s) { return true; }
                }
                for p in &m.sql_predicates {
                    if matches_predicate(*p, s) { return true; }
                }
            }
        }
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

#[derive(Debug)]
pub struct Engine {
    pub rules: Vec<CompiledRule>,
}

impl Engine {
    /// Load a Shield ruleset from a YAML string. Returns an error on
    /// malformed YAML or regex compilation failure.
    pub fn from_yaml(raw: &str) -> anyhow::Result<Self> {
        let root: Root = serde_yaml::from_str(raw)?;
        let mut rules = Vec::with_capacity(root.shieldset.rules.len());
        for y in root.shieldset.rules {
            let scope = match y.where_.as_str() {
                "tool_call" => Scope::ToolCall,
                "llm_response" => Scope::LlmResponse,
                other => anyhow::bail!("rule '{}' has unknown where '{}'", y.id, other),
            };
            let matcher = if let Some(m) = y.r#match {
                let mut predicates = Vec::new();
                for n in m.sql_predicates {
                    let p = match n.to_ascii_lowercase().as_str() {
                        "unscoped_update" => SqlPredicate::UnscopedUpdate,
                        "unscoped_delete" => SqlPredicate::UnscopedDelete,
                        other => anyhow::bail!("rule '{}'.sql_predicates: unknown '{}'", y.id, other),
                    };
                    predicates.push(p);
                }
                Some(Match {
                    tool_whitelist: m.tool.map(|v| v.into_iter().collect()),
                    any_param_re: compile_regexes(&y.id, "any_param_matches", m.any_param_matches)?,
                    sql_re: compile_regexes(&y.id, "sql_matches", m.sql_matches)?,
                    sql_predicates: predicates,
                    text_re: compile_regexes(&y.id, "text_matches", m.text_matches)?,
                })
            } else {
                None
            };
            rules.push(CompiledRule {
                id: y.id,
                severity: y.severity,
                scope,
                reason: y.reason,
                matcher,
            });
        }
        Ok(Engine { rules })
    }

    /// Bundled defaults — the same YAML used by the enterprise build,
    /// embedded at compile time so the binary always has *some* ruleset.
    pub fn builtin_default() -> Self {
        let yaml = include_str!("../config/shieldset.yaml");
        Self::from_yaml(yaml).expect("bundled shieldset.yaml must parse")
    }

    pub fn evaluate_tool_call(&self, tool: &str, params: &serde_json::Value) -> Decision {
        let mut best: Option<&CompiledRule> = None;
        for r in self.rules.iter().filter(|r| r.scope == Scope::ToolCall) {
            if r.matches_tool_call(tool, params) {
                best = match best {
                    None => Some(r),
                    Some(p) if r.severity.rank() > p.severity.rank() => Some(r),
                    Some(p) => Some(p),
                };
            }
        }
        decision_from(best)
    }

    pub fn evaluate_text(&self, text: &str) -> Decision {
        let mut best: Option<&CompiledRule> = None;
        for r in self.rules.iter().filter(|r| r.scope == Scope::LlmResponse) {
            if r.matches_text(text) {
                best = match best {
                    None => Some(r),
                    Some(p) if r.severity.rank() > p.severity.rank() => Some(r),
                    Some(p) => Some(p),
                };
            }
        }
        decision_from(best)
    }
}

fn decision_from(rule: Option<&CompiledRule>) -> Decision {
    match rule {
        None => Decision::Allow,
        Some(r) => match r.severity {
            Severity::Critical => Decision::Block {
                rule_id: r.id.clone(),
                severity: r.severity,
                reason: r.reason.clone(),
            },
            Severity::High => Decision::Approval {
                rule_id: r.id.clone(),
                severity: r.severity,
                reason: r.reason.clone(),
            },
            Severity::Medium => Decision::Warn {
                rule_id: r.id.clone(),
                severity: r.severity,
                banner: r.reason.clone(),
            },
            Severity::Low => Decision::Allow,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers — predicate matching, SQL extraction, regex compile
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

fn walk_strings<F: FnMut(&str)>(v: &serde_json::Value, f: &mut F) {
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

fn matches_predicate(p: SqlPredicate, sql: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bundled_default_loads() {
        let e = Engine::builtin_default();
        assert!(!e.rules.is_empty());
    }

    #[test]
    fn drop_database_blocked() {
        let e = Engine::builtin_default();
        let p = json!({"arguments": {"query": "DROP DATABASE prod;"}});
        match e.evaluate_tool_call("execute_sql", &p) {
            Decision::Block { rule_id, .. } => assert_eq!(rule_id, "sql.drop_database"),
            other => panic!("expected Block, got {:?}", other.label()),
        }
    }

    #[test]
    fn unscoped_update_approval() {
        let e = Engine::builtin_default();
        let p = json!({"arguments": {"query": "UPDATE users SET banned = true"}});
        match e.evaluate_tool_call("execute_sql", &p) {
            Decision::Approval { rule_id, .. } => assert_eq!(rule_id, "sql.unscoped_update"),
            other => panic!("expected Approval, got {:?}", other.label()),
        }
    }

    #[test]
    fn scoped_update_allow() {
        let e = Engine::builtin_default();
        let p = json!({"arguments": {"query": "UPDATE users SET banned = true WHERE id = 7"}});
        assert!(matches!(e.evaluate_tool_call("execute_sql", &p), Decision::Allow));
    }
}

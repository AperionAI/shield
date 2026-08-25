//! Suggestion generator. Walks audit records + the current shieldset
//! and emits a list of actionable rule-tuning [`Suggestion`]s.
//!
//! ## Suggestion taxonomy (v0.7)
//!
//! Three kinds, each with a documented confidence floor. We
//! deliberately err on the side of FEWER suggestions: the cost of a
//! wrong "lower this rule" recommendation is real (the user might
//! actually act on it and create a hole), whereas the cost of an
//! omitted suggestion is bounded (the rule keeps doing its job).
//!
//! | Variant            | Trigger                                              | Risk        |
//! |--------------------|------------------------------------------------------|-------------|
//! | `RuleNeverFires`   | Rule is in the shieldset but produced 0 audit rows  | LOW (info)  |
//! |                    | over the analysis window. We DO NOT recommend       |             |
//! |                    | removing -- we recommend the operator review.        |             |
//! | `ConsistentlyDemoted` | Final severity has been strictly LOWER than raw  | LOW         |
//! |                    | severity in ≥ `min_occurrences` audit rows. The      |             |
//! |                    | adaptive layer is doing the work the static          |             |
//! |                    | severity wishes it could -- consider lowering.       |             |
//! | `NoisyWarn`        | Rule fires ≥ `min_occurrences` times in the window  | MEDIUM      |
//! |                    | AND every observed decision was Warn (never          |             |
//! |                    | escalated to Approval / Block). Suggest making it    |             |
//! |                    | informational-only (Low severity, decision: warn).   |             |
//!
//! We deliberately do NOT emit "ADD_RULE for an uncovered destructive
//! pattern" suggestions in v0.7. That requires running a heuristic
//! over `params` content, which the standalone audit log doesn't
//! capture (only `tool` + `primary_rule_id` + `fingerprint` are
//! logged). Adding param-content capture is a v0.8 conversation
//! because of the privacy implications (audit log starts containing
//! SQL fragments, file paths, etc.).

use crate::engine::Engine;
use crate::suggest::audit::AuditRecord;
use std::collections::{BTreeMap, HashSet};

/// A single tuning recommendation. Caller decides whether to apply.
#[derive(Debug, Clone)]
pub enum Suggestion {
    /// Rule is loaded but produced no audit rows over the window.
    /// Either the operator doesn't need it (consider removing) or
    /// nobody's tried to do that destructive thing yet (keep it).
    RuleNeverFires {
        rule_id: String,
        window_days: Option<u32>,
    },

    /// The adaptive layer has been demoting this rule on every fire
    /// for ≥ min_occurrences observations.  The static severity is
    /// probably too high.
    ConsistentlyDemoted {
        rule_id: String,
        observed_fires: usize,
        raw_severity: String,
        observed_final: String,
    },

    /// The rule fires a lot AND every observation resolved to Warn
    /// (never Approval / Block). Consider demoting to informational
    /// so it stops eating composite-score headroom for other rules.
    NoisyWarn {
        rule_id: String,
        observed_fires: usize,
    },
}

impl Suggestion {
    pub fn rule_id(&self) -> &str {
        match self {
            Suggestion::RuleNeverFires { rule_id, .. } => rule_id,
            Suggestion::ConsistentlyDemoted { rule_id, .. } => rule_id,
            Suggestion::NoisyWarn { rule_id, .. } => rule_id,
        }
    }

    /// One-line kind label for tabular output.
    pub fn kind(&self) -> &'static str {
        match self {
            Suggestion::RuleNeverFires { .. } => "RULE_NEVER_FIRES",
            Suggestion::ConsistentlyDemoted { .. } => "CONSISTENTLY_DEMOTED",
            Suggestion::NoisyWarn { .. } => "NOISY_WARN",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnalyzeOptions {
    pub window_days: Option<u32>,
    pub min_occurrences: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            window_days: Some(30),
            min_occurrences: 5,
        }
    }
}

/// Bookkeeping per rule_id across the window.
#[derive(Debug, Default, Clone)]
pub struct RuleStats {
    pub fires: usize,
    /// Distinct `decision` strings observed (allow/warn/approval/block/identity_verification).
    pub decisions: BTreeMap<String, usize>,
    /// Distinct `raw_severity` observed -- usually one value per rule,
    /// since the static severity comes from the YAML.
    pub raw_severities: HashSet<String>,
    /// All observed `final_severity` values. Useful for detecting
    /// "raw -> final" demotion patterns from the adaptive layer.
    pub final_severities: HashSet<String>,
    /// Number of fires where final_severity STRICTLY lower than
    /// raw_severity. (Used by `ConsistentlyDemoted`.)
    pub demotions: usize,
}

/// Aggregate per-rule stats across the audit window.
pub fn aggregate(records: &[AuditRecord]) -> BTreeMap<String, RuleStats> {
    let mut out: BTreeMap<String, RuleStats> = BTreeMap::new();
    for r in records {
        let entry = out.entry(r.primary_rule_id.clone()).or_default();
        entry.fires += 1;
        *entry.decisions.entry(r.decision.clone()).or_insert(0) += 1;
        entry.raw_severities.insert(r.raw_severity.clone());
        entry.final_severities.insert(r.final_severity.clone());
        if severity_rank(&r.final_severity) < severity_rank(&r.raw_severity) {
            entry.demotions += 1;
        }
    }
    out
}

/// Generate suggestions from per-rule stats + the loaded engine (so we
/// know which rule IDs exist in the current shieldset, even if they
/// never fired in the audit window).
pub fn analyze(engine: &Engine, records: &[AuditRecord], opts: AnalyzeOptions) -> Vec<Suggestion> {
    let stats = aggregate(records);
    let mut out: Vec<Suggestion> = Vec::new();

    // 1. RULE_NEVER_FIRES — iterate engine rules, not audit log,
    //    because by definition the audit log won't mention them.
    for rule in &engine.rules {
        if !stats.contains_key(&rule.id) {
            out.push(Suggestion::RuleNeverFires {
                rule_id: rule.id.clone(),
                window_days: opts.window_days,
            });
        }
    }

    // 2 & 3. From the rules that DID fire.
    for (rule_id, s) in &stats {
        // ConsistentlyDemoted: every fire was a demotion AND fires meet the threshold.
        if s.fires >= opts.min_occurrences && s.demotions == s.fires {
            // Pick the lowest final severity we ever observed -- that's
            // probably the right target for the static severity.
            let lowest_final =
                lowest_severity(&s.final_severities).unwrap_or_else(|| "Low".to_string());
            let raw_one = s
                .raw_severities
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string());
            out.push(Suggestion::ConsistentlyDemoted {
                rule_id: rule_id.clone(),
                observed_fires: s.fires,
                raw_severity: raw_one,
                observed_final: lowest_final,
            });
            continue; // mutually exclusive with NoisyWarn
        }

        // NoisyWarn: fires often AND every observation was Warn.
        if s.fires >= opts.min_occurrences {
            let only_warn = s.decisions.len() == 1 && s.decisions.contains_key("warn");
            if only_warn {
                out.push(Suggestion::NoisyWarn {
                    rule_id: rule_id.clone(),
                    observed_fires: s.fires,
                });
            }
        }
    }

    out
}

/// Ordering of severities as Shield uses them. Higher = more severe.
fn severity_rank(s: &str) -> u8 {
    match s {
        "Low" => 1,
        "Medium" => 2,
        "High" => 3,
        "Critical" => 4,
        _ => 0,
    }
}

/// Pick the lowest severity by [`severity_rank`] in a set.
fn lowest_severity(set: &HashSet<String>) -> Option<String> {
    set.iter()
        .filter(|s| severity_rank(s) > 0)
        .min_by_key(|s| severity_rank(s))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn rec(rule: &str, decision: &str, raw: &str, fin: &str) -> AuditRecord {
        AuditRecord {
            ts: Utc::now(),
            kind: "shield_eval".into(),
            tool: "execute_sql".into(),
            primary_rule_id: rule.into(),
            fingerprint: "fp".into(),
            matched_rules: vec![rule.into()],
            raw_severity: raw.into(),
            composite_points: 1,
            composite_severity: raw.into(),
            final_severity: fin.into(),
            decision: decision.into(),
        }
    }

    #[test]
    fn aggregate_counts_fires_and_demotions() {
        let records = vec![
            rec("sql.grant_all", "warn", "Medium", "Low"),
            rec("sql.grant_all", "warn", "Medium", "Low"),
            rec("sql.grant_all", "warn", "Medium", "Low"),
        ];
        let stats = aggregate(&records);
        let s = stats.get("sql.grant_all").unwrap();
        assert_eq!(s.fires, 3);
        assert_eq!(s.demotions, 3);
        assert_eq!(s.decisions.get("warn").copied(), Some(3));
    }

    #[test]
    fn analyze_emits_rule_never_fires_for_loaded_unfired_rules() {
        let engine = crate::engine::Engine::builtin_default();
        let records: Vec<AuditRecord> = vec![]; // no fires at all
        let suggestions = analyze(&engine, &records, AnalyzeOptions::default());
        // Every rule in the bundled shieldset should show up.
        let never_fires_count = suggestions
            .iter()
            .filter(|s| matches!(s, Suggestion::RuleNeverFires { .. }))
            .count();
        assert_eq!(never_fires_count, engine.rules.len());
    }

    #[test]
    fn analyze_emits_consistently_demoted_for_always_demoted_rule() {
        let engine = crate::engine::Engine::builtin_default();
        let rule_id = engine.rules[0].id.clone(); // any real rule
        let records: Vec<AuditRecord> = (0..6)
            .map(|_| rec(&rule_id, "warn", "Critical", "Low"))
            .collect();
        let suggestions = analyze(
            &engine,
            &records,
            AnalyzeOptions {
                window_days: None,
                min_occurrences: 5,
            },
        );
        let demoted: Vec<_> = suggestions
            .iter()
            .filter_map(|s| match s {
                Suggestion::ConsistentlyDemoted { rule_id: r, .. } if r == &rule_id => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(
            demoted.len(),
            1,
            "expected one CONSISTENTLY_DEMOTED for {}",
            rule_id
        );
    }

    #[test]
    fn analyze_emits_noisy_warn_for_always_warn_rule() {
        let engine = crate::engine::Engine::builtin_default();
        let rule_id = engine.rules[0].id.clone();
        let records: Vec<AuditRecord> = (0..6)
            // raw == final → not demoted; but always Warn → NoisyWarn fires
            .map(|_| rec(&rule_id, "warn", "Medium", "Medium"))
            .collect();
        let suggestions = analyze(
            &engine,
            &records,
            AnalyzeOptions {
                window_days: None,
                min_occurrences: 5,
            },
        );
        let noisy: Vec<_> = suggestions
            .iter()
            .filter(|s| matches!(s, Suggestion::NoisyWarn { rule_id: r, .. } if r == &rule_id))
            .collect();
        assert_eq!(noisy.len(), 1);
    }

    #[test]
    fn analyze_does_not_double_emit_demoted_and_noisy_for_same_rule() {
        let engine = crate::engine::Engine::builtin_default();
        let rule_id = engine.rules[0].id.clone();
        // 6 demotions, all warn -- this is both "consistently demoted"
        // (because every fire was a demotion) AND "all warn", but we
        // documented these as mutually exclusive so DEMOTED wins.
        let records: Vec<AuditRecord> = (0..6)
            .map(|_| rec(&rule_id, "warn", "Critical", "Low"))
            .collect();
        let suggestions = analyze(
            &engine,
            &records,
            AnalyzeOptions {
                window_days: None,
                min_occurrences: 5,
            },
        );
        let for_this_rule: Vec<_> = suggestions
            .iter()
            .filter(|s| s.rule_id() == rule_id)
            .collect();
        assert_eq!(
            for_this_rule.len(),
            1,
            "expected one suggestion, got {:#?}",
            for_this_rule
        );
        assert!(matches!(
            for_this_rule[0],
            Suggestion::ConsistentlyDemoted { .. }
        ));
    }
}

//! Render a list of [`Suggestion`]s for human + machine consumption.
//!
//! Three formats:
//!
//!  * **text** — terminal-friendly, grouped by suggestion kind. Default.
//!  * **markdown** — copy-paste into a PR review or issue. Same shape
//!    as the text format but with `##` headings + bullet lists.
//!  * **yaml-patch** — partial-shieldset YAML snippets the operator can
//!    splice into their `shieldset.yaml`. Each snippet has a
//!    `# rationale:` comment line that explains why the change is
//!    suggested.
//!
//! All three formats include the same per-suggestion fields (rule_id,
//! kind, evidence). What differs is the wrapping.

use crate::suggest::analyze::Suggestion;
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Markdown,
    YamlPatch,
}

impl OutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "markdown" | "md" => Ok(Self::Markdown),
            "yaml-patch" | "yaml" | "patch" => Ok(Self::YamlPatch),
            _ => anyhow::bail!(
                "unknown --format '{}'. Valid: text | markdown | yaml-patch",
                s
            ),
        }
    }
}

pub fn render(suggestions: &[Suggestion], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text(suggestions),
        OutputFormat::Markdown => render_markdown(suggestions),
        OutputFormat::YamlPatch => render_yaml_patch(suggestions),
    }
}

fn render_text(suggestions: &[Suggestion]) -> String {
    let mut out = String::new();
    if suggestions.is_empty() {
        out.push_str("[shield-suggest-rules] No tuning suggestions — your shieldset is well-fit for the audit window.\n");
        return out;
    }
    let _ = writeln!(out, "[shield-suggest-rules] {} suggestion(s):\n", suggestions.len());
    for s in suggestions {
        match s {
            Suggestion::RuleNeverFires { rule_id, window_days } => {
                let _ = writeln!(
                    out,
                    "  [{kind}] {rid}",
                    kind = s.kind(),
                    rid = rule_id,
                );
                match window_days {
                    Some(d) => {
                        let _ = writeln!(out, "    Did not fire over the last {} day(s) of audit log.", d);
                    }
                    None => {
                        let _ = writeln!(out, "    Did not fire over the audit log window.");
                    }
                }
                let _ = writeln!(
                    out,
                    "    Suggestion: review whether this rule is still needed for your\n               \
                     environment. Do NOT remove blindly — \"never fired\" can mean\n               \
                     \"nobody's tried this destructive thing yet,\" which is exactly\n               \
                     the case Shield exists for.\n",
                );
            }
            Suggestion::ConsistentlyDemoted {
                rule_id,
                observed_fires,
                raw_severity,
                observed_final,
            } => {
                let _ = writeln!(out, "  [{}] {}", s.kind(), rule_id);
                let _ = writeln!(
                    out,
                    "    Fired {} time(s); the adaptive layer demoted EVERY observation\n    from `{}` down to `{}`.\n    Suggestion: bump the static `severity:` from {} to {} (or remove\n    `severity:` entirely and let the adaptive layer decide).\n",
                    observed_fires, raw_severity, observed_final, raw_severity, observed_final,
                );
            }
            Suggestion::NoisyWarn { rule_id, observed_fires } => {
                let _ = writeln!(out, "  [{}] {}", s.kind(), rule_id);
                let _ = writeln!(
                    out,
                    "    Fired {} time(s); every observation resolved to `warn` (never\n    escalated). This rule is eating composite-score headroom for\n    higher-stakes rules without ever blocking the call.\n    Suggestion: consider dropping severity to `Low` so it stops\n    contributing composite points OR add an exclude rule for the\n    specific call shape that's spamming it.\n",
                    observed_fires,
                );
            }
        }
    }
    out
}

fn render_markdown(suggestions: &[Suggestion]) -> String {
    let mut out = String::new();
    if suggestions.is_empty() {
        out.push_str("## Aperion Shield — rule tuning suggestions\n\nNo tuning suggestions for this audit window. Your shieldset is well-fit.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "## Aperion Shield — rule tuning suggestions\n\n{} suggestion(s) from analyzing your audit log.\n",
        suggestions.len()
    );
    for s in suggestions {
        match s {
            Suggestion::RuleNeverFires { rule_id, window_days } => {
                let _ = writeln!(out, "### `{}` — never fires", rule_id);
                match window_days {
                    Some(d) => {
                        let _ = writeln!(out, "\n- **Kind:** `RULE_NEVER_FIRES`");
                        let _ = writeln!(out, "- **Evidence:** 0 audit rows over the last {} day(s).", d);
                    }
                    None => {
                        let _ = writeln!(out, "\n- **Kind:** `RULE_NEVER_FIRES`");
                        let _ = writeln!(out, "- **Evidence:** 0 audit rows over the analyzed window.");
                    }
                }
                let _ = writeln!(
                    out,
                    "- **Suggestion:** review whether this rule is still needed for your environment. *Do not remove blindly* — \"never fired\" can mean \"nobody's tried this destructive thing yet,\" which is exactly the case Shield exists for.\n"
                );
            }
            Suggestion::ConsistentlyDemoted {
                rule_id,
                observed_fires,
                raw_severity,
                observed_final,
            } => {
                let _ = writeln!(out, "### `{}` — consistently demoted", rule_id);
                let _ = writeln!(out, "\n- **Kind:** `CONSISTENTLY_DEMOTED`");
                let _ = writeln!(
                    out,
                    "- **Evidence:** {} fires; the adaptive layer demoted every observation from `{}` to `{}`.",
                    observed_fires, raw_severity, observed_final,
                );
                let _ = writeln!(
                    out,
                    "- **Suggestion:** bump static `severity:` from `{}` to `{}`, or remove `severity:` entirely and let the adaptive layer continue to do the job it's already doing.\n",
                    raw_severity, observed_final,
                );
            }
            Suggestion::NoisyWarn { rule_id, observed_fires } => {
                let _ = writeln!(out, "### `{}` — noisy warn", rule_id);
                let _ = writeln!(out, "\n- **Kind:** `NOISY_WARN`");
                let _ = writeln!(
                    out,
                    "- **Evidence:** {} fires, all resolving to `warn`. Never escalated.",
                    observed_fires,
                );
                let _ = writeln!(
                    out,
                    "- **Suggestion:** drop severity to `Low` so it stops contributing composite-score points, or add an exclude rule for the call shape that's spamming it.\n",
                );
            }
        }
    }
    out
}

fn render_yaml_patch(suggestions: &[Suggestion]) -> String {
    let mut out = String::new();
    out.push_str(
        "# aperion-shield --suggest-rules YAML patch\n\
         # Apply by hand to your shieldset.yaml. Each block is a partial\n\
         # rule update — splice the `severity:` / `excludes:` fields into\n\
         # the matching rule. Do NOT paste the whole block verbatim.\n\
         #\n",
    );
    if suggestions.is_empty() {
        out.push_str("# (no suggestions)\n");
        return out;
    }
    for s in suggestions {
        match s {
            Suggestion::RuleNeverFires { rule_id, window_days } => {
                let _ = writeln!(out);
                let _ = writeln!(out, "# RULE_NEVER_FIRES: {}", rule_id);
                match window_days {
                    Some(d) => {
                        let _ = writeln!(out, "#   rationale: 0 audit rows in the last {} day(s).", d);
                    }
                    None => {
                        let _ = writeln!(out, "#   rationale: 0 audit rows in the analyzed window.");
                    }
                }
                let _ = writeln!(out, "#   action: REVIEW. We do not auto-suggest removal.");
                let _ = writeln!(out, "# - id: {}\n#   # (left intact — review only)", rule_id);
            }
            Suggestion::ConsistentlyDemoted {
                rule_id,
                observed_fires,
                raw_severity,
                observed_final,
            } => {
                let _ = writeln!(out);
                let _ = writeln!(out, "# CONSISTENTLY_DEMOTED: {}", rule_id);
                let _ = writeln!(
                    out,
                    "#   rationale: {} fires; every one demoted from {} to {}.",
                    observed_fires, raw_severity, observed_final,
                );
                let _ = writeln!(out, "- id: {}", rule_id);
                let _ = writeln!(out, "  severity: {}", observed_final);
            }
            Suggestion::NoisyWarn { rule_id, observed_fires } => {
                let _ = writeln!(out);
                let _ = writeln!(out, "# NOISY_WARN: {}", rule_id);
                let _ = writeln!(
                    out,
                    "#   rationale: {} fires, all resolving to `warn`. Never escalated.",
                    observed_fires,
                );
                let _ = writeln!(out, "- id: {}", rule_id);
                let _ = writeln!(out, "  severity: Low");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::analyze::Suggestion;

    #[test]
    fn parse_format_accepts_aliases() {
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Text);
        assert_eq!(OutputFormat::parse("markdown").unwrap(), OutputFormat::Markdown);
        assert_eq!(OutputFormat::parse("md").unwrap(), OutputFormat::Markdown);
        assert_eq!(OutputFormat::parse("yaml-patch").unwrap(), OutputFormat::YamlPatch);
        assert_eq!(OutputFormat::parse("patch").unwrap(), OutputFormat::YamlPatch);
        assert!(OutputFormat::parse("bogus").is_err());
    }

    #[test]
    fn empty_suggestion_list_renders_a_clean_message_in_each_format() {
        for fmt in [OutputFormat::Text, OutputFormat::Markdown, OutputFormat::YamlPatch] {
            let s = render(&[], fmt);
            assert!(!s.is_empty(), "format {:?} should always render something", fmt);
        }
    }

    #[test]
    fn yaml_patch_emits_severity_block_for_demoted() {
        let suggestions = vec![Suggestion::ConsistentlyDemoted {
            rule_id: "sql.foo".into(),
            observed_fires: 6,
            raw_severity: "Critical".into(),
            observed_final: "Low".into(),
        }];
        let out = render(&suggestions, OutputFormat::YamlPatch);
        assert!(out.contains("- id: sql.foo"));
        assert!(out.contains("severity: Low"));
        assert!(out.contains("CONSISTENTLY_DEMOTED"));
    }

    #[test]
    fn text_format_does_not_recommend_blind_removal() {
        let suggestions = vec![Suggestion::RuleNeverFires {
            rule_id: "sql.unused".into(),
            window_days: Some(30),
        }];
        let out = render(&suggestions, OutputFormat::Text);
        // Must surface the cautionary message.
        assert!(out.contains("Do NOT remove blindly") || out.contains("Do not remove"));
        assert!(out.contains("sql.unused"));
    }
}

//! Output formatters for `aperion-shield --diff`.
//!
//! Three formats: `text` (humans, terminal default), `markdown`
//! (CI / PR comments), and `json` (machine consumers, schema-stable
//! with `scripts/shield-diff.py`).
//!
//! Each renderer takes the same inputs -- the corpus header, the
//! decision distributions before/after, the per-rule deltas (already
//! populated with fires_before/fires_after/flipped_lines_caused),
//! and the flip counter -- and returns a `String`. None of them
//! print directly so that callers can capture the output cleanly
//! (tests, PR-comment posting, etc.).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::json;

use super::{loosening_count, FlipCounter, RuleDelta, DECISIONS};

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Short, single-line summary of one corpus input record. Kept in
/// sync with the Python prototype's `short_input` so flipped-line
/// samples are recognisable across the two implementations.
pub(crate) fn short_input(input: &serde_json::Value, maxlen: usize) -> String {
    let s = if let Some(tool) = input.get("tool").and_then(|v| v.as_str()) {
        let empty = json!({});
        let params = input.get("params").unwrap_or(&empty);
        let key_hit = ["query", "command", "cmd", "sql", "path", "url"]
            .iter()
            .find_map(|k| params.get(k));
        match key_hit {
            Some(v) => {
                let val_str = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                format!("{}: {}", tool, val_str)
            }
            None => {
                let mut blob = params.to_string();
                if blob.len() > 80 {
                    blob.truncate(80);
                }
                format!("{}: {}", tool, blob)
            }
        }
    } else if let Some(text) = input.get("text").and_then(|v| v.as_str()) {
        format!("text: {}", text)
    } else {
        input.to_string()
    };
    let s = s.replace('\n', " ").replace('\t', " ");
    if s.chars().count() <= maxlen {
        s
    } else {
        // Reserve 3 chars for the "..." marker so the final string
        // always fits in `maxlen`.
        let head = maxlen.saturating_sub(3);
        let mut truncated: String = s.chars().take(head).collect();
        truncated.push_str("...");
        truncated
    }
}

fn delta_pct(before: i64, after: i64) -> String {
    let delta = after - before;
    if before == 0 {
        format!("({:+})", delta)
    } else {
        let pct = (delta as f64) / (before as f64) * 100.0;
        format!("({:+}, {:+.1}%)", delta, pct)
    }
}

// ────────────────────────────────────────────────────────────────────
// Text renderer (default)
// ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn render_text(
    before_path: &str,
    after_path: &str,
    corpus_lines: usize,
    decision_before: &BTreeMap<String, usize>,
    decision_after: &BTreeMap<String, usize>,
    deltas: &BTreeMap<String, RuleDelta>,
    flips: &FlipCounter,
    max_samples: usize,
) -> String {
    let mut buf = String::new();
    let _ = writeln!(buf, "shield-diff: {} -> {}", before_path, after_path);
    let _ = writeln!(buf, "corpus:      {} commands\n", fmt_n(corpus_lines));

    let _ = writeln!(buf, "DECISION DISTRIBUTION");
    let _ = writeln!(
        buf,
        "{:<12}{:>10}{:>10}{:>14}",
        "", "before", "after", "delta"
    );
    for d in DECISIONS {
        let b = *decision_before.get(d).unwrap_or(&0);
        let a = *decision_after.get(d).unwrap_or(&0);
        let pct = delta_pct(b as i64, a as i64);
        let _ = writeln!(
            buf,
            "  {:<10}{:>10}{:>10}  {:<14}",
            d,
            fmt_n(b),
            fmt_n(a),
            pct
        );
    }
    buf.push('\n');

    let added: Vec<&RuleDelta> = deltas.values().filter(|d| d.status == "added").collect();
    let removed: Vec<&RuleDelta> = deltas.values().filter(|d| d.status == "removed").collect();
    let modified: Vec<&RuleDelta> = deltas.values().filter(|d| d.status == "modified").collect();
    let unchanged_n = deltas.values().filter(|d| d.status == "unchanged").count();

    let _ = writeln!(buf, "RULESET CHANGES");
    if !added.is_empty() {
        let _ = writeln!(
            buf,
            "  added    ({}): {}",
            added.len(),
            added
                .iter()
                .map(|d| d.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !removed.is_empty() {
        let _ = writeln!(
            buf,
            "  removed  ({}): {}",
            removed.len(),
            removed
                .iter()
                .map(|d| d.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if !modified.is_empty() {
        let _ = writeln!(
            buf,
            "  modified ({}): {}",
            modified.len(),
            modified
                .iter()
                .map(|d| d.rule_id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    let _ = writeln!(buf, "  unchanged: {} rules\n", unchanged_n);

    for d in added.iter().chain(removed.iter()).chain(modified.iter()) {
        let _ = writeln!(buf, "  --- {} ({}) ---", d.rule_id, d.status);
        for line in d.yaml_diff.lines() {
            let _ = writeln!(buf, "    {}", line);
        }
        buf.push('\n');
    }

    let _ = writeln!(buf, "BEHAVIORAL IMPACT BY RULE");
    let mut behavioral: Vec<&RuleDelta> = deltas
        .values()
        .filter(|d| d.fires_before != d.fires_after || !d.flipped_lines_caused.is_empty())
        .collect();
    behavioral.sort_by_key(|d| {
        // largest absolute fire-count delta first
        -((d.fires_after as i64 - d.fires_before as i64).abs())
    });
    if behavioral.is_empty() {
        let _ = writeln!(
            buf,
            "  (no rules changed their fire counts in this corpus)\n"
        );
    } else {
        for d in &behavioral {
            let delta = d.fires_after as i64 - d.fires_before as i64;
            let _ = writeln!(buf, "  {}:", d.rule_id);
            let _ = writeln!(buf, "    fired before:  {} lines", d.fires_before);
            let _ = writeln!(
                buf,
                "    fired after:   {} lines  ({:+})",
                d.fires_after, delta
            );
            if !d.flipped_lines_caused.is_empty() {
                let take_n = d.flipped_lines_caused.len().min(max_samples);
                let _ = writeln!(
                    buf,
                    "    sample of {} of {} flipped lines:",
                    take_n,
                    d.flipped_lines_caused.len()
                );
                for (db, da, inp) in d.flipped_lines_caused.iter().take(take_n) {
                    let _ = writeln!(buf, "      [{} -> {}]  {}", db, da, short_input(inp, 110));
                }
            }
            buf.push('\n');
        }
    }

    let flipped_total: usize = flips.values().sum();
    let _ = writeln!(buf, "SUMMARY");
    if corpus_lines > 0 {
        let pct = (flipped_total as f64) / (corpus_lines as f64) * 100.0;
        let _ = writeln!(
            buf,
            "  flipped lines:    {} of {} ({:.2}% of corpus)",
            fmt_n(flipped_total),
            fmt_n(corpus_lines),
            pct
        );
    } else {
        let _ = writeln!(buf, "  flipped lines:    0");
    }
    if !flips.is_empty() {
        let mut sorted: Vec<(&(String, String), &usize)> = flips.iter().collect();
        sorted.sort_by_key(|&(_, c)| -(*c as i64));
        for ((b, a), c) in sorted {
            let arrow = format!("{} -> {}", b, a);
            let _ = writeln!(buf, "    {:<24}{:>6}", arrow, c);
        }
        let loosened = loosening_count(flips);
        if loosened > 0 {
            let _ = writeln!(
                buf,
                "\n  loosened decisions: {}  \
                 (this proposed change makes the engine MORE permissive on \
                 {} previously-flagged calls -- review each by hand)",
                loosened, loosened
            );
        } else {
            let _ = writeln!(
                buf,
                "\n  no loosening detected (no line moved toward a more permissive decision)"
            );
        }
    } else {
        let _ = writeln!(buf, "  no behavioral change in this corpus.");
    }
    buf.push('\n');

    // Guidance line
    if flipped_total == 0 {
        let _ = writeln!(
            buf,
            "GUIDANCE: this ruleset change has no observable effect on the supplied\n\
             corpus. Either it only affects patterns your team hasn't seen yet, or\n\
             it's a no-op. Add more representative cases to the corpus before merging."
        );
    } else {
        let n_appr: usize = flips
            .iter()
            .filter(|((_, a), _)| a == "approval")
            .map(|(_, c)| *c)
            .sum();
        let n_block: usize = flips
            .iter()
            .filter(|((_, a), _)| a == "block")
            .map(|(_, c)| *c)
            .sum();
        let mut parts = Vec::new();
        if n_appr > 0 {
            parts.push(format!("~{} more daily approval prompts", n_appr));
        }
        if n_block > 0 {
            parts.push(format!("~{} more daily hard blocks", n_block));
        }
        if !parts.is_empty() {
            let _ = writeln!(
                buf,
                "GUIDANCE: based on this corpus, expect {}.\n\
                 Review the flipped-line samples above to confirm these are the\n\
                 prompts/blocks the change intends to add.",
                parts.join(" and ")
            );
        }
    }
    buf
}

// ────────────────────────────────────────────────────────────────────
// Markdown renderer (PR-comment friendly)
// ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn render_markdown(
    before_path: &str,
    after_path: &str,
    corpus_lines: usize,
    decision_before: &BTreeMap<String, usize>,
    decision_after: &BTreeMap<String, usize>,
    deltas: &BTreeMap<String, RuleDelta>,
    flips: &FlipCounter,
    max_samples: usize,
) -> String {
    let mut buf = String::new();
    let _ = writeln!(
        buf,
        "### shieldset behavior diff -- `{}` -> `{}`",
        before_path, after_path
    );
    let _ = writeln!(buf, "_corpus: {} commands_\n", fmt_n(corpus_lines));

    let _ = writeln!(buf, "| decision | before | after | delta |");
    let _ = writeln!(buf, "|---|---:|---:|---:|");
    for d in DECISIONS {
        let b = *decision_before.get(d).unwrap_or(&0);
        let a = *decision_after.get(d).unwrap_or(&0);
        let delta = a as i64 - b as i64;
        let pct = if b > 0 {
            format!(" ({:+.1}%)", (delta as f64) / (b as f64) * 100.0)
        } else {
            String::new()
        };
        let _ = writeln!(
            buf,
            "| `{}` | {} | {} | {:+}{} |",
            d,
            fmt_n(b),
            fmt_n(a),
            delta,
            pct
        );
    }
    buf.push('\n');

    let added = deltas.values().filter(|d| d.status == "added").count();
    let removed = deltas.values().filter(|d| d.status == "removed").count();
    let modified = deltas.values().filter(|d| d.status == "modified").count();
    let mut parts = Vec::new();
    if added > 0 {
        parts.push(format!("{} added", added));
    }
    if removed > 0 {
        parts.push(format!("{} removed", removed));
    }
    if modified > 0 {
        parts.push(format!("{} modified", modified));
    }
    if parts.is_empty() {
        parts.push("none".into());
    }
    let _ = writeln!(buf, "**Ruleset changes:** {}\n", parts.join(", "));

    let behavioral: Vec<&RuleDelta> = deltas
        .values()
        .filter(|d| d.fires_before != d.fires_after || !d.flipped_lines_caused.is_empty())
        .collect();
    if !behavioral.is_empty() {
        let _ = writeln!(
            buf,
            "<details><summary>Rules with changed behavior on this corpus</summary>\n"
        );
        for d in &behavioral {
            let delta = d.fires_after as i64 - d.fires_before as i64;
            let _ = writeln!(
                buf,
                "**`{}`** ({}) -- fires `{}` -> `{}` ({:+})\n",
                d.rule_id, d.status, d.fires_before, d.fires_after, delta
            );
            if !d.flipped_lines_caused.is_empty() {
                let take_n = d.flipped_lines_caused.len().min(max_samples);
                let _ = writeln!(
                    buf,
                    "_Sample of {} of {} flipped lines:_\n",
                    take_n,
                    d.flipped_lines_caused.len()
                );
                for (db, da, inp) in d.flipped_lines_caused.iter().take(take_n) {
                    let _ = writeln!(buf, "- `{} -> {}`: `{}`", db, da, short_input(inp, 110));
                }
                buf.push('\n');
            }
        }
        let _ = writeln!(buf, "</details>\n");
    }

    let flipped_total: usize = flips.values().sum();
    if flipped_total == 0 {
        let _ = writeln!(
            buf,
            "**Behavioral impact:** no flipped decisions on this corpus."
        );
    } else {
        let pct = if corpus_lines > 0 {
            (flipped_total as f64) / (corpus_lines as f64) * 100.0
        } else {
            0.0
        };
        let _ = writeln!(
            buf,
            "**Behavioral impact:** {} of {} lines flipped ({:.2}%).\n",
            fmt_n(flipped_total),
            fmt_n(corpus_lines),
            pct
        );
        let _ = writeln!(buf, "| direction | count |");
        let _ = writeln!(buf, "|---|---:|");
        let mut sorted: Vec<(&(String, String), &usize)> = flips.iter().collect();
        sorted.sort_by_key(|&(_, c)| -(*c as i64));
        for ((b, a), c) in sorted {
            let _ = writeln!(buf, "| `{} -> {}` | {} |", b, a, c);
        }
        let loosened = loosening_count(flips);
        if loosened > 0 {
            let _ = writeln!(
                buf,
                "\n> **{} lines loosened** (moved toward a more permissive decision). Review each by hand.",
                loosened
            );
        }
    }
    buf
}

// ────────────────────────────────────────────────────────────────────
// JSON renderer (machine consumers; schema MUST stay stable with the
// Python prototype's `--format json` output).
// ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn render_json(
    before_path: &str,
    after_path: &str,
    corpus_lines: usize,
    decision_before: &BTreeMap<String, usize>,
    decision_after: &BTreeMap<String, usize>,
    deltas: &BTreeMap<String, RuleDelta>,
    flips: &FlipCounter,
) -> String {
    let mut dbf = serde_json::Map::new();
    let mut daf = serde_json::Map::new();
    for d in DECISIONS {
        dbf.insert(d.to_string(), json!(*decision_before.get(d).unwrap_or(&0)));
        daf.insert(d.to_string(), json!(*decision_after.get(d).unwrap_or(&0)));
    }
    let rules: Vec<_> = deltas
        .values()
        .map(|d| {
            json!({
                "id": d.rule_id,
                "status": d.status,
                "fires_before": d.fires_before,
                "fires_after": d.fires_after,
                "flipped_caused": d.flipped_lines_caused.len(),
            })
        })
        .collect();
    let flips_arr: Vec<_> = flips
        .iter()
        .map(|((b, a), c)| json!({"from": b, "to": a, "count": c}))
        .collect();
    let payload = json!({
        "before": before_path,
        "after":  after_path,
        "corpus_lines": corpus_lines,
        "decision_before": dbf,
        "decision_after":  daf,
        "rules": rules,
        "flips": flips_arr,
        "loosened_count": loosening_count(flips),
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Thousand-separated number formatting (matches the Python `{:,}`
/// format used in the prototype). Builds the string from the right
/// so the comma positions are unambiguous for any digit count.
fn fmt_n(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    if bytes.len() <= 3 {
        return s;
    }
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 3);
    for (i, b) in bytes.iter().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            out.push(b',');
        }
        out.push(*b);
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII digits + commas are always valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_n_thousands() {
        assert_eq!(fmt_n(0), "0");
        assert_eq!(fmt_n(123), "123");
        assert_eq!(fmt_n(1_000), "1,000");
        assert_eq!(fmt_n(12_345), "12,345");
        assert_eq!(fmt_n(1_000_000), "1,000,000");
        assert_eq!(fmt_n(13_456_789), "13,456,789");
    }

    #[test]
    fn short_input_tool_query() {
        let v = json!({"tool": "execute_sql", "params": {"query": "DROP DATABASE x"}});
        assert_eq!(short_input(&v, 80), "execute_sql: DROP DATABASE x");
    }

    #[test]
    fn short_input_text() {
        let v = json!({"text": "I will rm -rf /"});
        assert_eq!(short_input(&v, 80), "text: I will rm -rf /");
    }

    #[test]
    fn short_input_truncates() {
        let long = "a".repeat(200);
        let v = json!({"tool": "shell", "params": {"command": long}});
        let s = short_input(&v, 50);
        assert!(s.len() <= 50);
        assert!(s.ends_with("..."));
    }
}

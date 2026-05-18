//! Pre-merge behavior-diff explainer for shieldset changes.
//!
//! This module implements `aperion-shield --diff`, the native Rust
//! port of `scripts/shield-diff.py` (the Python prototype shipped
//! alongside `docs/shieldset-as-code.md`). Both produce a
//! source-compatible JSON output schema, so CI wired up against the
//! Python prototype keeps working unchanged when the flag flips to
//! `aperion-shield --diff`.
//!
//! ## Why this exists
//!
//! Shieldset changes are policy changes -- they need PR review like
//! code, but `diff shieldset.before.yaml shieldset.after.yaml` only
//! tells you the YAML changed. It does not tell you which calls in
//! the real corpus will now flip from `allow` to `block`, or worse,
//! from `block` to `allow`. That is what this mode is for.
//!
//! ## Pipeline
//!
//! ```text
//!   shieldset.before.yaml ─┐
//!   shieldset.after.yaml  ─┤── load Engine x2  ── evaluate corpus x2
//!   corpus.jsonl          ─┘                       │
//!                                                  v
//!                                          DecisionLine sets x2
//!                                                  │
//!                                                  v
//!                       diff rulesets (added/removed/modified/unchanged)
//!                                                  │
//!                                                  v
//!                       pair decisions by index, attribute every flip to
//!                       the changed rule(s) that fired under the after-state
//!                                                  │
//!                                                  v
//!                       render text / markdown / json
//! ```
//!
//! ## In-process, not subprocess
//!
//! The Python prototype shells out to `aperion-shield --check` twice.
//! This native port skips the subprocess: both runs use the same
//! `Engine::evaluate` path the proxy uses. It is materially faster
//! on big corpora (no JSON re-encode + re-decode trip per line) and
//! removes the runtime PATH dependency the Python prototype carried.

pub mod evaluate;
pub mod render;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use serde::Serialize;
use serde_yaml::Value as YamlValue;

pub use evaluate::{evaluate_corpus, DecisionLine, EvalOptions};

/// CLI-level options for `aperion-shield --diff`. Mirrors the Python
/// prototype 1:1 so the `--format json` output schema stays
/// source-compatible.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub rules_before: PathBuf,
    pub rules_after: PathBuf,
    /// Corpus path; `None` means read JSON-Lines from stdin.
    pub corpus: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub format: OutputFormat,
    pub max_samples: usize,
    pub fail_if_flipped: bool,
    pub fail_if_loosened: bool,
    pub fail_if_allows_loosened: Option<usize>,
}

/// Output format for the diff report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Markdown,
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "text" => Ok(OutputFormat::Text),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "json" => Ok(OutputFormat::Json),
            other => Err(anyhow!(
                "unknown --format '{}': must be one of text|markdown|json",
                other
            )),
        }
    }
}

/// Per-rule change: YAML-level (textual) + behavioral (corpus-level).
/// Mirrors `shield-diff.py::RuleDelta`. Serialised in `--format json`
/// output -- keep the field names stable.
#[derive(Debug, Clone, Serialize)]
pub struct RuleDelta {
    pub rule_id: String,
    /// "added" | "removed" | "modified" | "unchanged"
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub yaml_diff: String,
    pub fires_before: usize,
    pub fires_after: usize,
    /// Each entry: (decision_before, decision_after, input_obj).
    #[serde(skip_serializing)]
    pub flipped_lines_caused: Vec<(String, String, serde_json::Value)>,
}

/// Aggregate counter: `(decision_before, decision_after) -> count`.
/// Lexically ordered so render order is deterministic.
pub type FlipCounter = BTreeMap<(String, String), usize>;

pub const DECISIONS: [&str; 4] = ["allow", "warn", "approval", "block"];

/// Numeric ordering of decision severities. Used by [`loosening_count`]
/// to decide whether a flip moved toward a more permissive decision.
fn severity_rank(d: &str) -> u8 {
    match d {
        "allow" => 0,
        "warn" => 1,
        "approval" | "identity_verification" => 2,
        "block" => 3,
        _ => 99,
    }
}

/// How many flipped lines moved toward a more permissive decision.
/// `identity_verification` counts at the same severity as `approval`
/// because both gate the call before it runs upstream.
pub fn loosening_count(flips: &FlipCounter) -> usize {
    flips
        .iter()
        .filter(|((b, a), _)| severity_rank(a) < severity_rank(b))
        .map(|(_, c)| *c)
        .sum()
}

/// How many flipped lines ended at `allow`. Used by
/// `--fail-if-allows-loosened`.
pub fn flips_to_allow(flips: &FlipCounter) -> usize {
    flips
        .iter()
        .filter(|((_, a), _)| a == "allow")
        .map(|(_, c)| *c)
        .sum()
}

/// Parse a shieldset YAML file into a `BTreeMap<rule_id, rule_body>`
/// where `rule_body` is the rule's YAML node MINUS its `id` field.
/// Used for diffing rules textually. Tolerates both the wrapped
/// (`shieldset:\n  rules:`) and bare (`rules:`) forms, matching the
/// Python prototype.
pub fn load_ruleset_yaml(
    path: &Path,
) -> anyhow::Result<BTreeMap<String, YamlValue>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading shieldset YAML from {}", path.display()))?;
    let root: YamlValue = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing YAML at {}", path.display()))?;
    let YamlValue::Mapping(top) = &root else {
        anyhow::bail!("{} did not parse as a YAML mapping", path.display());
    };
    let shieldset = top
        .get(YamlValue::String("shieldset".into()))
        .unwrap_or(&root);
    let rules = match shieldset {
        YamlValue::Mapping(m) => m.get(YamlValue::String("rules".into())).cloned(),
        _ => None,
    };
    let Some(YamlValue::Sequence(rules)) = rules else {
        return Ok(BTreeMap::new());
    };
    let mut out: BTreeMap<String, YamlValue> = BTreeMap::new();
    for r in rules {
        let YamlValue::Mapping(mut m) = r else { continue };
        let Some(YamlValue::String(rid)) = m.remove(YamlValue::String("id".into())) else {
            continue;
        };
        out.insert(rid, YamlValue::Mapping(m));
    }
    Ok(out)
}

/// Dump one rule (id + body) back to YAML for textual diffing.
/// Always emits `id` first to keep the diff stable across runs.
pub fn yaml_dump_rule(rid: &str, body: &YamlValue) -> String {
    let mut top = serde_yaml::Mapping::new();
    top.insert(YamlValue::String("id".into()), YamlValue::String(rid.into()));
    if let YamlValue::Mapping(m) = body {
        for (k, v) in m {
            top.insert(k.clone(), v.clone());
        }
    }
    let wrapped = YamlValue::Sequence(vec![YamlValue::Mapping(top)]);
    serde_yaml::to_string(&wrapped).unwrap_or_default()
}

/// Classify every rule that appears in either ruleset. The YAML diff
/// is rendered eagerly so we don't pay the cost twice if the renderer
/// is asked to embed it.
pub fn diff_rulesets(
    before: &BTreeMap<String, YamlValue>,
    after: &BTreeMap<String, YamlValue>,
) -> BTreeMap<String, RuleDelta> {
    use similar::{ChangeTag, TextDiff};

    let mut all_ids: std::collections::BTreeSet<&String> = before.keys().collect();
    all_ids.extend(after.keys());

    let mut deltas = BTreeMap::new();
    for rid in all_ids {
        let in_before = before.contains_key(rid);
        let in_after = after.contains_key(rid);
        let (status, yaml_diff): (&str, String) = match (in_before, in_after) {
            (true, false) => {
                let dumped = yaml_dump_rule(rid, &before[rid]);
                let diff = dumped
                    .lines()
                    .map(|l| format!("- {}", l))
                    .collect::<Vec<_>>()
                    .join("\n");
                ("removed", diff)
            }
            (false, true) => {
                let dumped = yaml_dump_rule(rid, &after[rid]);
                let diff = dumped
                    .lines()
                    .map(|l| format!("+ {}", l))
                    .collect::<Vec<_>>()
                    .join("\n");
                ("added", diff)
            }
            (true, true) if before[rid] == after[rid] => ("unchanged", String::new()),
            _ => {
                let b_yaml = yaml_dump_rule(rid, &before[rid]);
                let a_yaml = yaml_dump_rule(rid, &after[rid]);
                let diff = TextDiff::from_lines(&b_yaml, &a_yaml);
                let mut out = String::new();
                out.push_str(&format!("--- {}.before\n", rid));
                out.push_str(&format!("+++ {}.after\n", rid));
                for change in diff.iter_all_changes() {
                    let sign = match change.tag() {
                        ChangeTag::Delete => "-",
                        ChangeTag::Insert => "+",
                        ChangeTag::Equal => " ",
                    };
                    out.push_str(sign);
                    out.push_str(change.value());
                }
                ("modified", out)
            }
        };
        deltas.insert(
            rid.clone(),
            RuleDelta {
                rule_id: rid.clone(),
                status: status.to_string(),
                yaml_diff,
                fires_before: 0,
                fires_after: 0,
                flipped_lines_caused: Vec::new(),
            },
        );
    }
    deltas
}

/// Walk paired before/after decision lists, fill in `fires_before` /
/// `fires_after`, build the global flip counter, attribute each flip
/// to the rule(s) that materially changed under the after-state, and
/// return the global flip counter.
///
/// Pairing is by index, mirroring the Python prototype. If the two
/// runs produced different counts (which can happen if a shieldset
/// change causes evaluation errors on some lines), we pair as many
/// as we have and emit a stderr warning.
pub fn populate_behavior(
    deltas: &mut BTreeMap<String, RuleDelta>,
    before: &[DecisionLine],
    after: &[DecisionLine],
) -> FlipCounter {
    if before.len() != after.len() {
        eprintln!(
            "warn: decision counts differ ({} vs {}); pairing by index",
            before.len(),
            after.len()
        );
    }
    let n = before.len().min(after.len());
    let mut flips: FlipCounter = BTreeMap::new();
    for i in 0..n {
        let b = &before[i];
        let a = &after[i];
        for rid in &b.matched_rules {
            if let Some(d) = deltas.get_mut(rid) {
                d.fires_before += 1;
            }
        }
        for rid in &a.matched_rules {
            if let Some(d) = deltas.get_mut(rid) {
                d.fires_after += 1;
            }
        }
        if b.decision != a.decision {
            *flips
                .entry((b.decision.clone(), a.decision.clone()))
                .or_insert(0) += 1;
            // Attribute the flip to whichever changed rule(s) actually
            // fired under the new state. For removals we attribute to
            // the rule that fired under the OLD state and is now gone.
            for rid in &a.matched_rules {
                if let Some(d) = deltas.get_mut(rid) {
                    if matches!(d.status.as_str(), "added" | "modified") {
                        d.flipped_lines_caused.push((
                            b.decision.clone(),
                            a.decision.clone(),
                            b.input.clone(),
                        ));
                    }
                }
            }
            for rid in &b.matched_rules {
                if let Some(d) = deltas.get_mut(rid) {
                    if d.status == "removed" {
                        d.flipped_lines_caused.push((
                            b.decision.clone(),
                            a.decision.clone(),
                            b.input.clone(),
                        ));
                    }
                }
            }
        }
    }
    flips
}

/// Top-level entry point for `aperion-shield --diff`. Returns the
/// shell exit code: 0 for success, 1 for a policy-gate trip (e.g.
/// `--fail-if-flipped`), 2 for an internal / I/O error.
pub async fn run_diff_mode(opts: DiffOptions) -> anyhow::Result<i32> {
    let before_yaml = load_ruleset_yaml(&opts.rules_before)?;
    let after_yaml = load_ruleset_yaml(&opts.rules_after)?;

    let corpus_bytes = read_corpus(opts.corpus.as_deref())?;
    if corpus_bytes.trim().is_empty() {
        anyhow::bail!("corpus is empty");
    }
    // Count non-comment, non-blank lines for the "corpus: N commands"
    // header. Matches the Python prototype's line-count semantics AND
    // the `evaluate_corpus` skip rules (which treat both `#` and `//`
    // as comment markers) so the line count agrees with the number
    // of decisions reported.
    let corpus_line_count = corpus_bytes
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with("//")
        })
        .count();

    let eval_opts = EvalOptions {
        workspace: opts.workspace.clone(),
    };

    let before_decisions = evaluate_corpus(&opts.rules_before, &corpus_bytes, &eval_opts)?;
    let after_decisions = evaluate_corpus(&opts.rules_after, &corpus_bytes, &eval_opts)?;

    let mut decision_before: BTreeMap<String, usize> = BTreeMap::new();
    for d in DECISIONS {
        decision_before.insert(d.into(), 0);
    }
    for d in &before_decisions {
        *decision_before.entry(d.decision.clone()).or_insert(0) += 1;
    }
    let mut decision_after: BTreeMap<String, usize> = BTreeMap::new();
    for d in DECISIONS {
        decision_after.insert(d.into(), 0);
    }
    for d in &after_decisions {
        *decision_after.entry(d.decision.clone()).or_insert(0) += 1;
    }

    let mut deltas = diff_rulesets(&before_yaml, &after_yaml);
    let flips = populate_behavior(&mut deltas, &before_decisions, &after_decisions);

    let before_label = opts.rules_before.display().to_string();
    let after_label = opts.rules_after.display().to_string();

    let out = match opts.format {
        OutputFormat::Text => render::render_text(
            &before_label,
            &after_label,
            corpus_line_count,
            &decision_before,
            &decision_after,
            &deltas,
            &flips,
            opts.max_samples,
        ),
        OutputFormat::Markdown => render::render_markdown(
            &before_label,
            &after_label,
            corpus_line_count,
            &decision_before,
            &decision_after,
            &deltas,
            &flips,
            opts.max_samples,
        ),
        OutputFormat::Json => render::render_json(
            &before_label,
            &after_label,
            corpus_line_count,
            &decision_before,
            &decision_after,
            &deltas,
            &flips,
        ),
    };
    print!("{}", out);
    if !out.ends_with('\n') {
        println!();
    }

    // Exit-code policy: order matches the Python prototype so a
    // shell wrapper that does `aperion-shield --diff || exit $?` keeps
    // its same semantics across the Python/Rust swap.
    let total_flipped: usize = flips.values().sum();
    if let Some(threshold) = opts.fail_if_allows_loosened {
        if flips_to_allow(&flips) > threshold {
            return Ok(1);
        }
    }
    if opts.fail_if_loosened && loosening_count(&flips) > 0 {
        return Ok(1);
    }
    if opts.fail_if_flipped && total_flipped > 0 {
        return Ok(1);
    }
    Ok(0)
}

/// Read the JSON-Lines corpus from a file or stdin. The Python
/// prototype refuses to read from a TTY; we keep that behaviour so
/// `aperion-shield --diff` doesn't hang waiting for input when the
/// user forgot `--corpus`.
fn read_corpus(path: Option<&Path>) -> anyhow::Result<String> {
    use std::io::Read;
    if let Some(p) = path {
        return std::fs::read_to_string(p)
            .with_context(|| format!("reading corpus from {}", p.display()));
    }
    if atty_stdin() {
        anyhow::bail!(
            "no corpus on stdin and no --corpus PATH given.\n\
             hint: aperion-shield --diff --corpus tests/corpus/golden.jsonl \
             --rules-before X --rules-after Y"
        );
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Minimal TTY detection that avoids pulling in the `atty` /
/// `is-terminal` crate just for one call site. Falls back to "no
/// pipe" (i.e. treat as TTY) on any error.
fn atty_stdin() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty is a thread-safe libc call.
        unsafe { libc_isatty(0) }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(unix)]
unsafe fn libc_isatty(fd: i32) -> bool {
    extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    isatty(fd) == 1
}

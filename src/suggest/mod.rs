//! `aperion-shield --suggest-rules` (v0.7+).
//!
//! Read your local audit log, compute per-rule statistics, and emit
//! actionable tuning recommendations for your `shieldset.yaml`.
//!
//! ## Why this exists
//!
//! Shieldsets are policy-as-code: it's easy to copy ours, easy to add
//! to it, easy to fork. What's *hard* is keeping it well-fit to your
//! environment over time — figuring out which rules are dead weight,
//! which are too noisy, which should be tightened. Without this
//! command, operators either over-trust the bundled defaults (and live
//! with whatever noise that produces) or hand-grep their audit logs
//! once a quarter when they get annoyed enough.
//!
//! `--suggest-rules` is the cheap path between those two extremes. You
//! point it at the JSONL audit log Shield has been writing, it picks
//! out three categories of evidence (`RULE_NEVER_FIRES`,
//! `CONSISTENTLY_DEMOTED`, `NOISY_WARN`) and tells you what's worth
//! reviewing.
//!
//! ## Inputs
//!
//! - `--audit-log PATH`     — JSONL file produced by Shield's stderr
//!                            redirect (one `kind: shield_eval` record
//!                            per evaluated tool call).
//! - `--rules PATH`         — current shieldset.yaml (so we know which
//!                            rules SHOULD have fired). Optional;
//!                            defaults to bundled.
//! - `--window-days N`      — only consider records in the last N
//!                            days. Default: 30. Pass 0 for all.
//! - `--min-occurrences N`  — threshold for `CONSISTENTLY_DEMOTED` and
//!                            `NOISY_WARN`. Default: 5.
//! - `--format FMT`         — `text` (default) / `markdown` / `yaml-patch`.

pub mod analyze;
pub mod audit;
pub mod render;

use crate::engine::Engine;
use anyhow::Result;
use std::path::Path;

pub use analyze::{analyze, AnalyzeOptions, Suggestion};
pub use audit::AuditRecord;
pub use render::{render, OutputFormat};

/// Glue: read the audit log, run the analyzer, return the rendered
/// output + a count of suggestions for the CLI exit-code policy.
pub fn run(
    engine: &Engine,
    audit_log: &Path,
    opts: AnalyzeOptions,
    format: OutputFormat,
) -> Result<(String, usize, usize)> {
    let (records, skipped) = audit::read_audit_file(audit_log)?;
    let records = audit::within_window(records, chrono::Utc::now(), opts.window_days);
    let suggestions = analyze(engine, &records, opts);
    let body = render(&suggestions, format);
    Ok((body, suggestions.len(), skipped))
}

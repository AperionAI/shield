//! Audit-log reader for the `--suggest-rules` workflow.
//!
//! Shield's standalone runtime emits one JSON-Lines record per
//! tool-call evaluation on stderr (see `src/main.rs` near the
//! `"kind": "shield_eval"` block). Operators who want `--suggest-rules`
//! to be useful redirect that stream to a file:
//!
//! ```bash
//! aperion-shield -- npx @modelcontextprotocol/server-postgres ... 2>>~/.aperion-shield/audit.jsonl
//! ```
//!
//! This module knows how to parse that file back into a typed
//! [`AuditRecord`]. We deliberately accept any extra JSON fields (org
//! mode adds a few) and silently skip lines that don't carry
//! `"kind": "shield_eval"` so the same audit file can hold other
//! records (heartbeats, identity verifications) without confusing the
//! analyzer.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// One row of `--suggest-rules`-ready data. Mirrors the JSON written by
/// `src/main.rs` (search for `"kind": "shield_eval"`).
#[derive(Debug, Clone, Deserialize)]
pub struct AuditRecord {
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub tool: String,
    pub primary_rule_id: String,
    pub fingerprint: String,
    #[serde(default)]
    pub matched_rules: Vec<String>,
    pub raw_severity: String,
    #[serde(default)]
    pub composite_points: u32,
    pub composite_severity: String,
    pub final_severity: String,
    pub decision: String,
}

/// Read every `kind == "shield_eval"` record out of an audit file.
/// Malformed JSON lines and lines of other kinds are silently skipped
/// (with the count returned in the report for visibility). This is
/// important: we don't want the analyzer to crash mid-run because the
/// operator concatenated two different log files together.
pub fn read_audit_file(path: &Path) -> Result<(Vec<AuditRecord>, usize)> {
    let file = File::open(path)
        .with_context(|| format!("can't open audit log {}", path.display()))?;
    read_audit_reader(BufReader::new(file))
}

/// Same as [`read_audit_file`] but reads from any `BufRead` (for
/// in-memory tests). Returns `(records, skipped_line_count)`.
pub fn read_audit_reader<R: BufRead>(reader: R) -> Result<(Vec<AuditRecord>, usize)> {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(trimmed) {
            Ok(r) if r.kind == "shield_eval" => out.push(r),
            Ok(_) => skipped += 1, // wrong kind
            Err(_) => skipped += 1, // not parseable as our schema
        }
    }
    Ok((out, skipped))
}

/// Filter to records within the last `window_days`. Pass `None` for
/// "all records". The cutoff is computed once against `now`.
pub fn within_window(
    records: Vec<AuditRecord>,
    now: DateTime<Utc>,
    window_days: Option<u32>,
) -> Vec<AuditRecord> {
    match window_days {
        None => records,
        Some(days) => {
            let cutoff = now - chrono::Duration::days(days as i64);
            records.into_iter().filter(|r| r.ts >= cutoff).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_basic_shield_eval_record() {
        let line = r#"{"ts":"2026-05-19T12:00:00Z","kind":"shield_eval","tool":"execute_sql","primary_rule_id":"sql.drop_database","fingerprint":"abc","matched_rules":["sql.drop_database"],"raw_severity":"Critical","composite_points":80,"composite_severity":"Critical","final_severity":"Critical","decision":"block","memory":{"approves":0,"denies":0},"adjustments":{}}"#;
        let (records, skipped) = read_audit_reader(Cursor::new(line.as_bytes())).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 0);
        assert_eq!(records[0].tool, "execute_sql");
        assert_eq!(records[0].primary_rule_id, "sql.drop_database");
        assert_eq!(records[0].decision, "block");
    }

    #[test]
    fn skips_unparseable_and_other_kinds() {
        let lines = r#"{"kind":"heartbeat","ts":"2026-05-19T12:00:00Z"}
not json at all
{"ts":"2026-05-19T12:00:00Z","kind":"shield_eval","tool":"execute_sql","primary_rule_id":"sql.drop_database","fingerprint":"abc","raw_severity":"Critical","composite_severity":"Critical","final_severity":"Critical","decision":"block"}
{}"#;
        let (records, skipped) = read_audit_reader(Cursor::new(lines.as_bytes())).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 3);
    }

    #[test]
    fn window_filter_drops_old_records() {
        let now: DateTime<Utc> = "2026-05-19T12:00:00Z".parse().unwrap();
        let make = |ts: &str| AuditRecord {
            ts: ts.parse().unwrap(),
            kind: "shield_eval".into(),
            tool: "execute_sql".into(),
            primary_rule_id: "sql.foo".into(),
            fingerprint: "x".into(),
            matched_rules: vec!["sql.foo".into()],
            raw_severity: "Medium".into(),
            composite_points: 10,
            composite_severity: "Medium".into(),
            final_severity: "Medium".into(),
            decision: "warn".into(),
        };
        let records = vec![
            make("2026-04-15T00:00:00Z"), // 34 days ago, dropped @30d
            make("2026-05-10T00:00:00Z"), // 9 days ago, kept @30d
            make("2026-05-18T00:00:00Z"), // 1 day ago, kept @30d
        ];
        let kept = within_window(records.clone(), now, Some(30));
        assert_eq!(kept.len(), 2);
        // No filter: keep all
        let all = within_window(records, now, None);
        assert_eq!(all.len(), 3);
    }
}

//! v1.0: `--scan` -- pre-install audit of an MCP server.
//!
//! Point-in-time audit BEFORE a server is ever wired into the IDE.
//! Complements (does not replace) runtime enforcement: scan catches a
//! bad server at install time, TOFU pinning catches the rug pull
//! three weeks later, and the engine blocks whatever slips through at
//! call time.
//!
//! Four passes, run in this order:
//!   (a) typosquat name-similarity -- compares the target package
//!       name against a curated seed list of well-known MCP servers,
//!       flagging separator/case variants (`mcp_shield` vs. the real
//!       `mcp-shield` -- visually indistinguishable) and small
//!       edit-distance typos (homoglyph-style single-char swaps).
//!       Pure string comparison against the name alone -- no fetch,
//!       no network -- so it runs first, even under `--scan-offline`
//!       and even if the package can't be fetched; npm targets only
//!       today;
//!   (b) static source signatures -- exfiltration (credential reads,
//!       env harvesting near network calls), dynamic execution
//!       (eval/exec/child_process), obfuscation (runtime base64/hex
//!       decoding, charcode assembly);
//!   (c) supply-chain metadata -- npm registry age / maintainers /
//!       weekly downloads, plus known vulnerabilities from OSV.dev
//!       (best-effort, skipped when offline);
//!   (d) live catalog audit -- launch the server (under the v1.0
//!       sandbox), issue `initialize` + `tools/list`, and run the
//!       engine's `tool_description` rules against the catalog
//!       without ever exposing it to an agent.
//!
//! Targets: a local path, a GitHub URL (shallow clone), or an npm
//! package name (`npm pack`, no install scripts executed).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::engine::{Adjustments, Engine, Scope, Severity};

// ───────────────────────────── targets ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    LocalPath(PathBuf),
    Github(String),
    Npm(String),
}

impl Target {
    /// `./path`, `/abs/path`, `https://github.com/owner/repo`,
    /// `npm:package`, or a bare npm package name.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(pkg) = s.strip_prefix("npm:") {
            return Ok(Target::Npm(pkg.to_string()));
        }
        if s.starts_with("https://github.com/") || s.starts_with("git@github.com:") {
            return Ok(Target::Github(s.to_string()));
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            anyhow::bail!("only GitHub URLs are supported for --scan (got '{s}')");
        }
        let p = PathBuf::from(s);
        if p.exists() {
            return Ok(Target::LocalPath(p));
        }
        if s.starts_with('.') || s.starts_with('/') || s.starts_with('~') {
            anyhow::bail!("--scan path '{s}' does not exist");
        }
        // Bare name: treat as npm, the dominant MCP packaging today.
        Ok(Target::Npm(s.to_string()))
    }
}

// ───────────────────────────── findings ────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub pass: &'static str, // "static" | "typosquat" | "metadata" | "catalog"
    pub id: String,
    pub severity: Severity,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>, // file:line for static findings
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub findings: Vec<Finding>,
    pub passes_run: Vec<&'static str>,
    pub passes_skipped: Vec<(&'static str, String)>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Pass,
    Caution,
    Fail,
}

impl Report {
    fn finalize(&mut self) {
        let worst = self.findings.iter().map(|f| f.severity).max();
        self.verdict = match worst {
            Some(Severity::Critical) | Some(Severity::High) => Verdict::Fail,
            Some(Severity::Medium) => Verdict::Caution,
            Some(Severity::Low) | None => Verdict::Pass,
        };
    }

    pub fn exit_code(&self) -> i32 {
        match self.verdict {
            Verdict::Pass => 0,
            Verdict::Caution => 1,
            Verdict::Fail => 2,
        }
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("scan target: {}\n", self.target));
        out.push_str(&format!(
            "passes: {}{}\n",
            self.passes_run.join(", "),
            if self.passes_skipped.is_empty() {
                String::new()
            } else {
                format!(
                    " (skipped: {})",
                    self.passes_skipped
                        .iter()
                        .map(|(p, why)| format!("{p} -- {why}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }
        ));
        if self.findings.is_empty() {
            out.push_str("findings: none\n");
        } else {
            out.push_str(&format!("findings: {}\n", self.findings.len()));
            for f in &self.findings {
                out.push_str(&format!(
                    "  [{:?}] {} ({}): {}{}\n",
                    f.severity,
                    f.id,
                    f.pass,
                    f.detail,
                    f.location
                        .as_ref()
                        .map(|l| format!(" @ {l}"))
                        .unwrap_or_default()
                ));
            }
        }
        out.push_str(&format!("verdict: {:?}\n", self.verdict));
        out
    }
}

// ─────────────────────── pass (b): static scan ─────────────────────

struct StaticSig {
    id: &'static str,
    severity: Severity,
    detail: &'static str,
    /// File extensions this signature applies to; empty = all text.
    exts: &'static [&'static str],
    re: &'static str,
}

const JS: &[&str] = &["js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"];
const PY: &[&str] = &["py"];
const ANY: &[&str] = &[];

/// Seeded from the bundled shieldset patterns plus the classic MCP
/// supply-chain incident write-ups. Intentionally conservative: each
/// signature is something a benign MCP server has no business doing.
static STATIC_SIGS: &[StaticSig] = &[
    // exfiltration: credential reads
    StaticSig { id: "scan.static.ssh_key_read", severity: Severity::Critical, exts: ANY,
        detail: "reads SSH private key material",
        re: r#"(?i)[~$./\\A-Za-z_]*\.ssh[/\\](id_[a-z0-9]+|authorized_keys|known_hosts)"# },
    StaticSig { id: "scan.static.cloud_creds_read", severity: Severity::Critical, exts: ANY,
        detail: "reads cloud credential files",
        re: r#"(?i)\.(aws[/\\]credentials|kube[/\\]config|gnupg|netrc|docker[/\\]config\.json)"# },
    StaticSig { id: "scan.static.browser_secrets", severity: Severity::Critical, exts: ANY,
        detail: "touches browser credential / cookie stores",
        re: r#"(?i)(Login Data|Cookies|Local State)['"].{0,40}(Chrome|Chromium|Brave|Edge)|keychain-db"# },
    // exfiltration: env harvesting shipped over the network
    StaticSig { id: "scan.static.env_exfil_js", severity: Severity::High, exts: JS,
        detail: "serializes the entire process environment (pair with any network call = exfil)",
        re: r#"JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys)\(\s*process\.env\s*\)"# },
    StaticSig { id: "scan.static.env_exfil_py", severity: Severity::High, exts: PY,
        detail: "serializes the entire process environment",
        re: r#"(json\.dumps|str)\(\s*(dict\(\s*)?os\.environ"# },
    // dynamic execution
    StaticSig { id: "scan.static.dynamic_eval_js", severity: Severity::High, exts: JS,
        detail: "dynamic code execution (eval / new Function)",
        re: r#"\beval\s*\(\s*[^'")\s]|new\s+Function\s*\("# },
    StaticSig { id: "scan.static.child_process_js", severity: Severity::Medium, exts: JS,
        detail: "spawns shell subprocesses (child_process)",
        re: r#"require\(\s*['"]child_process['"]\s*\)|from\s+['"](node:)?child_process['"]"# },
    StaticSig { id: "scan.static.dynamic_require", severity: Severity::High, exts: JS,
        detail: "dynamic require/import of a computed module path",
        re: r#"require\s*\(\s*[A-Za-z_$][\w$]*(\[|\.|\+| )|import\s*\(\s*[A-Za-z_$][\w$]*[\s+\[]"# },
    StaticSig { id: "scan.static.dynamic_exec_py", severity: Severity::High, exts: PY,
        detail: "dynamic code execution (exec/eval on non-literal)",
        re: r#"\b(exec|eval)\s*\(\s*[A-Za-z_]"# },
    StaticSig { id: "scan.static.shell_true_py", severity: Severity::Medium, exts: PY,
        detail: "subprocess with shell=True",
        re: r#"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"# },
    // obfuscation
    StaticSig { id: "scan.static.b64_exec", severity: Severity::Critical, exts: ANY,
        detail: "decodes base64 then executes it",
        re: r#"(?i)(eval|exec|Function|spawn|system)\s*\(\s*[^)]{0,60}(atob|b64decode|from(?:_base64)?\s*\(\s*[^)]{0,40}['"]base64)"# },
    StaticSig { id: "scan.static.charcode_assembly", severity: Severity::High, exts: JS,
        detail: "assembles strings from character codes (classic obfuscation)",
        re: r#"String\.fromCharCode\s*\((\s*\d+\s*,){8,}"# },
    StaticSig { id: "scan.static.hex_blob_decode", severity: Severity::Medium, exts: ANY,
        detail: "decodes a large embedded hex/base64 blob at runtime",
        re: r#"(?i)(atob|b64decode|fromhex|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{200,}"# },
    // install-time hooks (npm)
    StaticSig { id: "scan.static.install_script", severity: Severity::Medium, exts: &["json"],
        detail: "package.json declares an install-time script hook",
        re: r#""(pre|post)?install"\s*:"# },
];

static COMPILED_SIGS: Lazy<Vec<(usize, Regex)>> = Lazy::new(|| {
    STATIC_SIGS
        .iter()
        .enumerate()
        .map(|(i, s)| (i, Regex::new(s.re).expect("static scan signature must compile")))
        .collect()
});

const MAX_FILE_BYTES: u64 = 2_000_000;
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "dist", "build", "target", "__pycache__", ".venv", "venv"];

fn walk(root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                walk(&p, files);
            }
        } else if p.is_file() {
            files.push(p);
        }
    }
}

pub fn static_scan(root: &Path) -> Vec<Finding> {
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut findings = Vec::new();
    // Cap per-signature reporting so one pattern repeated 500 times
    // doesn't drown the report.
    let mut per_sig: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        if let Ok(meta) = f.metadata() {
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }
        }
        let Ok(content) = std::fs::read_to_string(&f) else { continue };
        // package.json install hooks only matter in package.json.
        for (i, re) in COMPILED_SIGS.iter() {
            let sig = &STATIC_SIGS[*i];
            if !sig.exts.is_empty() && !sig.exts.contains(&ext.as_str()) {
                continue;
            }
            if sig.id == "scan.static.install_script"
                && f.file_name().and_then(|n| n.to_str()) != Some("package.json")
            {
                continue;
            }
            if let Some(m) = re.find(&content) {
                let count = per_sig.entry(sig.id).or_insert(0);
                *count += 1;
                if *count > 5 {
                    continue;
                }
                let line = content[..m.start()].matches('\n').count() + 1;
                findings.push(Finding {
                    pass: "static",
                    id: sig.id.to_string(),
                    severity: sig.severity,
                    detail: sig.detail.to_string(),
                    location: Some(format!("{}:{}", f.display(), line)),
                });
            }
        }
    }
    findings
}

// ─────────────────── pass (a): typosquat detection ──────────────────

/// A curated seed list of well-known MCP server package names (npm).
/// Not meant to be exhaustive or a registry -- the goal is to catch a
/// typosquat riding on the coattails of a widely-installed server.
/// Extend as new servers become de-facto standards; low maintenance
/// cost, no network dependency, no registry API to keep in sync with.
const KNOWN_MCP_PACKAGES: &[&str] = &[
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-everart",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-aws-kb-retrieval",
    "@modelcontextprotocol/inspector",
    "@modelcontextprotocol/sdk",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@supabase/mcp-server-supabase",
    "@cloudflare/mcp-server-cloudflare",
    "@sentry/mcp-server",
    "@browserbasehq/mcp-server-browserbase",
    "mcp-server-git",
    "mcp-shield",
    "firecrawl-mcp",
];

/// Lowercase and strip everything but alphanumerics, so `mcp-shield`,
/// `mcp_shield`, `mcpshield`, and `MCP.Shield` all normalize
/// identically -- exactly the class of typosquat that's invisible to
/// a human skimming a package name before installing.
fn normalize_pkg_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Classic Levenshtein edit distance, O(n*m). Package names are short
/// (a few dozen chars at most), so this is effectively instant and
/// doesn't warrant pulling in a crate for it.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0usize; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

/// Pure, local, offline: compares the target package name against the
/// seed list above. Two distinct signals, reported at different
/// severities because they mean different things:
///   - `name_collision` (High): normalized forms are IDENTICAL but the
///     literal spelling differs (hyphen/underscore/dot/case games) --
///     e.g. `mcp_shield` vs. the real `mcp-shield`. Visually
///     indistinguishable in a terminal or package.json diff; the
///     strongest and least-ambiguous signal this pass produces.
///   - `similar_name` (Medium): small normalized edit distance (1 for
///     short names, 2 otherwise) -- catches homoglyph-style
///     single-character swaps (`0`/`o`, `1`/`l`, `rn`/`m`) and classic
///     typos, at the cost of being a heuristic rather than a proof.
///
/// An exact literal match to a known-good package produces no finding
/// (it just *is* the real thing).
pub fn typosquat_scan(pkg: &str) -> Vec<Finding> {
    let target_norm = normalize_pkg_name(pkg);
    if target_norm.is_empty() {
        return Vec::new();
    }

    let mut best: Option<(&str, usize)> = None;
    for known in KNOWN_MCP_PACKAGES {
        if *known == pkg {
            // It IS the well-known package -- not a typosquat.
            return Vec::new();
        }
        let known_norm = normalize_pkg_name(known);
        if known_norm == target_norm {
            return vec![Finding {
                pass: "typosquat",
                id: "scan.typo.name_collision".into(),
                severity: Severity::High,
                detail: format!(
                    "'{pkg}' is a separator/case variant of the well-known package '{known}' \
                     -- visually indistinguishable, classic typosquat pattern"
                ),
                location: None,
            }];
        }
        let dist = edit_distance(&target_norm, &known_norm);
        if best.map(|(_, d)| dist < d).unwrap_or(true) {
            best = Some((known, dist));
        }
    }

    match best {
        Some((known, dist)) if dist > 0 => {
            let threshold = if target_norm.len() <= 6 { 1 } else { 2 };
            if dist <= threshold {
                return vec![Finding {
                    pass: "typosquat",
                    id: "scan.typo.similar_name".into(),
                    severity: Severity::Medium,
                    detail: format!(
                        "'{pkg}' is within edit distance {dist} of well-known package '{known}' \
                         -- verify this isn't a typosquat before installing"
                    ),
                    location: None,
                }];
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

// ───────────────────── pass (c): supply metadata ────────────────────

const YOUNG_PACKAGE_DAYS: i64 = 30;
const LOW_DOWNLOADS_WEEKLY: u64 = 50;

pub async fn npm_metadata_scan(pkg: &str) -> anyhow::Result<Vec<Finding>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("aperion-shield-scan")
        .build()?;
    let mut findings = Vec::new();

    let meta: serde_json::Value = client
        .get(format!("https://registry.npmjs.org/{}", pkg))
        .send()
        .await?
        .error_for_status()
        .context("npm registry lookup failed")?
        .json()
        .await?;

    if let Some(created) = meta
        .pointer("/time/created")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono_lite_days_since(s))
    {
        if created < YOUNG_PACKAGE_DAYS {
            findings.push(Finding {
                pass: "metadata",
                id: "scan.meta.young_package".into(),
                severity: Severity::Medium,
                detail: format!("package is only {created} days old"),
                location: None,
            });
        }
    }
    let maintainers = meta
        .get("maintainers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if maintainers <= 1 {
        findings.push(Finding {
            pass: "metadata",
            id: "scan.meta.single_maintainer".into(),
            severity: Severity::Low,
            detail: format!("{maintainers} maintainer(s) on npm"),
            location: None,
        });
    }

    if let Ok(resp) = client
        .get(format!("https://api.npmjs.org/downloads/point/last-week/{}", pkg))
        .send()
        .await
    {
        if let Ok(dl) = resp.json::<serde_json::Value>().await {
            if let Some(n) = dl.get("downloads").and_then(|v| v.as_u64()) {
                if n < LOW_DOWNLOADS_WEEKLY {
                    findings.push(Finding {
                        pass: "metadata",
                        id: "scan.meta.low_adoption".into(),
                        severity: Severity::Low,
                        detail: format!("{n} downloads in the last week"),
                        location: None,
                    });
                }
            }
        }
    }

    // Known vulnerabilities via OSV.dev.
    let osv: serde_json::Value = client
        .post("https://api.osv.dev/v1/query")
        .json(&serde_json::json!({
            "package": {"name": pkg, "ecosystem": "npm"}
        }))
        .send()
        .await?
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({}));
    if let Some(vulns) = osv.get("vulns").and_then(|v| v.as_array()) {
        for v in vulns.iter().take(5) {
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("OSV-unknown");
            let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
            findings.push(Finding {
                pass: "metadata",
                id: "scan.meta.known_vuln".into(),
                severity: Severity::High,
                detail: format!("{id}: {summary}"),
                location: None,
            });
        }
    }
    Ok(findings)
}

/// Days since an RFC3339 timestamp, without pulling in chrono: parse
/// the date part and diff against the system clock at day resolution.
fn chrono_lite_days_since(rfc3339: &str) -> Option<i64> {
    let date = rfc3339.split('T').next()?;
    let mut it = date.split('-');
    let (y, m, d): (i64, i64, i64) = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    // Days since civil epoch (Howard Hinnant's algorithm).
    let civil = |y: i64, m: i64, d: i64| -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    };
    let now_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86400) as i64;
    Some(now_days - civil(y, m, d))
}

// ───────────────────── pass (d): catalog audit ──────────────────────

/// Launch the server (caller passes the argv, already sandbox-wrapped
/// if requested), issue `initialize` + `tools/list`, and run the
/// engine's `tool_description` rules over every tool in the catalog.
/// The catalog never reaches an agent.
pub async fn catalog_audit(launch: &[String], engine: &Engine) -> anyhow::Result<Vec<Finding>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (program, args) = launch
        .split_first()
        .ok_or_else(|| anyhow!("empty launch command for catalog audit"))?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to launch '{program}' for catalog audit"))?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("no child stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no child stdout"))?;
    let mut lines = BufReader::new(stdout).lines();

    let send = |frame: serde_json::Value| {
        let mut s = frame.to_string();
        s.push('\n');
        s
    };
    stdin
        .write_all(
            send(serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                            "clientInfo": {"name": "aperion-shield-scan", "version": env!("CARGO_PKG_VERSION")}}
            }))
            .as_bytes(),
        )
        .await?;
    stdin
        .write_all(send(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).as_bytes())
        .await?;
    stdin
        .write_all(send(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).as_bytes())
        .await?;
    stdin.flush().await?;

    let tools = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(line) = lines.next_line().await? {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            if v.get("id").and_then(|i| i.as_i64()) == Some(2) {
                return Ok::<_, anyhow::Error>(
                    v.pointer("/result/tools").cloned().unwrap_or(serde_json::json!([])),
                );
            }
        }
        anyhow::bail!("upstream closed stdout before answering tools/list")
    })
    .await
    .context("timed out waiting for tools/list (20s)")??;

    let _ = child.kill().await;

    let mut findings = Vec::new();
    let empty = vec![];
    let tool_list = tools.as_array().unwrap_or(&empty);
    for t in tool_list {
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let schema = t.get("inputSchema").map(|s| s.to_string()).unwrap_or_default();
        let surface = format!("{desc}\n{schema}");
        let eval = engine.evaluate_scoped_text(
            Scope::ToolDescription,
            Some(name),
            &surface,
            Adjustments::default(),
        );
        for m in eval.matches {
            findings.push(Finding {
                pass: "catalog",
                id: m.rule_id,
                severity: m.severity,
                detail: format!("tool '{name}': {}", m.reason),
                location: None,
            });
        }
    }
    if tool_list.is_empty() {
        findings.push(Finding {
            pass: "catalog",
            id: "scan.catalog.empty".into(),
            severity: Severity::Low,
            detail: "server advertised zero tools (nothing to audit; suspicious for an MCP server)".into(),
            location: None,
        });
    }
    Ok(findings)
}

// ───────────────────────── orchestration ────────────────────────────

pub struct ScanOptions {
    pub target: String,
    /// argv to launch the server for the live catalog pass (pass (d)
    /// is skipped when empty). The caller sandbox-wraps it first.
    pub launch: Vec<String>,
    pub offline: bool,
}

/// Resolve the target into a local directory to static-scan. Network
/// targets are fetched into `workdir` WITHOUT executing anything:
/// `npm pack` (tarball, --ignore-scripts semantics: pack never runs
/// install hooks locally) and `git clone --depth 1`.
pub fn fetch_target(target: &Target, workdir: &Path) -> anyhow::Result<PathBuf> {
    match target {
        Target::LocalPath(p) => Ok(p.clone()),
        Target::Github(url) => {
            let dst = workdir.join("repo");
            let out = std::process::Command::new("git")
                .args(["clone", "--depth", "1", url])
                .arg(&dst)
                .output()
                .context("running git clone")?;
            if !out.status.success() {
                anyhow::bail!("git clone failed: {}", String::from_utf8_lossy(&out.stderr));
            }
            Ok(dst)
        }
        Target::Npm(pkg) => {
            let out = std::process::Command::new("npm")
                .args(["pack", pkg, "--silent"])
                .current_dir(workdir)
                .output()
                .context("running npm pack (is npm installed?)")?;
            if !out.status.success() {
                anyhow::bail!("npm pack failed: {}", String::from_utf8_lossy(&out.stderr));
            }
            let tarball = String::from_utf8_lossy(&out.stdout).trim().lines().last().map(str::to_string)
                .ok_or_else(|| anyhow!("npm pack produced no tarball name"))?;
            let tar_out = std::process::Command::new("tar")
                .args(["xzf", &tarball])
                .current_dir(workdir)
                .output()
                .context("extracting npm tarball")?;
            if !tar_out.status.success() {
                anyhow::bail!("tar extract failed: {}", String::from_utf8_lossy(&tar_out.stderr));
            }
            // npm tarballs unpack to package/
            Ok(workdir.join("package"))
        }
    }
}

pub async fn run_scan(opts: &ScanOptions, engine: &Engine) -> anyhow::Result<Report> {
    let target = Target::parse(&opts.target)?;
    let mut report = Report {
        target: opts.target.clone(),
        findings: Vec::new(),
        passes_run: Vec::new(),
        passes_skipped: Vec::new(),
        verdict: Verdict::Pass,
    };

    // (a) typosquat name-similarity -- pure string comparison against
    // the target name alone, no fetch and no network required. Run
    // this FIRST, before we ever try to pull the package down: a
    // typosquat is often an unpublished or since-yanked name, and we
    // don't want a fetch failure to hide the one signal that doesn't
    // depend on the fetch succeeding.
    if let Target::Npm(pkg) = &target {
        report.findings.extend(typosquat_scan(pkg));
        report.passes_run.push("typosquat");
    } else {
        report.passes_skipped.push((
            "typosquat",
            "name-similarity check only applies to a registry package name".into(),
        ));
    }

    let tmp = tempfile::tempdir().context("creating scan workdir")?;

    // (b) static -- needs the fetched source, so a fetch failure only
    // takes this pass down, not the whole scan (metadata and catalog
    // below don't depend on `root` at all).
    match fetch_target(&target, tmp.path()) {
        Ok(root) => {
            report.findings.extend(static_scan(&root));
            report.passes_run.push("static");
        }
        Err(e) => report.passes_skipped.push(("static", format!("{e:#}"))),
    }

    // (c) metadata
    if opts.offline {
        report.passes_skipped.push(("metadata", "--scan-offline".into()));
    } else if let Target::Npm(pkg) = &target {
        match npm_metadata_scan(pkg).await {
            Ok(f) => {
                report.findings.extend(f);
                report.passes_run.push("metadata");
            }
            Err(e) => report.passes_skipped.push(("metadata", format!("{e:#}"))),
        }
    } else {
        report
            .passes_skipped
            .push(("metadata", "only npm targets have registry metadata today".into()));
    }

    // (d) live catalog
    if opts.launch.is_empty() {
        report.passes_skipped.push((
            "catalog",
            "no launch command given (append `-- <cmd...>` to run the live catalog audit)".into(),
        ));
    } else {
        match catalog_audit(&opts.launch, engine).await {
            Ok(f) => {
                report.findings.extend(f);
                report.passes_run.push("catalog");
            }
            Err(e) => report.passes_skipped.push(("catalog", format!("{e:#}"))),
        }
    }

    report.finalize();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_static_signatures_compile() {
        assert_eq!(COMPILED_SIGS.len(), STATIC_SIGS.len());
    }

    #[test]
    fn target_parsing() {
        assert_eq!(Target::parse("npm:foo").unwrap(), Target::Npm("foo".into()));
        assert_eq!(
            Target::parse("https://github.com/o/r").unwrap(),
            Target::Github("https://github.com/o/r".into())
        );
        assert_eq!(Target::parse(".").unwrap(), Target::LocalPath(".".into()));
        assert_eq!(Target::parse("some-package").unwrap(), Target::Npm("some-package".into()));
        assert!(Target::parse("./does-not-exist-xyz").is_err());
        assert!(Target::parse("https://gitlab.com/o/r").is_err());
    }

    fn scan_str(name: &str, content: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(name), content).unwrap();
        static_scan(dir.path()).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn static_scan_catches_ssh_read() {
        let ids = scan_str("index.js", r#"const k = fs.readFileSync(home + "/.ssh/id_rsa");"#);
        assert!(ids.contains(&"scan.static.ssh_key_read".to_string()), "{ids:?}");
    }

    #[test]
    fn static_scan_catches_env_exfil() {
        let ids = scan_str("x.js", "fetch(url, {body: JSON.stringify(process.env)})");
        assert!(ids.contains(&"scan.static.env_exfil_js".to_string()), "{ids:?}");
    }

    #[test]
    fn static_scan_catches_b64_exec() {
        let ids = scan_str("x.js", "eval(atob(payload))");
        assert!(ids.contains(&"scan.static.b64_exec".to_string()), "{ids:?}");
    }

    #[test]
    fn static_scan_install_hook_only_in_package_json() {
        let ids = scan_str("package.json", r#"{"scripts": {"postinstall": "node evil.js"}}"#);
        assert!(ids.contains(&"scan.static.install_script".to_string()), "{ids:?}");
        let ids = scan_str("README.json", r#"{"scripts": {"postinstall": "node evil.js"}}"#);
        assert!(!ids.contains(&"scan.static.install_script".to_string()), "{ids:?}");
    }

    #[test]
    fn benign_source_is_clean() {
        let ids = scan_str(
            "server.js",
            r#"
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
const server = new Server({ name: "weather", version: "1.0.0" });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "get_forecast", description: "Get weather forecast for a city" }],
}));
"#,
        );
        assert!(ids.is_empty(), "{ids:?}");
    }

    #[test]
    fn typosquat_flags_separator_collision() {
        let ids: Vec<String> = typosquat_scan("mcp_shield").into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"scan.typo.name_collision".to_string()), "{ids:?}");

        let ids: Vec<String> = typosquat_scan("mcpshield").into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"scan.typo.name_collision".to_string()), "{ids:?}");

        let ids: Vec<String> = typosquat_scan("MCP.Shield").into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"scan.typo.name_collision".to_string()), "{ids:?}");
    }

    #[test]
    fn typosquat_flags_small_edit_distance() {
        // homoglyph-ish: 'l' -> '1' against the known "mcp-shield".
        let ids: Vec<String> = typosquat_scan("mcp-shie1d").into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"scan.typo.similar_name".to_string()), "{ids:?}");

        // classic typo (dropped letter) against a longer known name.
        let ids: Vec<String> =
            typosquat_scan("@modelcontextprotocol/server-githb").into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&"scan.typo.similar_name".to_string()), "{ids:?}");
    }

    #[test]
    fn typosquat_no_finding_on_known_good_package() {
        let findings = typosquat_scan("@modelcontextprotocol/server-github");
        assert!(findings.is_empty(), "{findings:?}");
        let findings = typosquat_scan("mcp-shield");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn typosquat_no_finding_on_unrelated_name() {
        let findings = typosquat_scan("my-companys-internal-widget-formatter-tool");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn edit_distance_basic_cases() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn normalize_strips_separators_and_case() {
        assert_eq!(normalize_pkg_name("mcp-shield"), "mcpshield");
        assert_eq!(normalize_pkg_name("mcp_shield"), "mcpshield");
        assert_eq!(normalize_pkg_name("MCP.Shield"), "mcpshield");
        assert_eq!(normalize_pkg_name("@scope/mcp-shield"), "scopemcpshield");
    }

    #[test]
    fn days_since_parses_rfc3339() {
        let d = chrono_lite_days_since("2020-01-01T00:00:00.000Z").unwrap();
        assert!(d > 2000, "{d}");
        let recent = chrono_lite_days_since("2099-01-01T00:00:00Z").unwrap();
        assert!(recent < 0);
    }

    #[test]
    fn verdict_mapping() {
        let mut r = Report {
            target: "t".into(), findings: vec![], passes_run: vec![],
            passes_skipped: vec![], verdict: Verdict::Pass,
        };
        r.finalize();
        assert_eq!(r.verdict, Verdict::Pass);
        r.findings.push(Finding {
            pass: "static", id: "x".into(), severity: Severity::Medium,
            detail: "".into(), location: None,
        });
        r.finalize();
        assert_eq!(r.verdict, Verdict::Caution);
        assert_eq!(r.exit_code(), 1);
        r.findings.push(Finding {
            pass: "static", id: "y".into(), severity: Severity::Critical,
            detail: "".into(), location: None,
        });
        r.finalize();
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.exit_code(), 2);
    }
}

//! `aperion-shield --summarize <path>...` (v1.7).
//!
//! The other half of the I/O offload gate. When `hooks::offload` refuses
//! a full read of a large file, the deny reason tells the agent to run
//! this instead. We read the files locally, post them with the agent's
//! question to Smartflow's `/api/offload/summarize`, and print the
//! bullets the gateway got back from the efficient model. The frontier
//! model sees a dozen lines instead of a few thousand.
//!
//! Where the gateway comes from, in order:
//!
//!   1. `--offload-url` / `--offload-key` flags
//!   2. `APERION_SHIELD_OFFLOAD_URL` / `APERION_SHIELD_OFFLOAD_KEY`
//!   3. the org-mode enrollment record (`~/.aperion-shield/orgmode.json`)
//!
//! Standalone users who are not enrolled need (1) or (2); the summary
//! runs on their own Smartflow, never on a third party.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

use crate::orgmode::OrgState;

pub const URL_ENV: &str = "APERION_SHIELD_OFFLOAD_URL";
pub const KEY_ENV: &str = "APERION_SHIELD_OFFLOAD_KEY";

/// Per-file byte ceiling before we stop reading and let the gateway's
/// own head/tail truncation take over. 2 MiB is well past any source file.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SummarizeOpts {
    pub paths: Vec<PathBuf>,
    pub question: String,
    pub max_bullets: Option<usize>,
    pub model: Option<String>,
    pub url: Option<String>,
    pub key: Option<String>,
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct FileBody<'a> {
    path: String,
    content: &'a str,
}

#[derive(Debug, Serialize)]
struct RequestBody<'a> {
    question: &'a str,
    files: Vec<FileBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_bullets: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<&'a str>,
    source: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct Tokens {
    pub input_before: u64,
    pub summary: u64,
    pub saved: u64,
}

#[derive(Debug, Deserialize)]
pub struct SummarizeResponse {
    pub request_id: String,
    pub model: String,
    pub bullets: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
    pub tokens: Tokens,
}

/// Resolve `(base_url, bearer)` from flags, env, then org-mode.
pub fn resolve_endpoint(
    url_flag: Option<&str>,
    key_flag: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let env_url = std::env::var(URL_ENV).ok();
    let env_key = std::env::var(KEY_ENV).ok();
    let org = OrgState::load().ok().flatten();
    resolve_endpoint_from(url_flag, key_flag, env_url, env_key, org)
}

fn resolve_endpoint_from(
    url_flag: Option<&str>,
    key_flag: Option<&str>,
    env_url: Option<String>,
    env_key: Option<String>,
    org: Option<OrgState>,
) -> anyhow::Result<(String, String)> {
    let non_empty = |s: String| if s.trim().is_empty() { None } else { Some(s) };
    let mut url = url_flag.map(str::to_string).or(env_url.and_then(non_empty));
    let mut key = key_flag.map(str::to_string).or(env_key.and_then(non_empty));

    if let Some(state) = org {
        url.get_or_insert(state.smartflow_url);
        key.get_or_insert(state.vkey);
    }

    let url = url.ok_or_else(|| {
        anyhow!(
            "no Smartflow gateway configured for --summarize. Pass --offload-url, set \
{URL_ENV}, or enroll with `aperion-shield --enroll --smartflow-url <URL> --token <TOKEN>`."
        )
    })?;
    let key = key.ok_or_else(|| {
        anyhow!("no virtual key for --summarize. Pass --offload-key, set {KEY_ENV}, or enroll.")
    })?;
    Ok((url.trim_end_matches('/').to_string(), key))
}

fn read_file(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        return Err(anyhow!("{} is not a regular file", path.display()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(anyhow!(
            "{} is {} bytes; over the {} MiB --summarize ceiling. Use a targeted range instead.",
            path.display(),
            meta.len(),
            MAX_FILE_BYTES / 1024 / 1024
        ));
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.iter().take(4096).any(|&b| b == 0) {
        return Err(anyhow!(
            "{} looks binary; nothing to summarize",
            path.display()
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Default question when the agent didn't pass one. Broad on purpose:
/// structure plus the things you'd need to edit it.
pub fn default_question() -> &'static str {
    "What does this file do? List the main types/functions/sections with their line \
numbers, any external dependencies or config keys it reads, and anything that looks like \
an error path or a TODO."
}

pub async fn run(opts: SummarizeOpts) -> anyhow::Result<i32> {
    if opts.paths.is_empty() {
        return Err(anyhow!("--summarize needs at least one path"));
    }
    let (base, key) = resolve_endpoint(opts.url.as_deref(), opts.key.as_deref())?;

    let mut contents: Vec<(String, String)> = Vec::with_capacity(opts.paths.len());
    for p in &opts.paths {
        let text = read_file(p)?;
        contents.push((p.display().to_string(), text));
    }
    let raw_lines: usize = contents.iter().map(|(_, c)| c.lines().count()).sum();

    let question = if opts.question.trim().is_empty() {
        default_question()
    } else {
        opts.question.as_str()
    };
    let body = RequestBody {
        question,
        files: contents
            .iter()
            .map(|(path, content)| FileBody {
                path: path.clone(),
                content,
            })
            .collect(),
        max_bullets: opts.max_bullets,
        model: opts.model.as_deref(),
        source: "aperion-shield --summarize",
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(150))
        .user_agent(format!("aperion-shield/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let url = format!("{base}/api/offload/summarize");
    let resp = client
        .post(&url)
        .bearer_auth(&key)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or(text);
        return Err(anyhow!("gateway {status}: {msg}"));
    }
    let parsed: SummarizeResponse =
        serde_json::from_str(&text).context("gateway returned unexpected JSON")?;

    if opts.json {
        println!("{text}");
    } else {
        println!("{}", render_markdown(&parsed, &contents, raw_lines));
    }
    eprintln!(
        "[shield] offload: {} line(s) in {} file(s) -> {} bullet(s) on {}; ~{} tokens kept out of the frontier model (id {})",
        raw_lines,
        contents.len(),
        parsed.bullets.len(),
        parsed.model,
        parsed.tokens.saved,
        parsed.request_id
    );
    Ok(0)
}

pub fn render_markdown(
    r: &SummarizeResponse,
    files: &[(String, String)],
    raw_lines: usize,
) -> String {
    let mut out = String::new();
    let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    out.push_str(&format!(
        "Summary of {} ({} lines, via {}):\n",
        names.join(", "),
        raw_lines,
        r.model
    ));
    for b in &r.bullets {
        out.push_str("- ");
        out.push_str(b);
        out.push('\n');
    }
    if r.truncated {
        out.push_str(
            "- (file was cut to head+tail for size; ask for a targeted line range if a middle section matters)\n",
        );
    }
    out.push_str(
        "\nNeed exact text to edit? Read a targeted range (offset/limit) around the cited lines.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> OrgState {
        OrgState {
            smartflow_url: "https://org.example".into(),
            vkey: "sk-sf-org".into(),
            device_id: "d".into(),
            policy_group: "g".into(),
            owner_email: None,
            enrolled_at: String::new(),
            platform: "macos".into(),
            device_name: "n".into(),
            device_fingerprint: "f".into(),
        }
    }

    #[test]
    fn resolve_prefers_flags_then_env_then_org() {
        let env_u = Some("https://env.example/".to_string());
        let env_k = Some("sk-sf-env".to_string());
        let (u, k) = resolve_endpoint_from(
            Some("https://flag.example/"),
            None,
            env_u.clone(),
            env_k.clone(),
            Some(org()),
        )
        .unwrap();
        assert_eq!(u, "https://flag.example");
        assert_eq!(k, "sk-sf-env");

        let (u, k) =
            resolve_endpoint_from(None, Some("sk-sf-flag"), env_u, None, Some(org())).unwrap();
        assert_eq!(u, "https://env.example");
        assert_eq!(k, "sk-sf-flag");

        let (u, k) =
            resolve_endpoint_from(None, None, Some("  ".into()), None, Some(org())).unwrap();
        assert_eq!(u, "https://org.example");
        assert_eq!(k, "sk-sf-org");
    }

    #[test]
    fn resolve_without_anything_is_a_clear_error() {
        let err = resolve_endpoint_from(None, None, None, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offload-url"), "{err}");
    }

    #[test]
    fn read_file_rejects_binary_and_dirs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_file(dir.path()).is_err());
        let bin = dir.path().join("x.bin");
        std::fs::write(&bin, [0u8, 1, 2, 3]).unwrap();
        assert!(read_file(&bin).unwrap_err().to_string().contains("binary"));
        let ok = dir.path().join("x.rs");
        std::fs::write(&ok, "fn main() {}\n").unwrap();
        assert_eq!(read_file(&ok).unwrap(), "fn main() {}\n");
    }

    #[test]
    fn render_lists_bullets_and_truncation_note() {
        let r = SummarizeResponse {
            request_id: "abc".into(),
            model: "gpt-4o-mini".into(),
            bullets: vec!["a src/x.rs:1".into(), "b".into()],
            truncated: true,
            tokens: Tokens {
                input_before: 1000,
                summary: 20,
                saved: 980,
            },
        };
        let md = render_markdown(&r, &[("src/x.rs".into(), String::new())], 1234);
        assert!(md.starts_with("Summary of src/x.rs (1234 lines, via gpt-4o-mini):"));
        assert!(md.contains("- a src/x.rs:1\n- b\n"));
        assert!(md.contains("head+tail"));
    }
}

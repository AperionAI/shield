//! Claude Desktop third-party inference config.
//!
//! The desktop app does not read `~/.claude/settings.json` or
//! `ANTHROPIC_BASE_URL`. It sends chats to Anthropic until this file
//! names the gateway. The virtual key stays in the keystore; the app
//! runs `aperion-shield --api-key` when it needs it.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::{json, Value};

use super::state::OrgState;
use super::write_private;

const ENTRY_ID: &str = "smartflow";

pub fn default_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/var/root".into());
        return PathBuf::from(home).join("Library/Application Support/Claude-3p/configLibrary");
    }
    #[cfg(target_os = "windows")]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        return PathBuf::from(local).join("Claude-3p").join("configLibrary");
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".config/Claude-3p/configLibrary")
    }
}

/// Point Claude Desktop at this enrollment. Re-running updates the same
/// file and leaves any other saved configurations in place.
pub fn apply(state: &OrgState) -> anyhow::Result<PathBuf> {
    let bin = std::env::current_exe().context("locate aperion-shield")?;
    let bin = bin.canonicalize().unwrap_or(bin);
    write_config(&default_dir(), state.smartflow_url.trim_end_matches('/'), &bin)
}

pub fn write_config(dir: &Path, base_url: &str, bin: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let meta_path = dir.join("_meta.json");
    let mut meta = read_json(&meta_path).unwrap_or_else(|_| json!({}));
    if !meta.is_object() {
        meta = json!({});
    }
    let applied = meta
        .get("appliedId")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty() && dir.join(format!("{id}.json")).is_file())
        .map(str::to_string)
        .unwrap_or_else(|| ENTRY_ID.to_string());

    let entry_path = dir.join(format!("{applied}.json"));
    let mut cfg = read_json(&entry_path).unwrap_or_else(|_| json!({}));
    if !cfg.is_object() {
        cfg = json!({});
    }
    let obj = cfg.as_object_mut().expect("object");
    obj.insert("inferenceProvider".into(), json!("gateway"));
    obj.insert(
        "inferenceGatewayBaseUrl".into(),
        json!(base_url.trim_end_matches('/')),
    );
    obj.insert("inferenceCredentialKind".into(), json!("helper-script"));
    obj.insert("inferenceCredentialHelper".into(), json!(bin.to_string_lossy()));
    obj.insert("inferenceCredentialHelperArgs".into(), json!(["--api-key"]));
    obj.insert("inferenceGatewayAuthScheme".into(), json!("bearer"));
    obj.insert("inferenceCredentialHelperTtlSec".into(), json!(900));
    obj.insert("modelDiscoveryEnabled".into(), json!(false));
    obj.insert("autoModeEnabled".into(), json!(false));
    obj.insert("isClaudeCodeForDesktopEnabled".into(), json!(true));
    obj.insert(
        "inferenceModels".into(),
        json!([
            {"name": "claude-haiku-4-5", "anthropicFamilyTier": "haiku", "isFamilyDefault": true},
            {"name": "claude-sonnet-4-5", "anthropicFamilyTier": "sonnet", "isFamilyDefault": true},
            {"name": "claude-opus-4-5", "anthropicFamilyTier": "opus", "isFamilyDefault": true}
        ]),
    );
    obj.remove("inferenceGatewayApiKey");

    let body = serde_json::to_string_pretty(&cfg)? + "\n";
    write_private(&entry_path, body.as_bytes())?;

    meta["appliedId"] = json!(applied);
    if let Some(entries) = meta.get_mut("entries").and_then(|v| v.as_array_mut()) {
        let present = entries.iter().any(|e| e.get("id").and_then(|v| v.as_str()) == Some(applied.as_str()));
        if !present {
            entries.push(json!({"id": applied, "name": "Smartflow"}));
        }
    } else if meta.get("entries").is_none() {
        meta["entries"] = json!([{"id": applied, "name": "Smartflow"}]);
    }
    let meta_body = serde_json::to_string_pretty(&meta)? + "\n";
    write_private(&meta_path, meta_body.as_bytes())?;
    Ok(entry_path)
}

fn read_json(path: &Path) -> anyhow::Result<Value> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_gateway_without_a_key_and_keeps_other_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(
            dir.join("_meta.json"),
            r#"{"appliedId":"existing","entries":[{"id":"existing","name":"Old"}]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("existing.json"),
            r#"{"inferenceGatewayApiKey":"sk-sf-secret","banner":"keep me"}"#,
        )
        .unwrap();
        let path = write_config(dir, "https://sf.example/", Path::new("/usr/local/bin/aperion-shield")).unwrap();
        assert_eq!(path, dir.join("existing.json"));
        let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg["inferenceProvider"], "gateway");
        assert_eq!(cfg["inferenceGatewayBaseUrl"], "https://sf.example");
        assert_eq!(cfg["inferenceCredentialKind"], "helper-script");
        assert_eq!(cfg["inferenceCredentialHelperArgs"][0], "--api-key");
        assert_eq!(cfg["autoModeEnabled"], false);
        assert_eq!(cfg["banner"], "keep me");
        assert!(cfg.get("inferenceGatewayApiKey").is_none());
        assert!(!cfg.to_string().contains("sk-sf-"));
        let meta: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("_meta.json")).unwrap()).unwrap();
        assert_eq!(meta["appliedId"], "existing");
        assert_eq!(meta["entries"][0]["name"], "Old");
    }
}

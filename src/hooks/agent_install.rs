//! User-level installer for native agent hooks (v1.5).
//!
//! Writes:
//!   * `~/.aperion-shield/hooks/claude-pretooluse.sh`
//!   * `~/.aperion-shield/hooks/cursor-pretooluse.sh`
//!   * merges `~/.claude/settings.json` `hooks.PreToolUse`
//!   * merges `~/.cursor/hooks.json` `hooks.preToolUse`
//!
//! Both wrappers fail closed if `aperion-shield` is missing from PATH
//! and the install-time absolute path is gone. `SHIELD_HOOKS_DISABLE=1`
//! is the documented bypass, matching the git-hook contract.
//!
//! Project-level hook files are intentionally not touched: TrustFall
//! (CSA 2026-07) is project-injected MCP / hook config. User-level
//! install is the point.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const APERION_AGENT_HOOK_MARKER: &str =
    "# APERION-SHIELD-AGENT-HOOK v1 -- managed by `aperion-shield --install-agent-hooks`";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHookKind {
    Claude,
    Cursor,
}

impl AgentHookKind {
    pub fn wrapper_filename(self) -> &'static str {
        match self {
            Self::Claude => "claude-pretooluse.sh",
            Self::Cursor => "cursor-pretooluse.sh",
        }
    }

    pub fn dialect_flag(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstallOutcome {
    Installed,
    Refreshed,
    Merged,
    UnknownPresent,
}

#[derive(Debug)]
pub struct AgentInstallReport {
    pub home: PathBuf,
    pub hooks_dir: PathBuf,
    pub claude_wrapper: AgentInstallOutcome,
    pub cursor_wrapper: AgentInstallOutcome,
    pub claude_settings: AgentInstallOutcome,
    pub cursor_settings: AgentInstallOutcome,
    pub shield_bin: Option<PathBuf>,
}

#[derive(Debug)]
pub struct AgentUninstallReport {
    pub home: PathBuf,
    pub claude_wrapper_removed: bool,
    pub cursor_wrapper_removed: bool,
    pub claude_settings_cleared: bool,
    pub cursor_settings_cleared: bool,
}

fn default_home() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow!("couldn't resolve home directory"))
}

fn which_shield() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("APERION_SHIELD_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if exe
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("aperion-shield"))
            .unwrap_or(false)
        {
            return Some(exe);
        }
    }
    which_on_path("aperion-shield")
}

fn which_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{bin}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

pub fn hooks_dir(home: &Path) -> PathBuf {
    home.join(".aperion-shield").join("hooks")
}

pub fn claude_settings_path(home: &Path) -> PathBuf {
    home.join(".claude").join("settings.json")
}

pub fn cursor_hooks_path(home: &Path) -> PathBuf {
    home.join(".cursor").join("hooks.json")
}

fn wrapper_script(kind: AgentHookKind, baked_bin: Option<&Path>) -> String {
    let dialect = kind.dialect_flag();
    let baked = baked_bin
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let fail_json = match kind {
        AgentHookKind::Claude => {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"aperion-shield is not installed (fail-closed)"}}"#
        }
        AgentHookKind::Cursor => {
            r#"{"permission":"deny","permissionDecisionReason":"aperion-shield is not installed (fail-closed)"}"#
        }
    };
    format!(
        r#"#!/bin/sh
{marker}
#
# Fail-closed PreToolUse wrapper. Do not edit by hand -- refresh with
#   aperion-shield --install-agent-hooks
#
if [ "${{SHIELD_HOOKS_DISABLE:-}}" = "1" ]; then
  exit 0
fi
BIN="${{APERION_SHIELD_BIN:-{baked}}}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  BIN="$(command -v aperion-shield 2>/dev/null || true)"
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  printf '%s\n' '{fail_json}'
  exit 2
fi
exec "$BIN" --check-hook --hook-dialect {dialect}
"#,
        marker = APERION_AGENT_HOOK_MARKER,
        baked = shell_single_quote(&baked),
        fail_json = fail_json,
        dialect = dialect,
    )
}

fn shell_single_quote(s: &str) -> String {
    // The baked path is interpolated into BIN="...". Escape any double
    // quotes so a weird install prefix can't break the wrapper.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_wrapper(dir: &Path, kind: AgentHookKind, baked_bin: Option<&Path>) -> Result<AgentInstallOutcome> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(kind.wrapper_filename());
    let body = wrapper_script(kind, baked_bin);
    let outcome = if path.exists() {
        let existing = fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(APERION_AGENT_HOOK_MARKER) {
            AgentInstallOutcome::Refreshed
        } else {
            AgentInstallOutcome::Refreshed
        }
    } else {
        AgentInstallOutcome::Installed
    };
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)?;
    }
    Ok(outcome)
}

fn command_entry(wrapper: &Path) -> Value {
    json!({
        "type": "command",
        "command": wrapper.to_string_lossy(),
    })
}

fn is_our_command(cmd: &str, wrapper: &Path) -> bool {
    let w = wrapper.to_string_lossy();
    cmd == w.as_ref()
        || cmd.ends_with(wrapper.file_name().and_then(|n| n.to_str()).unwrap_or(""))
        || cmd.contains("aperion-shield --check-hook")
}

fn merge_claude_settings(path: &Path, wrapper: &Path, chain_existing: bool) -> Result<AgentInstallOutcome> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut root: Value = if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?
        }
    } else {
        json!({})
    };

    let hooks = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} root is not a JSON object", path.display()))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} hooks is not an object", path.display()))?;
    let pre = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    let arr = pre
        .as_array_mut()
        .ok_or_else(|| anyhow!("{} hooks.PreToolUse is not an array", path.display()))?;

    let already = arr.iter().any(|entry| {
        entry
            .pointer("/hooks/0/command")
            .and_then(|v| v.as_str())
            .map(|c| is_our_command(c, wrapper))
            .unwrap_or(false)
            || entry
                .get("command")
                .and_then(|v| v.as_str())
                .map(|c| is_our_command(c, wrapper))
                .unwrap_or(false)
    });
    if already {
        // Refresh the command path in place.
        for entry in arr.iter_mut() {
            if let Some(hooks_arr) = entry.get_mut("hooks").and_then(|v| v.as_array_mut()) {
                for h in hooks_arr {
                    if let Some(cmd) = h.get("command").and_then(|v| v.as_str()) {
                        if is_our_command(cmd, wrapper) {
                            h["command"] = json!(wrapper.to_string_lossy());
                        }
                    }
                }
            }
        }
        fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
        return Ok(AgentInstallOutcome::Refreshed);
    }

    if !arr.is_empty() && !chain_existing {
        return Ok(AgentInstallOutcome::UnknownPresent);
    }

    arr.push(json!({
        "matcher": "*",
        "hooks": [command_entry(wrapper)],
    }));
    fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    Ok(if path.exists() {
        AgentInstallOutcome::Merged
    } else {
        AgentInstallOutcome::Installed
    })
}

fn merge_cursor_hooks(path: &Path, wrapper: &Path, chain_existing: bool) -> Result<AgentInstallOutcome> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut root: Value = if path.exists() {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        if raw.trim().is_empty() {
            json!({"version": 1, "hooks": {}})
        } else {
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?
        }
    } else {
        json!({"version": 1, "hooks": {}})
    };

    if root.get("version").is_none() {
        root["version"] = json!(1);
    }
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} root is not a JSON object", path.display()))?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} hooks is not an object", path.display()))?;
    let pre = hooks_obj.entry("preToolUse").or_insert_with(|| json!([]));
    let arr = pre
        .as_array_mut()
        .ok_or_else(|| anyhow!("{} hooks.preToolUse is not an array", path.display()))?;

    let already = arr.iter().any(|entry| {
        entry
            .get("command")
            .and_then(|v| v.as_str())
            .map(|c| is_our_command(c, wrapper))
            .unwrap_or(false)
    });
    if already {
        for entry in arr.iter_mut() {
            if let Some(cmd) = entry.get("command").and_then(|v| v.as_str()) {
                if is_our_command(cmd, wrapper) {
                    entry["command"] = json!(wrapper.to_string_lossy());
                }
            }
        }
        fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
        return Ok(AgentInstallOutcome::Refreshed);
    }

    if !arr.is_empty() && !chain_existing {
        return Ok(AgentInstallOutcome::UnknownPresent);
    }

    arr.push(json!({
        "command": wrapper.to_string_lossy(),
    }));
    fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    Ok(AgentInstallOutcome::Merged)
}

/// Install wrappers + merge user-level Claude/Cursor config under `home`.
pub fn install(home: Option<&Path>, chain_existing: bool) -> Result<AgentInstallReport> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => default_home()?,
    };
    let hooks = hooks_dir(&home);
    let shield_bin = which_shield();
    let baked = shield_bin.as_deref();

    let claude_wrapper = write_wrapper(&hooks, AgentHookKind::Claude, baked)?;
    let cursor_wrapper = write_wrapper(&hooks, AgentHookKind::Cursor, baked)?;

    let claude_w = hooks.join(AgentHookKind::Claude.wrapper_filename());
    let cursor_w = hooks.join(AgentHookKind::Cursor.wrapper_filename());

    let claude_settings = merge_claude_settings(
        &claude_settings_path(&home),
        &claude_w,
        chain_existing,
    )?;
    let cursor_settings = merge_cursor_hooks(
        &cursor_hooks_path(&home),
        &cursor_w,
        chain_existing,
    )?;

    Ok(AgentInstallReport {
        home,
        hooks_dir: hooks,
        claude_wrapper,
        cursor_wrapper,
        claude_settings,
        cursor_settings,
        shield_bin,
    })
}

fn strip_our_claude_entries(arr: &mut Vec<Value>, wrapper: &Path) -> bool {
    let before = arr.len();
    arr.retain(|entry| {
        let ours = entry
            .pointer("/hooks/0/command")
            .and_then(|v| v.as_str())
            .map(|c| is_our_command(c, wrapper))
            .unwrap_or(false)
            || entry
                .get("command")
                .and_then(|v| v.as_str())
                .map(|c| is_our_command(c, wrapper))
                .unwrap_or(false);
        !ours
    });
    arr.len() != before
}

fn strip_our_cursor_entries(arr: &mut Vec<Value>, wrapper: &Path) -> bool {
    let before = arr.len();
    arr.retain(|entry| {
        let ours = entry
            .get("command")
            .and_then(|v| v.as_str())
            .map(|c| is_our_command(c, wrapper))
            .unwrap_or(false);
        !ours
    });
    arr.len() != before
}

/// Remove only our wrappers and our entries in the JSON configs.
pub fn uninstall(home: Option<&Path>) -> Result<AgentUninstallReport> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => default_home()?,
    };
    let hooks = hooks_dir(&home);
    let claude_w = hooks.join(AgentHookKind::Claude.wrapper_filename());
    let cursor_w = hooks.join(AgentHookKind::Cursor.wrapper_filename());

    let claude_wrapper_removed = remove_our_file(&claude_w)?;
    let cursor_wrapper_removed = remove_our_file(&cursor_w)?;

    let claude_settings_cleared =
        clear_claude_settings(&claude_settings_path(&home), &claude_w)?;
    let cursor_settings_cleared = clear_cursor_hooks(&cursor_hooks_path(&home), &cursor_w)?;

    Ok(AgentUninstallReport {
        home,
        claude_wrapper_removed,
        cursor_wrapper_removed,
        claude_settings_cleared,
        cursor_settings_cleared,
    })
}

fn remove_our_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let body = fs::read_to_string(path).unwrap_or_default();
    if !body.contains(APERION_AGENT_HOOK_MARKER) {
        anyhow::bail!(
            "{} exists but is not an Aperion agent hook -- leaving it alone",
            path.display()
        );
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn clear_claude_settings(path: &Path, wrapper: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path)?;
    let mut root: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    let Some(arr) = root
        .pointer_mut("/hooks/PreToolUse")
        .and_then(|v| v.as_array_mut())
    else {
        return Ok(false);
    };
    let changed = strip_our_claude_entries(arr, wrapper);
    if changed {
        fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    }
    Ok(changed)
}

fn clear_cursor_hooks(path: &Path, wrapper: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path)?;
    let mut root: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    let Some(arr) = root
        .pointer_mut("/hooks/preToolUse")
        .and_then(|v| v.as_array_mut())
    else {
        return Ok(false);
    };
    let changed = strip_our_cursor_entries(arr, wrapper);
    if changed {
        fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_creates_wrappers_and_json() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let report = install(Some(home), false).unwrap();
        assert_eq!(report.claude_wrapper, AgentInstallOutcome::Installed);
        assert_eq!(report.cursor_wrapper, AgentInstallOutcome::Installed);

        let claude_w = hooks_dir(home).join("claude-pretooluse.sh");
        let body = fs::read_to_string(&claude_w).unwrap();
        assert!(body.contains(APERION_AGENT_HOOK_MARKER));
        assert!(body.contains("fail-closed"));
        assert!(body.contains("--hook-dialect claude"));

        let settings: Value =
            serde_json::from_str(&fs::read_to_string(claude_settings_path(home)).unwrap()).unwrap();
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["matcher"],
            json!("*")
        );
        assert!(settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("claude-pretooluse.sh"));

        let cursor: Value =
            serde_json::from_str(&fs::read_to_string(cursor_hooks_path(home)).unwrap()).unwrap();
        assert!(cursor["hooks"]["preToolUse"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("cursor-pretooluse.sh"));

        // Idempotent refresh.
        let report2 = install(Some(home), false).unwrap();
        assert_eq!(report2.claude_settings, AgentInstallOutcome::Refreshed);
        assert_eq!(report2.cursor_settings, AgentInstallOutcome::Refreshed);

        let un = uninstall(Some(home)).unwrap();
        assert!(un.claude_wrapper_removed);
        assert!(un.cursor_wrapper_removed);
        assert!(un.claude_settings_cleared);
        assert!(un.cursor_settings_cleared);
        assert!(!claude_w.exists());
    }

    #[test]
    fn refuses_to_clobber_foreign_hooks_without_chain() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let cursor_path = cursor_hooks_path(home);
        fs::create_dir_all(cursor_path.parent().unwrap()).unwrap();
        fs::write(
            &cursor_path,
            r#"{"version":1,"hooks":{"preToolUse":[{"command":"endorctl ai-audit cursor"}]}}"#,
        )
        .unwrap();
        let report = install(Some(home), false).unwrap();
        assert_eq!(report.cursor_settings, AgentInstallOutcome::UnknownPresent);
        let raw = fs::read_to_string(&cursor_path).unwrap();
        assert!(raw.contains("endorctl"));
        assert!(!raw.contains("cursor-pretooluse.sh"));

        let report2 = install(Some(home), true).unwrap();
        assert_eq!(report2.cursor_settings, AgentInstallOutcome::Merged);
        let raw2 = fs::read_to_string(&cursor_path).unwrap();
        assert!(raw2.contains("endorctl"));
        assert!(raw2.contains("cursor-pretooluse.sh"));
    }

    #[test]
    fn wrapper_denies_when_binary_missing() {
        let script = wrapper_script(AgentHookKind::Claude, None);
        assert!(script.contains("permissionDecision\":\"deny\"") || script.contains("fail-closed"));
        assert!(script.contains("exit 2"));
        assert!(script.contains("SHIELD_HOOKS_DISABLE"));
    }
}

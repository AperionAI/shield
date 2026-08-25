//! User-level installer for native agent hooks (v1.5+).
//!
//! Writes fail-closed wrappers under `~/.aperion-shield/hooks/` and
//! merges user-level host config:
//!   * Claude Code `~/.claude/settings.json` `hooks.PreToolUse`
//!   * Cursor `~/.cursor/hooks.json` `hooks.preToolUse`
//!   * Codex `~/.codex/hooks.json` `hooks.preToolUse`
//!   * Gemini CLI `~/.gemini/settings.json` `hooks.PreToolUse`
//!   * Copilot CLI `~/.copilot/hooks.json` `hooks.preToolUse`
//!
//! Project-level hook files are not modified. Install prints them
//! (TrustFall: a repo can drop `.cursor/hooks.json`). `--scan-ide`
//! flags the same files as findings.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const APERION_AGENT_HOOK_MARKER: &str =
    "# APERION-SHIELD-AGENT-HOOK v1 -- managed by `aperion-shield --install-agent-hooks`";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStyle {
    /// Claude Code / Gemini: `hooks.PreToolUse` array of `{matcher, hooks:[{command}]}`.
    ClaudePreToolUse,
    /// Cursor / Codex / Copilot: `hooks.preToolUse` array of `{command}`.
    CursorPreToolUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentHookKind {
    Claude,
    Cursor,
    Codex,
    Gemini,
    Copilot,
}

impl AgentHookKind {
    pub const ALL: [AgentHookKind; 5] = [
        Self::Claude,
        Self::Cursor,
        Self::Codex,
        Self::Gemini,
        Self::Copilot,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Copilot => "copilot",
        }
    }

    pub fn wrapper_filename(self) -> String {
        #[cfg(windows)]
        {
            format!("{}-pretooluse.cmd", self.slug())
        }
        #[cfg(not(windows))]
        {
            format!("{}-pretooluse.sh", self.slug())
        }
    }

    pub fn dialect_flag(self) -> &'static str {
        match self {
            Self::Claude | Self::Gemini => "claude",
            Self::Cursor | Self::Codex | Self::Copilot => "cursor",
        }
    }

    pub fn merge_style(self) -> MergeStyle {
        match self {
            Self::Claude | Self::Gemini => MergeStyle::ClaudePreToolUse,
            Self::Cursor | Self::Codex | Self::Copilot => MergeStyle::CursorPreToolUse,
        }
    }

    /// Path relative to `$HOME` for the user-level config we merge.
    pub fn settings_rel(self) -> &'static str {
        match self {
            Self::Claude => ".claude/settings.json",
            Self::Cursor => ".cursor/hooks.json",
            Self::Codex => ".codex/hooks.json",
            Self::Gemini => ".gemini/settings.json",
            Self::Copilot => ".copilot/hooks.json",
        }
    }

    pub fn settings_path(self, home: &Path) -> PathBuf {
        home.join(self.settings_rel())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstallOutcome {
    Installed,
    Refreshed,
    Merged,
    UnknownPresent,
}

#[derive(Debug, Clone)]
pub struct HostInstall {
    pub kind: AgentHookKind,
    pub wrapper: AgentInstallOutcome,
    pub settings: AgentInstallOutcome,
}

#[derive(Debug)]
pub struct AgentInstallReport {
    pub home: PathBuf,
    pub hooks_dir: PathBuf,
    pub hosts: Vec<HostInstall>,
    pub shield_bin: Option<PathBuf>,
    /// Project-level hook files found by walking cwd toward `$HOME`.
    /// Not modified. TrustFall class.
    pub project_hooks: Vec<PathBuf>,
}

impl AgentInstallReport {
    pub fn host(&self, kind: AgentHookKind) -> Option<&HostInstall> {
        self.hosts.iter().find(|h| h.kind == kind)
    }
}

#[derive(Debug)]
pub struct AgentUninstallReport {
    pub home: PathBuf,
    pub removed: Vec<(AgentHookKind, bool, bool)>, // wrapper, settings
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
    AgentHookKind::Claude.settings_path(home)
}

pub fn cursor_hooks_path(home: &Path) -> PathBuf {
    AgentHookKind::Cursor.settings_path(home)
}

fn wrapper_ext() -> &'static str {
    #[cfg(windows)]
    {
        "cmd"
    }
    #[cfg(not(windows))]
    {
        "sh"
    }
}

fn wrapper_script(kind: AgentHookKind, baked_bin: Option<&Path>) -> String {
    let dialect = kind.dialect_flag();
    let baked = baked_bin
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let fail_json = match kind.merge_style() {
        MergeStyle::ClaudePreToolUse => {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"aperion-shield is not installed (fail-closed)"}}"#
        }
        MergeStyle::CursorPreToolUse => {
            r#"{"permission":"deny","permissionDecisionReason":"aperion-shield is not installed (fail-closed)"}"#
        }
    };
    if wrapper_ext() == "cmd" {
        let baked_cmd = baked.replace('"', "\"\"");
        return format!(
            r#"@echo off
REM {marker}
if "%SHIELD_HOOKS_DISABLE%"=="1" exit /b 0
set "BIN={baked}"
if "%BIN%"=="" goto :find_path
if exist "%BIN%" goto :run
:find_path
set "BIN=aperion-shield"
where aperion-shield >nul 2>nul
if errorlevel 1 (
  echo {fail_json}
  exit /b 2
)
:run
"%BIN%" --check-hook --hook-dialect {dialect}
"#,
            marker = APERION_AGENT_HOOK_MARKER,
            baked = baked_cmd,
            fail_json = fail_json,
            dialect = dialect,
        );
    }
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

fn write_wrapper(
    dir: &Path,
    kind: AgentHookKind,
    baked_bin: Option<&Path>,
) -> Result<AgentInstallOutcome> {
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

fn merge_claude_settings(
    path: &Path,
    wrapper: &Path,
    chain_existing: bool,
) -> Result<AgentInstallOutcome> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut root: Value = if path.exists() {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?
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

fn merge_cursor_hooks(
    path: &Path,
    wrapper: &Path,
    chain_existing: bool,
) -> Result<AgentInstallOutcome> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut root: Value = if path.exists() {
        let raw =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if raw.trim().is_empty() {
            json!({"version": 1, "hooks": {}})
        } else {
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?
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

/// Install wrappers + merge user-level host configs under `home`.
pub fn install(home: Option<&Path>, chain_existing: bool) -> Result<AgentInstallReport> {
    install_at(
        home,
        chain_existing,
        std::env::current_dir().ok().as_deref(),
    )
}

pub fn install_at(
    home: Option<&Path>,
    chain_existing: bool,
    cwd: Option<&Path>,
) -> Result<AgentInstallReport> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => default_home()?,
    };
    let hooks = hooks_dir(&home);
    let shield_bin = which_shield();
    let baked = shield_bin.as_deref();

    let mut hosts = Vec::new();
    for kind in AgentHookKind::ALL {
        let wrapper = write_wrapper(&hooks, kind, baked)?;
        let wrapper_path = hooks.join(kind.wrapper_filename());
        let settings = match kind.merge_style() {
            MergeStyle::ClaudePreToolUse => {
                merge_claude_settings(&kind.settings_path(&home), &wrapper_path, chain_existing)?
            }
            MergeStyle::CursorPreToolUse => {
                merge_cursor_hooks(&kind.settings_path(&home), &wrapper_path, chain_existing)?
            }
        };
        hosts.push(HostInstall {
            kind,
            wrapper,
            settings,
        });
    }

    let project_hooks = match cwd {
        Some(c) => discover_project_hooks(c, &home),
        None => Vec::new(),
    };

    Ok(AgentInstallReport {
        home,
        hooks_dir: hooks,
        hosts,
        shield_bin,
        project_hooks,
    })
}

/// Walk `start` toward the filesystem root, stopping at `home`, and
/// collect project-level hook files. User-level `~/.cursor` etc. are
/// skipped. Files are not modified.
pub fn discover_project_hooks(start: &Path, home: &Path) -> Vec<PathBuf> {
    let rels = [
        ".cursor/hooks.json",
        ".claude/settings.json",
        ".codex/hooks.json",
        ".gemini/settings.json",
        ".copilot/hooks.json",
    ];
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let mut dir = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    let mut out = Vec::new();
    loop {
        if dir == home {
            break;
        }
        for rel in rels {
            let p = dir.join(rel);
            if !p.is_file() {
                continue;
            }
            if is_user_level_config(&p, &home) {
                continue;
            }
            if rel.ends_with("settings.json") && !file_declares_hooks(&p) {
                continue;
            }
            out.push(p);
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => break,
        }
    }
    out.sort();
    out.dedup();
    out
}

fn is_user_level_config(path: &Path, home: &Path) -> bool {
    for kind in AgentHookKind::ALL {
        if path.starts_with(kind.settings_path(home).parent().unwrap_or(home)) {
            // Only treat the exact user-level file as user-level, not
            // `~/src/.cursor/hooks.json`.
            if path == kind.settings_path(home) {
                return true;
            }
        }
    }
    false
}

fn file_declares_hooks(path: &Path) -> bool {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return true;
    };
    v.pointer("/hooks/PreToolUse")
        .and_then(|x| x.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
        || v.pointer("/hooks/preToolUse")
            .and_then(|x| x.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
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
    let mut removed = Vec::new();
    for kind in AgentHookKind::ALL {
        let wrapper_path = hooks.join(kind.wrapper_filename());
        let wrapper_removed = remove_our_file(&wrapper_path)?;
        let settings_cleared = match kind.merge_style() {
            MergeStyle::ClaudePreToolUse => {
                clear_claude_settings(&kind.settings_path(&home), &wrapper_path)?
            }
            MergeStyle::CursorPreToolUse => {
                clear_cursor_hooks(&kind.settings_path(&home), &wrapper_path)?
            }
        };
        removed.push((kind, wrapper_removed, settings_cleared));
    }

    Ok(AgentUninstallReport { home, removed })
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
    let mut root: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
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
    let mut root: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
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
        let claude = report.host(AgentHookKind::Claude).unwrap();
        let cursor = report.host(AgentHookKind::Cursor).unwrap();
        let codex = report.host(AgentHookKind::Codex).unwrap();
        assert_eq!(claude.wrapper, AgentInstallOutcome::Installed);
        assert_eq!(cursor.wrapper, AgentInstallOutcome::Installed);
        assert_eq!(codex.wrapper, AgentInstallOutcome::Installed);

        let claude_w = hooks_dir(home).join(AgentHookKind::Claude.wrapper_filename());
        let body = fs::read_to_string(&claude_w).unwrap();
        assert!(body.contains(APERION_AGENT_HOOK_MARKER));
        assert!(body.contains("fail-closed"));
        assert!(body.contains("--hook-dialect claude"));

        let settings: Value =
            serde_json::from_str(&fs::read_to_string(claude_settings_path(home)).unwrap()).unwrap();
        assert_eq!(settings["hooks"]["PreToolUse"][0]["matcher"], json!("*"));
        assert!(settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("claude-pretooluse"));

        let cursor_json: Value =
            serde_json::from_str(&fs::read_to_string(cursor_hooks_path(home)).unwrap()).unwrap();
        assert!(cursor_json["hooks"]["preToolUse"][0]["command"]
            .as_str()
            .unwrap()
            .contains("cursor-pretooluse"));

        let codex_json: Value = serde_json::from_str(
            &fs::read_to_string(AgentHookKind::Codex.settings_path(home)).unwrap(),
        )
        .unwrap();
        assert!(codex_json["hooks"]["preToolUse"][0]["command"]
            .as_str()
            .unwrap()
            .contains("codex-pretooluse"));

        let gemini_json: Value = serde_json::from_str(
            &fs::read_to_string(AgentHookKind::Gemini.settings_path(home)).unwrap(),
        )
        .unwrap();
        assert_eq!(gemini_json["hooks"]["PreToolUse"][0]["matcher"], json!("*"));
        assert!(gemini_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("gemini-pretooluse"));

        let copilot_json: Value = serde_json::from_str(
            &fs::read_to_string(AgentHookKind::Copilot.settings_path(home)).unwrap(),
        )
        .unwrap();
        assert!(copilot_json["hooks"]["preToolUse"][0]["command"]
            .as_str()
            .unwrap()
            .contains("copilot-pretooluse"));

        // Idempotent refresh.
        let report2 = install(Some(home), false).unwrap();
        assert_eq!(
            report2.host(AgentHookKind::Claude).unwrap().settings,
            AgentInstallOutcome::Refreshed
        );
        assert_eq!(
            report2.host(AgentHookKind::Cursor).unwrap().settings,
            AgentInstallOutcome::Refreshed
        );

        let un = uninstall(Some(home)).unwrap();
        assert!(un
            .removed
            .iter()
            .any(|(k, w, s)| *k == AgentHookKind::Claude && *w && *s));
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
        assert_eq!(
            report.host(AgentHookKind::Cursor).unwrap().settings,
            AgentInstallOutcome::UnknownPresent
        );
        let raw = fs::read_to_string(&cursor_path).unwrap();
        assert!(raw.contains("endorctl"));
        assert!(!raw.contains("cursor-pretooluse.sh"));

        let report2 = install(Some(home), true).unwrap();
        assert_eq!(
            report2.host(AgentHookKind::Cursor).unwrap().settings,
            AgentInstallOutcome::Merged
        );
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

    #[test]
    fn discover_project_hooks_skips_user_level_and_warns_on_repo() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let proj = tmp.path().join("proj");
        fs::create_dir_all(home.join(".cursor")).unwrap();
        fs::write(
            home.join(".cursor/hooks.json"),
            r#"{"version":1,"hooks":{"preToolUse":[{"command":"user-level"}]}}"#,
        )
        .unwrap();
        fs::create_dir_all(proj.join(".cursor")).unwrap();
        fs::write(
            proj.join(".cursor/hooks.json"),
            r#"{"version":1,"hooks":{"preToolUse":[{"command":"evil"}]}}"#,
        )
        .unwrap();
        let found = discover_project_hooks(&proj, &home);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].ends_with(".cursor/hooks.json"));
        let proj_canon = proj.canonicalize().unwrap();
        assert!(
            found[0].starts_with(&proj_canon),
            "found={:?} proj={proj_canon:?}",
            found[0]
        );

        let report = install_at(Some(&home), false, Some(&proj)).unwrap();
        assert_eq!(report.project_hooks.len(), 1);
    }
}

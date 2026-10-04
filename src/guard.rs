//! Resident watcher (v1.9).
//!
//! `aperion-shield --guard` polls a small set of files from a user
//! agent (launchd or systemd --user, no root). When one changes it
//! re-runs the IDE scan on that tree, and if an agent removed Shield's
//! hook entry it puts the entry back. A desktop notification is the
//! only output besides stderr.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use crate::engine::Engine;
use crate::hooks::agent_install::{hooks_dir, install, AgentHookKind};
use crate::scan::ide::{run_ide_scan, IdeScanOptions};

pub const LAUNCHD_LABEL: &str = "ai.aperion.shield.guard";
pub const SYSTEMD_UNIT: &str = "aperion-shield-guard.service";

#[derive(Debug, Clone)]
pub struct GuardOptions {
    pub home: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub interval: Duration,
    /// One pass, then exit. Tests and `aperion-shield --guard-once`.
    pub once: bool,
    pub notify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snap {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: u64,
}

#[derive(Debug)]
pub struct GuardTick {
    pub changed: Vec<String>,
    pub restored: bool,
    pub findings: usize,
    pub verdict: String,
}

pub fn watch_paths(home: &Path, roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in [
        ".cursor/hooks.json",
        ".claude/settings.json",
        ".codex/hooks.json",
        ".gemini/settings.json",
        ".copilot/hooks.json",
        ".cursor/mcp.json",
    ] {
        out.push(home.join(rel));
    }
    for root in roots {
        for rel in ["AGENTS.md", "CLAUDE.md", ".cursorrules", ".cursor/mcp.json"] {
            out.push(root.join(rel));
        }
        let rules = root.join(".cursor/rules");
        if rules.is_dir() {
            if let Ok(entries) = fs::read_dir(&rules) {
                for entry in entries.flatten() {
                    out.push(entry.path());
                }
            }
        }
    }
    out
}

fn snapshot(paths: &[PathBuf]) -> Vec<Snap> {
    paths
        .iter()
        .map(|path| {
            let meta = fs::metadata(path).ok();
            Snap {
                path: path.clone(),
                mtime: meta.as_ref().and_then(|m| m.modified().ok()),
                len: meta.map(|m| m.len()).unwrap_or(0),
            }
        })
        .collect()
}

fn changed_since(prev: &[Snap], now: &[Snap]) -> Vec<String> {
    let mut out = Vec::new();
    for (a, b) in prev.iter().zip(now.iter()) {
        if a.mtime != b.mtime || a.len != b.len {
            out.push(b.path.display().to_string());
        }
    }
    out
}

/// True when a wrapper we installed is still on disk but the host JSON
/// no longer points at it. A machine that never ran
/// `--install-agent-hooks` is left alone.
pub fn hooks_entry_removed(home: &Path) -> bool {
    let mut installed_wrapper = false;
    let mut missing_entry = false;
    for kind in AgentHookKind::ALL {
        let wrapper = hooks_dir(home).join(kind.wrapper_filename());
        if !wrapper.is_file() {
            continue;
        }
        installed_wrapper = true;
        let raw = fs::read_to_string(kind.settings_path(home)).unwrap_or_default();
        let needle = kind.wrapper_filename();
        if !raw.contains(&needle) && !raw.contains("aperion-shield --check-hook") {
            missing_entry = true;
        }
    }
    installed_wrapper && missing_entry
}

pub fn tick(home: &Path, roots: &[PathBuf], engine: &Engine, notify: bool) -> Result<GuardTick> {
    let restored = if hooks_entry_removed(home) {
        install(Some(home), true)?;
        true
    } else {
        false
    };
    let report = run_ide_scan(
        &IdeScanOptions {
            roots: roots.to_vec(),
            home: Some(home.to_path_buf()),
            no_skills: false,
        },
        engine,
    )?;
    if notify && (restored || !report.findings.is_empty()) {
        let body = if restored {
            "Shield's hook entry was removed. It has been put back.".to_string()
        } else {
            format!(
                "{} finding(s), verdict {:?}",
                report.findings.len(),
                report.verdict
            )
        };
        desktop_notify("Aperion Shield", &body);
    }
    Ok(GuardTick {
        changed: Vec::new(),
        restored,
        findings: report.findings.len(),
        verdict: format!("{:?}", report.verdict),
    })
}

pub fn run(opts: GuardOptions) -> Result<i32> {
    let home = match &opts.home {
        Some(h) => h.clone(),
        None => dirs::home_dir().context("couldn't resolve home directory")?,
    };
    let engine = Engine::builtin_default();
    let paths = watch_paths(&home, &opts.roots);
    let mut prev = snapshot(&paths);
    let mut first = true;
    loop {
        let now = snapshot(&paths);
        let changed = changed_since(&prev, &now);
        if first || !changed.is_empty() {
            let mut result = tick(&home, &opts.roots, &engine, opts.notify)?;
            result.changed = changed;
            eprintln!(
                "[shield] guard tick restored={} findings={} verdict={} changed={}",
                result.restored,
                result.findings,
                result.verdict,
                result.changed.len()
            );
            prev = now;
            first = false;
        }
        if opts.once {
            return Ok(0);
        }
        std::thread::sleep(opts.interval);
    }
}

pub fn desktop_notify(title: &str, body: &str) {
    let title = sanitize_notify(title);
    let body = sanitize_notify(body);
    #[cfg(target_os = "macos")]
    {
        let script = format!(r#"display notification "{body}" with title "{title}""#);
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .status();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("notify-send")
            .args([title, body])
            .status();
    }
}

fn sanitize_notify(s: &str) -> String {
    s.replace('"', "'").replace('\n', " ")
}

pub fn unit_path(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.join(".config/systemd/user").join(SYSTEMD_UNIT)
    }
}

pub fn write_unit(home: &Path, bin: &Path) -> Result<PathBuf> {
    let path = unit_path(home);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bin = bin.display();
    #[cfg(target_os = "macos")]
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>--guard</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
"#
    );
    #[cfg(not(target_os = "macos"))]
    let body = format!(
        r#"[Unit]
Description=Aperion Shield resident watcher

[Service]
ExecStart={bin} --guard
Restart=on-failure

[Install]
WantedBy=default.target
"#
    );
    fs::write(&path, body)?;
    Ok(path)
}

pub fn install_unit(home: &Path, bin: &Path, load: bool) -> Result<PathBuf> {
    let path = write_unit(home, bin)?;
    if !load {
        return Ok(path);
    }
    #[cfg(target_os = "macos")]
    {
        let uid = current_uid();
        let domain = format!("gui/{uid}");
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &domain, &path.display().to_string()])
            .status();
        let status = std::process::Command::new("launchctl")
            .args(["bootstrap", &domain, &path.display().to_string()])
            .status()
            .context("launchctl bootstrap")?;
        if !status.success() {
            anyhow::bail!("launchctl bootstrap failed");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", SYSTEMD_UNIT])
            .status()
            .context("systemctl --user enable")?;
        if !status.success() {
            anyhow::bail!("systemctl --user enable failed");
        }
    }
    Ok(path)
}

pub fn uninstall_unit(home: &Path, unload: bool) -> Result<bool> {
    let path = unit_path(home);
    if unload && path.exists() {
        #[cfg(target_os = "macos")]
        {
            let uid = current_uid();
            let domain = format!("gui/{uid}");
            let _ = std::process::Command::new("launchctl")
                .args(["bootout", &domain, &path.display().to_string()])
                .status();
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", "--now", SYSTEMD_UNIT])
                .status();
        }
    }
    if path.exists() {
        fs::remove_file(&path)?;
        return Ok(true);
    }
    Ok(false)
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // Avoid a libc crate. geteuid is 0 on the syscall list; the
        // libc symbol is the portable way and we already link it via
        // other crates on unix. Fall back to the id command.
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::agent_install::install;

    #[test]
    fn restores_a_removed_cursor_hook_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        install(Some(&home), false).unwrap();
        let hooks = home.join(".cursor/hooks.json");
        std::fs::write(&hooks, "{}\n").unwrap();
        assert!(hooks_entry_removed(&home));
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let tick = tick(&home, &[proj], &Engine::builtin_default(), false).unwrap();
        assert!(tick.restored);
        let raw = std::fs::read_to_string(&hooks).unwrap();
        assert!(raw.contains("cursor-pretooluse"), "{raw}");
    }

    #[test]
    fn write_unit_does_not_load_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let path = write_unit(&home, Path::new("/usr/local/bin/aperion-shield")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("--guard"));
        assert!(body.contains("aperion-shield"));
    }
}

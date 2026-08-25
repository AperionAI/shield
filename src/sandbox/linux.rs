//! Linux Landlock backend.
//!
//! Applied in a helper process (`--internal-sandbox-exec`) then `exec`'d
//! into the upstream. Landlock syscalls are not async-signal-safe, so we
//! cannot use `Command::pre_exec`.

use anyhow::{anyhow, Context, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use serde::{Deserialize, Serialize};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::paths::{fs_grants, FsGrant};
use super::{SandboxConfig, SandboxLevel};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecSpec {
    pub level: String,
    pub allow_paths: Vec<PathBuf>,
    pub allow_network: bool,
    pub home: Option<PathBuf>,
}

impl From<&SandboxConfig> for ExecSpec {
    fn from(cfg: &SandboxConfig) -> Self {
        Self {
            level: match cfg.level {
                SandboxLevel::Secrets => "secrets".into(),
                SandboxLevel::Strict => "strict".into(),
                SandboxLevel::Off => "off".into(),
            },
            allow_paths: cfg.allow_paths.clone(),
            allow_network: cfg.allow_network,
            home: cfg.home.clone(),
        }
    }
}

impl ExecSpec {
    fn into_config(self) -> Result<SandboxConfig> {
        Ok(SandboxConfig {
            level: SandboxLevel::parse(&self.level)?,
            allow_paths: self.allow_paths,
            allow_network: self.allow_network,
            home: self.home,
        })
    }
}

pub fn apply(cfg: &SandboxConfig) -> Result<RulesetStatus> {
    let abi = ABI::V4;
    let all = AccessFs::from_all(abi);
    let read_exec = AccessFs::from_read(abi);

    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all)?;

    if cfg.level == SandboxLevel::Strict && !cfg.allow_network {
        // ABI V4 / Linux 6.7+: handled TCP rights with no NetPort
        // allow-rules means bind/connect are denied. HardRequirement so
        // `strict` cannot silently run with a network-capable kernel
        // that simply doesn't implement Landlock net yet.
        builder = builder
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)?;
        builder = builder.set_compatibility(CompatLevel::BestEffort);
    }

    let mut ruleset = builder.create()?;
    for FsGrant { path, writable } in fs_grants(cfg) {
        if !path.exists() {
            continue;
        }
        let access = if writable { all } else { read_exec };
        ruleset = ruleset.add_rules(path_beneath_rules(&[path], access))?;
    }

    let status = ruleset.restrict_self().context("landlock_restrict_self")?;
    Ok(status.ruleset)
}

/// Restrict the current process, then exec `cmd`. Never returns on success.
pub fn exec_sandboxed(spec_json: &str, cmd: &[String]) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("--internal-sandbox-exec requires a command after --");
    }
    let spec: ExecSpec =
        serde_json::from_str(spec_json).context("parsing --internal-sandbox-exec JSON")?;
    let cfg = spec.into_config()?;
    if cfg.level == SandboxLevel::Off {
        return exec_now(cmd);
    }

    match apply(&cfg) {
        Ok(RulesetStatus::NotEnforced) => {
            if cfg.level == SandboxLevel::Strict {
                anyhow::bail!(
                    "--sandbox strict requested but Landlock is not available \
                     on this kernel; refusing to run unconfined"
                );
            }
            log::warn!("[shield] Landlock not enforced on this kernel -- upstream runs UNCONFINED");
        }
        Ok(_) => {}
        Err(e) => {
            if cfg.level == SandboxLevel::Strict {
                return Err(e).context("--sandbox strict: Landlock apply failed");
            }
            log::warn!(
                "[shield] Landlock apply failed ({e}); --sandbox secrets degrades to unconfined"
            );
        }
    }
    exec_now(cmd)
}

fn exec_now(cmd: &[String]) -> Result<()> {
    let mut c = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        c.args(&cmd[1..]);
    }
    let err = c.exec();
    Err(anyhow!("exec {}: {err}", cmd[0]))
}

//! v1.0: upstream process confinement.
//!
//! Shield already owns the upstream MCP server's process lifecycle
//! (we spawn it), which makes the spawn point the natural seam for
//! OS-level confinement. Protocol filtering (the engine) and process
//! confinement (this module) are complementary layers: the engine
//! stops malicious *messages*, the sandbox limits what the server
//! *process* can touch outside the protocol entirely.
//!
//! Platform support:
//!   - macOS: Seatbelt via `sandbox-exec -p <profile>`. Deprecated by
//!     Apple for third-party use but stable, universally present, and
//!     still what Bazel/Chromium-class tooling uses for exactly this
//!     job. No daemon, no privileges required.
//!   - other platforms: graceful degrade -- warn loudly and run
//!     unconfined (`SandboxLevel::Off` semantics) unless the user
//!     passed `--sandbox strict`, in which case refusing to start is
//!     the only honest behaviour.
//!
//! Levels:
//!   - `off`     -- current pre-v1.0 behaviour, no confinement.
//!   - `secrets` -- allow-by-default, deny read/write of credential
//!     material: ~/.ssh, ~/.aws, ~/.gnupg, cloud CLI configs, kube
//!     config, ~/.netrc, Docker creds. Low breakage: an MCP server
//!     that legitimately needs one of these (e.g. a git server doing
//!     SSH pushes) is exactly the server you want to consciously
//!     exempt via `--sandbox-allow <path>`.
//!   - `strict`  -- everything `secrets` does, PLUS deny-by-default
//!     writes (working directory, /tmp, and the user cache dirs only)
//!     and no network unless `--sandbox-allow-network`. Reads stay
//!     broadly allowed (minus credential paths): a read deny-default
//!     profile needs an exact enumeration of the dyld/runtime surface,
//!     which differs per macOS release and breaks silently -- write +
//!     network confinement is the part that holds reliably, and it is
//!     the part that stops exfiltration and tampering.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxLevel {
    Off,
    Secrets,
    Strict,
}

impl SandboxLevel {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "secrets" => Ok(Self::Secrets),
            "strict" => Ok(Self::Strict),
            other => anyhow::bail!(
                "unknown --sandbox level '{}' (expected off | secrets | strict)",
                other
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub level: SandboxLevel,
    /// Paths exempted from the `secrets` deny-list, or granted
    /// read+write in `strict` mode (beyond the defaults).
    pub allow_paths: Vec<PathBuf>,
    /// `strict` only: permit outbound/inbound network. `secrets`
    /// leaves the network alone -- most MCP servers need it.
    pub allow_network: bool,
    /// Home directory override (tests use a temp dir).
    pub home: Option<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            level: SandboxLevel::Off,
            allow_paths: Vec::new(),
            allow_network: false,
            home: None,
        }
    }
}

/// How the upstream actually ended up confined, for the startup log
/// and the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confinement {
    None,
    Seatbelt { level: SandboxLevel },
}

impl std::fmt::Display for Confinement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confinement::None => write!(f, "unconfined"),
            Confinement::Seatbelt { level } => {
                write!(f, "seatbelt:{}", match level {
                    SandboxLevel::Off => "off",
                    SandboxLevel::Secrets => "secrets",
                    SandboxLevel::Strict => "strict",
                })
            }
        }
    }
}

/// Credential material the `secrets` level denies. Relative to $HOME.
const SECRET_SUBPATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".gcloud",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".netrc",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials.toml",
];

fn sbpl_escape(p: &Path) -> String {
    // SBPL string literals are double-quoted; escape embedded quotes
    // and backslashes. Paths with either are vanishingly rare but a
    // sandbox profile is the wrong place to be sloppy.
    p.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
}

fn home_dir(cfg: &SandboxConfig) -> PathBuf {
    cfg.home
        .clone()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Render the Seatbelt (SBPL) profile for a config. Public for tests.
///
/// SBPL evaluation: the LAST matching rule wins, so both levels open
/// with `(allow default)` and stack targeted denies (and re-allows)
/// after it. A `(deny default)` read profile was prototyped and
/// rejected: the dyld/runtime read surface differs per macOS release
/// and fails as SIGABRT before the upstream's main() -- unshippable.
pub fn seatbelt_profile(cfg: &SandboxConfig) -> String {
    let home = home_dir(cfg);
    let mut out = String::from("(version 1)\n(allow default)\n");

    // Both levels: deny credential material (minus exemptions).
    for sub in SECRET_SUBPATHS {
        let p = home.join(sub);
        if cfg.allow_paths.iter().any(|a| p.starts_with(a) || a.starts_with(&p)) {
            continue;
        }
        out.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{}\"))\n",
            sbpl_escape(&p)
        ));
    }

    if cfg.level == SandboxLevel::Strict {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        // Deny-by-default WRITES, then re-open the working directory,
        // scratch/cache space, and terminal devices.
        out.push_str("(deny file-write*)\n");
        out.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            sbpl_escape(&cwd)
        ));
        for p in ["/tmp", "/private/tmp", "/private/var/tmp", "/private/var/folders", "/dev/null", "/dev/tty"] {
            let kind = if p.starts_with("/dev/") { "literal" } else { "subpath" };
            out.push_str(&format!("(allow file-write* ({} \"{}\"))\n", kind, p));
        }
        for p in &cfg.allow_paths {
            out.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                sbpl_escape(p)
            ));
        }
        if !cfg.allow_network {
            out.push_str("(deny network*)\n");
        }
    }
    out
}

/// Wrap `cmd` in the platform sandbox launcher per `cfg`.
///
/// Returns the command to exec plus the achieved confinement. Degrades
/// gracefully (warn + unconfined) when the platform has no sandbox,
/// EXCEPT for `strict`, where silently running unconfined would be a
/// lie -- there we refuse.
pub fn wrap_command(cmd: &[String], cfg: &SandboxConfig) -> anyhow::Result<(Vec<String>, Confinement)> {
    if cfg.level == SandboxLevel::Off || cmd.is_empty() {
        return Ok((cmd.to_vec(), Confinement::None));
    }

    #[cfg(target_os = "macos")]
    {
        let profile = seatbelt_profile(cfg);
        let mut wrapped = vec![
            "/usr/bin/sandbox-exec".to_string(),
            "-p".to_string(),
            profile,
        ];
        wrapped.extend(cmd.iter().cloned());
        Ok((wrapped, Confinement::Seatbelt { level: cfg.level }))
    }

    #[cfg(not(target_os = "macos"))]
    {
        match cfg.level {
            SandboxLevel::Strict => anyhow::bail!(
                "--sandbox strict is not supported on this platform yet \
                 (macOS Seatbelt only); refusing to run unconfined when \
                 strict confinement was requested"
            ),
            _ => {
                log::warn!(
                    "[shield] --sandbox {:?} requested but no sandbox backend \
                     exists on this platform yet -- upstream runs UNCONFINED",
                    cfg.level
                );
                Ok((cmd.to_vec(), Confinement::None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(level: SandboxLevel) -> SandboxConfig {
        SandboxConfig {
            level,
            allow_paths: vec![],
            allow_network: false,
            home: Some(PathBuf::from("/Users/testhome")),
        }
    }

    #[test]
    fn off_is_passthrough() {
        let cmd = vec!["echo".to_string(), "hi".to_string()];
        let (wrapped, conf) = wrap_command(&cmd, &cfg(SandboxLevel::Off)).unwrap();
        assert_eq!(wrapped, cmd);
        assert_eq!(conf, Confinement::None);
    }

    #[test]
    fn secrets_profile_denies_credential_dirs() {
        let p = seatbelt_profile(&cfg(SandboxLevel::Secrets));
        assert!(p.starts_with("(version 1)\n(allow default)\n"));
        assert!(p.contains("(deny file-read* file-write* (subpath \"/Users/testhome/.ssh\"))"));
        assert!(p.contains("/Users/testhome/.aws"));
        assert!(p.contains("/Users/testhome/.kube"));
    }

    #[test]
    fn secrets_allow_path_exempts_dir() {
        let mut c = cfg(SandboxLevel::Secrets);
        c.allow_paths.push(PathBuf::from("/Users/testhome/.ssh"));
        let p = seatbelt_profile(&c);
        assert!(!p.contains("/Users/testhome/.ssh"));
        assert!(p.contains("/Users/testhome/.aws")); // others still denied
    }

    #[test]
    fn strict_profile_confines_writes_and_network() {
        let p = seatbelt_profile(&cfg(SandboxLevel::Strict));
        assert!(p.contains("(deny file-write*)"));
        assert!(p.contains("(deny network*)"));
        assert!(p.contains("/Users/testhome/.ssh")); // credential denies kept
        let mut c = cfg(SandboxLevel::Strict);
        c.allow_network = true;
        assert!(!seatbelt_profile(&c).contains("(deny network*)"));
    }

    #[test]
    fn profile_escapes_quotes_in_paths() {
        let mut c = cfg(SandboxLevel::Secrets);
        c.home = Some(PathBuf::from("/Users/we\"ird"));
        let p = seatbelt_profile(&c);
        assert!(p.contains("/Users/we\\\"ird/.ssh"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_wraps_with_sandbox_exec() {
        let cmd = vec!["/bin/echo".to_string(), "hi".to_string()];
        let (wrapped, conf) = wrap_command(&cmd, &cfg(SandboxLevel::Secrets)).unwrap();
        assert_eq!(wrapped[0], "/usr/bin/sandbox-exec");
        assert_eq!(wrapped[1], "-p");
        assert!(wrapped[2].contains("(deny file-read*"));
        assert_eq!(&wrapped[3..], &cmd[..]);
        assert_eq!(conf, Confinement::Seatbelt { level: SandboxLevel::Secrets });
    }
}

//! Shared sandbox path policy (Seatbelt + Landlock).
//!
//! Landlock is allow-list only: it cannot deny `~/.ssh` while granting
//! `$HOME`. We grant each non-secret child of `$HOME` instead, and recurse
//! through directories that *contain* a secret (so `~/.config` is not
//! granted wholesale when `~/.config/gcloud` is secret).

use std::path::{Path, PathBuf};

use super::{SandboxConfig, SandboxLevel};

/// Credential material both backends keep out of the upstream's reach,
/// relative to `$HOME`.
pub const SECRET_SUBPATHS: &[&str] = &[
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

/// Runtime prefixes a typical MCP server (node, python, npx) needs to
/// read and exec. Missing paths are skipped at apply time.
pub const SYSTEM_PREFIXES: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc", "/dev", "/proc", "/sys", "/run",
    "/nix", "/home",
];

pub fn home_dir(cfg: &SandboxConfig) -> PathBuf {
    cfg.home
        .clone()
        .or_else(dirs::home_dir)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn secret_paths(home: &Path) -> Vec<PathBuf> {
    SECRET_SUBPATHS.iter().map(|s| home.join(s)).collect()
}

fn is_secret_or_under_secret(path: &Path, secrets: &[PathBuf]) -> bool {
    secrets.iter().any(|s| path == s || path.starts_with(s))
}

fn is_ancestor_of_secret(path: &Path, secrets: &[PathBuf]) -> bool {
    secrets.iter().any(|s| s.starts_with(path) && s != path)
}

/// `$HOME` children granted under `secrets` (and as read-only under
/// `strict` we do not use this — strict only grants cwd/tmp/allow).
pub fn home_allows_except_secrets(home: &Path, extra_allow: &[PathBuf]) -> Vec<PathBuf> {
    let secrets: Vec<PathBuf> = secret_paths(home)
        .into_iter()
        .filter(|s| {
            !extra_allow
                .iter()
                .any(|a| s.starts_with(a) || a.starts_with(s))
        })
        .collect();
    walk_allows(home, &secrets)
}

fn walk_allows(dir: &Path, secrets: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if is_secret_or_under_secret(&p, secrets) {
            continue;
        }
        if p.is_dir() && is_ancestor_of_secret(&p, secrets) {
            out.extend(walk_allows(&p, secrets));
            continue;
        }
        out.push(p);
    }
    out
}

/// One Landlock PathBeneath grant: `(path, writable)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsGrant {
    pub path: PathBuf,
    pub writable: bool,
}

/// Build the allow-list Landlock will install. Writable grants are cwd,
/// `/tmp`, `/var/tmp`, `--sandbox-allow`, and (secrets only) non-secret
/// `$HOME` children. System prefixes are read+exec only in `strict`.
pub fn fs_grants(cfg: &SandboxConfig) -> Vec<FsGrant> {
    let home = home_dir(cfg);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut grants = Vec::new();

    let mut push = |path: PathBuf, writable: bool| {
        if grants.iter().any(|g: &FsGrant| g.path == path) {
            return;
        }
        grants.push(FsGrant { path, writable });
    };

    push(cwd, true);
    for p in ["/tmp", "/var/tmp", "/dev/null", "/dev/tty"] {
        push(PathBuf::from(p), true);
    }
    for p in &cfg.allow_paths {
        push(p.clone(), true);
    }

    let system_writable = cfg.level != SandboxLevel::Strict;
    for p in SYSTEM_PREFIXES {
        // `/home` as a prefix would re-open every user's secrets. Skip
        // it; `$HOME` children are granted explicitly below.
        if *p == "/home" {
            continue;
        }
        push(PathBuf::from(p), system_writable);
    }

    if cfg.level == SandboxLevel::Secrets {
        for p in home_allows_except_secrets(&home, &cfg.allow_paths) {
            push(p, true);
        }
    }

    grants
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn home_walk_skips_ssh_and_nested_gcloud() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join(".config/gcloud")).unwrap();
        fs::create_dir_all(home.join(".config/gh")).unwrap();
        fs::write(home.join("notes.txt"), "ok").unwrap();
        fs::create_dir_all(home.join("src")).unwrap();

        let allows = home_allows_except_secrets(home, &[]);
        let names: Vec<String> = allows
            .iter()
            .map(|p| p.strip_prefix(home).unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(names.iter().any(|n| n == "notes.txt"), "{names:?}");
        assert!(names.iter().any(|n| n == "src"), "{names:?}");
        assert!(names.iter().any(|n| n == ".config/gh"), "{names:?}");
        assert!(
            !names.iter().any(|n| n == ".ssh" || n.starts_with(".ssh/")),
            "{names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n == ".config/gcloud" || n.starts_with(".config/gcloud/")),
            "{names:?}"
        );
        // Must not grant `.config` wholesale or gcloud leaks.
        assert!(!names.iter().any(|n| n == ".config"), "{names:?}");
    }

    #[test]
    fn sandbox_allow_reopens_ssh() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        let ssh = home.join(".ssh");
        let allows = home_allows_except_secrets(home, std::slice::from_ref(&ssh));
        assert!(
            allows.iter().any(|p| p == &ssh),
            "exempted .ssh must show up in the HOME allow-list: {allows:?}"
        );
    }
}

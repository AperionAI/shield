//! Install / uninstall the `pre-commit` and `pre-push` hooks for a git
//! repository.
//!
//! Design points:
//!
//!  * **Idempotent.** Running `--install-hooks` twice is a no-op the
//!    second time. We detect our own hook by matching the marker line
//!    from `templates::APERION_HOOK_MARKER`, not by comparing whole-file
//!    checksums -- this lets us refresh the hook body across Shield
//!    versions without losing the ability to recognise our own.
//!
//!  * **Husky-compatible coexistence.** If a non-Aperion hook is
//!    already present, we don't clobber it. Instead we:
//!      1. Preserve the existing file as `<hook>.aperion-backup`.
//!      2. Write our hook in its place.
//!      3. Have *our* hook `exec` the backup at the end so the chain
//!         survives. Husky / pre-commit / lefthook users keep their
//!         existing pipeline; Shield slots in as the first link.
//!    This is opt-in via `--chain-existing`; without it we refuse to
//!    overwrite an unrecognised hook and tell the user how to chain
//!    manually. Failing closed is safer than guessing.
//!
//!  * **Resolves the .git dir correctly** for worktrees and submodules
//!    by parsing `git rev-parse --git-path hooks`. We do NOT assume
//!    `.git/hooks/` exists at the repo root -- that's wrong for
//!    worktrees and breaks loudly when used inside `git worktree add`.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::hooks::templates::{
    pre_commit_script, pre_push_script, APERION_HOOK_MARKER,
};

/// Outcome categories the installer reports back to the CLI. Kept
/// granular so the `--install-hooks` log line is informative without
/// requiring callers to re-inspect the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookInstallOutcome {
    /// Wrote a fresh hook (no prior file existed).
    Installed,
    /// Re-wrote our own hook from a prior version (idempotent refresh).
    Refreshed,
    /// A non-Aperion hook is in place; we did NOT overwrite. Caller
    /// must re-invoke with `chain_existing = true` to proceed.
    UnknownHookPresent,
    /// `chain_existing = true` was supplied and we moved the prior
    /// hook aside + installed ours, chaining via `exec` at the end.
    Chained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    PreCommit,
    PrePush,
}

impl HookKind {
    /// Filename inside the git hooks directory.
    pub fn filename(self) -> &'static str {
        match self {
            HookKind::PreCommit => "pre-commit",
            HookKind::PrePush => "pre-push",
        }
    }

    /// Render the hook body. Kept here so callers don't have to import
    /// the templates module directly.
    pub fn body(self) -> String {
        match self {
            HookKind::PreCommit => pre_commit_script(),
            HookKind::PrePush => pre_push_script(),
        }
    }
}

/// Result of an install / uninstall pass over both hook files.
#[derive(Debug)]
pub struct InstallReport {
    pub hooks_dir: PathBuf,
    pub pre_commit: HookInstallOutcome,
    pub pre_push: HookInstallOutcome,
}

/// Result of an uninstall pass.
#[derive(Debug)]
pub struct UninstallReport {
    pub hooks_dir: PathBuf,
    /// `true` if the hook existed and was ours (removed).
    /// `false` if no hook existed (nothing to do).
    /// Errors if the hook existed but wasn't ours.
    pub pre_commit_removed: bool,
    pub pre_push_removed: bool,
    /// `true` if a `<hook>.aperion-backup` chain partner was restored
    /// in place of the removed hook (i.e. user had a prior hook chained
    /// by `--chain-existing`; we put it back).
    pub pre_commit_chain_restored: bool,
    pub pre_push_chain_restored: bool,
}

/// Resolve the absolute path to `<repo>/.git/hooks` for the repo whose
/// working tree contains `start`. Honors worktrees and submodules by
/// shelling out to `git rev-parse --git-path hooks`. Returns an error
/// when `start` is not inside a git repository.
pub fn resolve_hooks_dir(start: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks"])
        .current_dir(start)
        .output()
        .with_context(|| {
            format!(
                "couldn't invoke `git rev-parse --git-path hooks` at {} (is git installed?)",
                start.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "git rev-parse failed at {}: {}",
            start.display(),
            stderr.trim()
        ));
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(anyhow!(
            "git rev-parse returned an empty hooks path -- is {} inside a git repo?",
            start.display()
        ));
    }
    // `git rev-parse --git-path hooks` may return a relative path
    // (relative to `start`). Canonicalise so the rest of the installer
    // can treat it as absolute without surprises.
    let candidate = PathBuf::from(&raw);
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        start.join(candidate)
    };
    Ok(absolute)
}

/// Top-level install entrypoint. Writes / refreshes the pre-commit and
/// pre-push hooks for the repository at `start`.
pub fn install(start: &Path, chain_existing: bool) -> Result<InstallReport> {
    let hooks_dir = resolve_hooks_dir(start)?;
    fs::create_dir_all(&hooks_dir).with_context(|| {
        format!("couldn't create hooks dir {}", hooks_dir.display())
    })?;

    let pre_commit = install_one(&hooks_dir, HookKind::PreCommit, chain_existing)?;
    let pre_push = install_one(&hooks_dir, HookKind::PrePush, chain_existing)?;

    Ok(InstallReport {
        hooks_dir,
        pre_commit,
        pre_push,
    })
}

/// Top-level uninstall entrypoint. Removes Aperion-installed hooks
/// (and restores any chained-aside originals).
pub fn uninstall(start: &Path) -> Result<UninstallReport> {
    let hooks_dir = resolve_hooks_dir(start)?;

    let (pre_commit_removed, pre_commit_chain_restored) =
        uninstall_one(&hooks_dir, HookKind::PreCommit)?;
    let (pre_push_removed, pre_push_chain_restored) =
        uninstall_one(&hooks_dir, HookKind::PrePush)?;

    Ok(UninstallReport {
        hooks_dir,
        pre_commit_removed,
        pre_push_removed,
        pre_commit_chain_restored,
        pre_push_chain_restored,
    })
}

fn install_one(
    hooks_dir: &Path,
    kind: HookKind,
    chain_existing: bool,
) -> Result<HookInstallOutcome> {
    let path = hooks_dir.join(kind.filename());
    let body = kind.body();

    if !path.exists() {
        write_hook(&path, &body)?;
        return Ok(HookInstallOutcome::Installed);
    }

    // Hook file exists -- is it ours?
    let existing = fs::read_to_string(&path).with_context(|| {
        format!("couldn't read existing hook at {}", path.display())
    })?;
    if existing.contains(APERION_HOOK_MARKER) {
        // Our own hook; refresh body in case the template evolved.
        write_hook(&path, &body)?;
        return Ok(HookInstallOutcome::Refreshed);
    }

    if !chain_existing {
        return Ok(HookInstallOutcome::UnknownHookPresent);
    }

    // Chain mode: move existing aside, write ours, append a chain tail
    // that execs the moved-aside hook. Preserves husky / pre-commit /
    // lefthook setups.
    let backup_path = path.with_extension("aperion-backup");
    fs::rename(&path, &backup_path).with_context(|| {
        format!(
            "couldn't move existing hook out of the way: {} -> {}",
            path.display(),
            backup_path.display()
        )
    })?;
    let chained_body = format!(
        "{}\n# --- chained existing hook (preserved by --install-hooks --chain-existing) ---\nexec {} \"$@\"\n",
        body.trim_end(),
        backup_path.display(),
    );
    write_hook(&path, &chained_body)?;
    Ok(HookInstallOutcome::Chained)
}

fn uninstall_one(hooks_dir: &Path, kind: HookKind) -> Result<(bool, bool)> {
    let path = hooks_dir.join(kind.filename());
    if !path.exists() {
        return Ok((false, false));
    }
    let body = fs::read_to_string(&path).with_context(|| {
        format!("couldn't read hook at {}", path.display())
    })?;
    if !body.contains(APERION_HOOK_MARKER) {
        return Err(anyhow!(
            "refusing to remove {}: it isn't an Aperion-installed hook (no marker line found). \
             Inspect and delete manually if you intend to.",
            path.display()
        ));
    }
    fs::remove_file(&path)
        .with_context(|| format!("couldn't remove hook {}", path.display()))?;

    // Was a chain partner left aside? Restore it.
    let backup_path = path.with_extension("aperion-backup");
    if backup_path.exists() {
        fs::rename(&backup_path, &path).with_context(|| {
            format!(
                "couldn't restore chained-aside hook: {} -> {}",
                backup_path.display(),
                path.display()
            )
        })?;
        return Ok((true, true));
    }

    Ok((true, false))
}

fn write_hook(path: &Path, body: &str) -> Result<()> {
    fs::write(path, body)
        .with_context(|| format!("couldn't write hook to {}", path.display()))?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_git_repo() -> TempDir {
        let tmp = TempDir::new().expect("create tempdir");
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .expect("run git init");
        assert!(status.success(), "git init failed");
        // git complains about missing user.* in some CI environments;
        // set them locally so subsequent commits in tests succeed.
        for (key, val) in [("user.email", "test@aperion.ai"), ("user.name", "Test")] {
            let s = Command::new("git")
                .args(["config", "--local", key, val])
                .current_dir(tmp.path())
                .status()
                .expect("git config");
            assert!(s.success());
        }
        tmp
    }

    #[test]
    fn install_fresh_writes_both_hooks() {
        let tmp = init_git_repo();
        let report = install(tmp.path(), false).expect("install");
        assert_eq!(report.pre_commit, HookInstallOutcome::Installed);
        assert_eq!(report.pre_push, HookInstallOutcome::Installed);
        assert!(report.hooks_dir.join("pre-commit").exists());
        assert!(report.hooks_dir.join("pre-push").exists());
        let body = fs::read_to_string(report.hooks_dir.join("pre-commit")).unwrap();
        assert!(body.contains(APERION_HOOK_MARKER));
    }

    #[test]
    fn install_twice_refreshes_idempotently() {
        let tmp = init_git_repo();
        install(tmp.path(), false).unwrap();
        let second = install(tmp.path(), false).expect("re-install");
        assert_eq!(second.pre_commit, HookInstallOutcome::Refreshed);
        assert_eq!(second.pre_push, HookInstallOutcome::Refreshed);
    }

    #[test]
    fn install_refuses_to_clobber_unknown_hook() {
        let tmp = init_git_repo();
        let hooks_dir = resolve_hooks_dir(tmp.path()).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(
            hooks_dir.join("pre-commit"),
            "#!/bin/sh\n# user's husky hook\nexec husky pre-commit\n",
        )
        .unwrap();

        let report = install(tmp.path(), false).expect("install");
        assert_eq!(report.pre_commit, HookInstallOutcome::UnknownHookPresent);

        // and the original was NOT modified
        let body = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        assert!(body.contains("husky pre-commit"));
    }

    #[test]
    fn install_chains_existing_hook_when_asked() {
        let tmp = init_git_repo();
        let hooks_dir = resolve_hooks_dir(tmp.path()).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(
            hooks_dir.join("pre-commit"),
            "#!/bin/sh\n# user's husky hook\nexec husky pre-commit\n",
        )
        .unwrap();

        let report = install(tmp.path(), true).expect("install with chain");
        assert_eq!(report.pre_commit, HookInstallOutcome::Chained);
        // backup exists
        assert!(hooks_dir.join("pre-commit.aperion-backup").exists());
        // new hook exists and chains to backup
        let body = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        assert!(body.contains(APERION_HOOK_MARKER));
        assert!(body.contains("pre-commit.aperion-backup"));
    }

    #[test]
    fn uninstall_removes_our_hook_and_restores_chain() {
        let tmp = init_git_repo();
        let hooks_dir = resolve_hooks_dir(tmp.path()).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(
            hooks_dir.join("pre-commit"),
            "#!/bin/sh\n# user's husky hook\nexec husky pre-commit\n",
        )
        .unwrap();
        install(tmp.path(), true).unwrap();

        let report = uninstall(tmp.path()).expect("uninstall");
        assert!(report.pre_commit_removed);
        assert!(report.pre_commit_chain_restored);

        // backup is gone, original husky hook is back in place
        assert!(!hooks_dir.join("pre-commit.aperion-backup").exists());
        let body = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        assert!(body.contains("husky pre-commit"));
        assert!(!body.contains(APERION_HOOK_MARKER));
    }

    #[test]
    fn uninstall_refuses_to_remove_foreign_hook() {
        let tmp = init_git_repo();
        let hooks_dir = resolve_hooks_dir(tmp.path()).unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(
            hooks_dir.join("pre-commit"),
            "#!/bin/sh\n# not ours\nexit 0\n",
        )
        .unwrap();
        let err = uninstall(tmp.path()).expect_err("should refuse");
        let msg = format!("{:?}", err);
        assert!(msg.contains("isn't an Aperion-installed hook"));
        // original still there, intact
        let body = fs::read_to_string(hooks_dir.join("pre-commit")).unwrap();
        assert!(body.contains("# not ours"));
    }
}

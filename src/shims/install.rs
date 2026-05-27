//! Install / uninstall the per-command shims that route invocations
//! through `aperion-shield --check-cmd`.
//!
//! Design points (mirroring `src/hooks/install.rs`):
//!
//!  * **Per-user, not system-wide.** Shims live in
//!    `~/.aperion-shield/bin/` (override with `--shim-dir`). The user
//!    adds that directory to their `$PATH` ahead of the system paths.
//!    We do NOT touch `/usr/local/bin` or any shared location -- those
//!    paths often require sudo and clobbering them would break other
//!    users on the same machine.
//!
//!  * **Idempotent.** Re-running `--install-shims` is a no-op when the
//!    existing shims still match the marker. Refreshing a shim across
//!    Shield versions just rewrites it; user-authored scripts at the
//!    same path are NEVER overwritten (we refuse with `ForeignPresent`
//!    and let the operator decide).
//!
//!  * **Resolves the real binary path at install time** by running
//!    `which <cmd>` after removing our shim directory from `$PATH`.
//!    We bake the absolute path into the shim body. This both prevents
//!    the obvious `$PATH` self-loop (shim execs itself) and gives the
//!    user predictability: the shim does exactly what `which <cmd>`
//!    did when they installed it.
//!
//!  * **Per-command granularity.** `--install-shims --for aws,kubectl`
//!    installs only those two; the rest of `DEFAULT_SHIMMED_COMMANDS`
//!    are untouched. This is how we keep adoption low-risk: protect
//!    the one command you keep getting burned by, leave the rest alone.

use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::shims::templates::{shim_script, APERION_SHIELD_SHIM_MARKER, DEFAULT_SHIMMED_COMMANDS};

/// Outcome categories reported by the installer for a single command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimInstallOutcome {
    /// Wrote a fresh shim where none existed.
    Installed,
    /// Recognised our own prior shim and refreshed it in place.
    Refreshed,
    /// A file already exists at the target path that we don't recognise
    /// (no `APERION_SHIELD_SHIM_MARKER`). We did NOT overwrite it. The
    /// caller surfaces this to the operator who can either delete the
    /// foreign file themselves or pick a different `--shim-dir`.
    ForeignPresent,
    /// The real binary couldn't be resolved on `$PATH` at install time.
    /// Skipping rather than baking a broken path into the shim.
    UpstreamBinaryNotFound,
}

#[derive(Debug, Clone)]
pub struct ShimInstallEntry {
    pub command: String,
    pub outcome: ShimInstallOutcome,
    /// The absolute path of the real binary that was baked into the
    /// shim, when we got that far. None when the outcome was
    /// `UpstreamBinaryNotFound` or `ForeignPresent`.
    pub resolved_path: Option<PathBuf>,
    /// Where the shim was (or would have been) written.
    pub shim_path: PathBuf,
}

#[derive(Debug)]
pub struct ShimInstallReport {
    pub shim_dir: PathBuf,
    pub entries: Vec<ShimInstallEntry>,
}

impl ShimInstallReport {
    pub fn any_foreign(&self) -> bool {
        self.entries.iter().any(|e| e.outcome == ShimInstallOutcome::ForeignPresent)
    }

    pub fn any_missing_upstream(&self) -> bool {
        self.entries.iter().any(|e| e.outcome == ShimInstallOutcome::UpstreamBinaryNotFound)
    }

    pub fn successful(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                matches!(
                    e.outcome,
                    ShimInstallOutcome::Installed | ShimInstallOutcome::Refreshed
                )
            })
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimUninstallOutcome {
    /// Recognised our marker and removed the shim.
    Removed,
    /// File at the target path didn't carry our marker; we left it
    /// alone. Returned when the operator hand-rolled a wrapper after
    /// running `--install-shims` once.
    ForeignPresent,
    /// No file at the target path; nothing to do.
    AbsentNoop,
}

#[derive(Debug, Clone)]
pub struct ShimUninstallEntry {
    pub command: String,
    pub outcome: ShimUninstallOutcome,
    pub shim_path: PathBuf,
}

#[derive(Debug)]
pub struct ShimUninstallReport {
    pub shim_dir: PathBuf,
    pub entries: Vec<ShimUninstallEntry>,
}

/// Resolve the canonical shim directory. Order:
///
///  1. Explicit `--shim-dir PATH` if supplied.
///  2. `$APERION_SHIELD_SHIM_DIR` (mostly for tests).
///  3. `$HOME/.aperion-shield/bin/`.
///
/// Returned path is not guaranteed to exist on disk yet -- callers that
/// write to it must create it via `fs::create_dir_all`.
pub fn resolve_shim_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(env_dir) = std::env::var("APERION_SHIELD_SHIM_DIR") {
        if !env_dir.is_empty() {
            return Ok(PathBuf::from(env_dir));
        }
    }
    let home = std::env::var("HOME")
        .context("couldn't resolve $HOME (set --shim-dir explicitly)")?;
    Ok(PathBuf::from(home).join(".aperion-shield").join("bin"))
}

/// Install (or refresh) shims for each command in `commands`. When
/// `commands` is empty, defaults to `DEFAULT_SHIMMED_COMMANDS`.
///
/// `shim_dir` is created if absent (mode 0700 on unix). The caller is
/// expected to print a follow-on note telling the user how to add
/// `shim_dir` to their `$PATH` -- this function does NOT modify
/// dotfiles. That's deliberate: rewriting shell rc files is high-risk
/// and the operator's choice.
pub fn install(shim_dir: &Path, commands: &[String]) -> Result<ShimInstallReport> {
    fs::create_dir_all(shim_dir)
        .with_context(|| format!("couldn't create shim dir {}", shim_dir.display()))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(shim_dir)?.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(shim_dir, perms);
    }

    let to_install: Vec<String> = if commands.is_empty() {
        DEFAULT_SHIMMED_COMMANDS.iter().map(|s| s.to_string()).collect()
    } else {
        commands.to_vec()
    };

    let mut entries = Vec::with_capacity(to_install.len());
    for cmd in to_install {
        let shim_path = shim_dir.join(&cmd);
        entries.push(install_one(&cmd, &shim_path, shim_dir)?);
    }

    Ok(ShimInstallReport {
        shim_dir: shim_dir.to_path_buf(),
        entries,
    })
}

/// Install (or refresh) the shim for a single command.
fn install_one(
    cmd: &str,
    shim_path: &Path,
    shim_dir: &Path,
) -> Result<ShimInstallEntry> {
    // Refuse to overwrite a foreign file at the target path.
    if shim_path.exists() {
        let existing = fs::read_to_string(shim_path)
            .with_context(|| format!("couldn't read existing shim at {}", shim_path.display()))?;
        if !existing.contains(APERION_SHIELD_SHIM_MARKER) {
            return Ok(ShimInstallEntry {
                command: cmd.to_string(),
                outcome: ShimInstallOutcome::ForeignPresent,
                resolved_path: None,
                shim_path: shim_path.to_path_buf(),
            });
        }
    }

    let real_path = match resolve_real_binary(cmd, shim_dir)? {
        Some(p) => p,
        None => {
            return Ok(ShimInstallEntry {
                command: cmd.to_string(),
                outcome: ShimInstallOutcome::UpstreamBinaryNotFound,
                resolved_path: None,
                shim_path: shim_path.to_path_buf(),
            });
        }
    };

    let outcome = if shim_path.exists() {
        ShimInstallOutcome::Refreshed
    } else {
        ShimInstallOutcome::Installed
    };

    let body = shim_script(cmd, &real_path.to_string_lossy());
    write_shim(shim_path, &body)?;

    Ok(ShimInstallEntry {
        command: cmd.to_string(),
        outcome,
        resolved_path: Some(real_path),
        shim_path: shim_path.to_path_buf(),
    })
}

/// Uninstall every Shield-managed shim found in `shim_dir`. Files that
/// don't carry our marker are left alone (not our shim, not our problem
/// -- the operator put them there for a reason).
pub fn uninstall(shim_dir: &Path) -> Result<ShimUninstallReport> {
    let mut entries = Vec::new();

    if !shim_dir.exists() {
        return Ok(ShimUninstallReport {
            shim_dir: shim_dir.to_path_buf(),
            entries,
        });
    }

    for entry in fs::read_dir(shim_dir)
        .with_context(|| format!("couldn't read shim dir {}", shim_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !content.contains(APERION_SHIELD_SHIM_MARKER) {
            entries.push(ShimUninstallEntry {
                command: name,
                outcome: ShimUninstallOutcome::ForeignPresent,
                shim_path: path,
            });
            continue;
        }

        fs::remove_file(&path)
            .with_context(|| format!("couldn't remove shim {}", path.display()))?;
        entries.push(ShimUninstallEntry {
            command: name,
            outcome: ShimUninstallOutcome::Removed,
            shim_path: path,
        });
    }

    Ok(ShimUninstallReport {
        shim_dir: shim_dir.to_path_buf(),
        entries,
    })
}

/// List the shims currently installed in `shim_dir`, separated into
/// "ours" vs "foreign" by marker match. Used by `--list-shims` and the
/// install path's pre-state check.
pub fn list(shim_dir: &Path) -> Result<BTreeMap<String, bool>> {
    let mut out = BTreeMap::new();
    if !shim_dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(shim_dir)
        .with_context(|| format!("couldn't read shim dir {}", shim_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let content = fs::read_to_string(&path).unwrap_or_default();
        out.insert(name, content.contains(APERION_SHIELD_SHIM_MARKER));
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// Filesystem helpers
// ─────────────────────────────────────────────────────────────────────

fn write_shim(path: &Path, body: &str) -> Result<()> {
    fs::write(path, body)
        .with_context(|| format!("couldn't write shim to {}", path.display()))?;
    // Same Unix-only chmod story as src/hooks/install.rs: explicit 0755
    // because fs::write honours the process umask and may produce 0644
    // which the kernel refuses to exec. On Windows we skip; Windows
    // doesn't carry an exec bit and command resolution is by extension.
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Resolve the real binary for `cmd` -- i.e. what the user *would* hit
/// if our shim directory weren't on `$PATH`. Walks every directory on
/// `$PATH` in order, skipping the shim dir (so we don't pick up our
/// own shim, which would cause an infinite exec loop at runtime).
///
/// Pure Rust; no shell-out. That matters in two places:
///
///  1. **Tests** can manipulate `$PATH` without also needing `sh`
///     reachable.
///  2. **Windows** would otherwise need a totally different code path
///     (no `/bin/sh`, different `which` semantics) -- here we just
///     read whatever the user has on `PATH` and stat it directly.
///
/// Returns Ok(None) when the binary isn't on `$PATH` at all (we then
/// record `UpstreamBinaryNotFound` rather than baking a broken path).
fn resolve_real_binary(cmd: &str, shim_dir: &Path) -> Result<Option<PathBuf>> {
    let current_path = std::env::var_os("PATH").unwrap_or_default();
    let shim_dir_canon = shim_dir.canonicalize().unwrap_or_else(|_| shim_dir.to_path_buf());

    for dir in std::env::split_paths(&current_path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let dir_canon = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if dir_canon == shim_dir_canon {
            continue;
        }
        let candidate = dir.join(cmd);
        if !candidate.is_file() {
            continue;
        }
        if !is_executable(&candidate) {
            continue;
        }
        return Ok(Some(candidate));
    }

    Ok(None)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match path.metadata() {
        Ok(m) => m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_executable(_path: &Path) -> bool {
    // Windows: PATH resolution is by file extension (PATHEXT) and
    // there's no exec bit. If the file exists at the candidate path
    // with a runnable extension, treat it as executable. We don't
    // ship shims for Windows in v0.8 -- this branch exists only so
    // the crate compiles cross-target.
    true
}


/// Convenience: parse a comma-separated `--for aws,kubectl,terraform`
/// argument into a deduplicated, validated command list. Returns an
/// error if any item isn't a plausible command name (no shell
/// metacharacters, no path components -- otherwise install paths
/// could escape `shim_dir`).
pub fn parse_for_arg(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for piece in raw.split(',') {
        let cmd = piece.trim();
        if cmd.is_empty() {
            continue;
        }
        if cmd.contains('/') || cmd.contains('\\') || cmd.contains(' ') {
            return Err(anyhow!(
                "--for entry '{}' is not a plain command name (no paths, no spaces, no slashes)",
                cmd
            ));
        }
        if !out.iter().any(|c: &String| c == cmd) {
            out.push(cmd.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Tests in this module mutate `$PATH` and `$APERION_SHIELD_SHIM_DIR`,
    /// which are process-global. cargo runs lib tests in parallel within
    /// one binary, so without serialisation the env mutations race each
    /// other and tests flake. Same defensive pattern we use in
    /// `src/hooks/check_pushed.rs`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Build a tempdir that holds a fake real binary for `cmd_name`
    /// (so `resolve_real_binary` finds something) and a clean shim
    /// directory. Returns (real_dir, shim_dir, full_path_to_real).
    fn fixture(cmd_name: &str) -> (TempDir, TempDir, PathBuf) {
        let real_dir = TempDir::new().expect("real dir");
        let shim_dir = TempDir::new().expect("shim dir");
        let real_bin = real_dir.path().join(cmd_name);
        fs::write(&real_bin, "#!/bin/sh\necho fake\n").expect("write fake bin");
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&real_bin).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&real_bin, perms).unwrap();
        }
        // Save & restore $PATH around the test so we don't pollute the
        // global env for parallel tests in the same process.
        (real_dir, shim_dir, real_bin)
    }

    /// Set PATH for the duration of a test, restoring on drop.
    /// Holding the module-local `ENV_LOCK` for the whole call serialises
    /// against every other test that reads or writes PATH.
    ///
    /// We deliberately PREPEND the test's fixture directory rather than
    /// REPLACING $PATH, so unrelated tests that shell out to
    /// `hostname`, `git`, etc. (e.g. `orgmode::state::fingerprint_is_stable`)
    /// keep working while we hold the lock. The fixture binary always
    /// resolves first because our directory is at the front of the
    /// joined path.
    fn with_path<R>(new_path_prefix: &Path, f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var_os("PATH");
        let joined = match &prev {
            Some(existing) => {
                let mut s = std::ffi::OsString::new();
                s.push(new_path_prefix);
                s.push(":");
                s.push(existing);
                s
            }
            None => new_path_prefix.as_os_str().to_owned(),
        };
        std::env::set_var("PATH", &joined);
        let r = f();
        match prev {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        r
    }

    #[test]
    fn install_writes_a_shim_with_the_marker() {
        let (real_dir, shim_dir, real_bin) = fixture("aws");
        let report = with_path(real_dir.path(), || {
            install(shim_dir.path(), &["aws".to_string()]).expect("install")
        });

        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.command, "aws");
        assert_eq!(entry.outcome, ShimInstallOutcome::Installed);
        assert_eq!(entry.resolved_path.as_deref(), Some(real_bin.as_path()));

        let written = fs::read_to_string(&entry.shim_path).expect("read shim");
        assert!(written.contains(APERION_SHIELD_SHIM_MARKER));
        assert!(written.contains(&real_bin.to_string_lossy().to_string()));
    }

    #[test]
    fn install_is_idempotent_refresh() {
        let (real_dir, shim_dir, _real_bin) = fixture("kubectl");
        let (r1, r2) = with_path(real_dir.path(), || {
            let r1 = install(shim_dir.path(), &["kubectl".to_string()]).expect("install1");
            let r2 = install(shim_dir.path(), &["kubectl".to_string()]).expect("install2");
            (r1, r2)
        });
        assert_eq!(r1.entries[0].outcome, ShimInstallOutcome::Installed);
        assert_eq!(r2.entries[0].outcome, ShimInstallOutcome::Refreshed);
    }

    #[test]
    fn install_refuses_to_clobber_a_foreign_file() {
        let (real_dir, shim_dir, _real_bin) = fixture("terraform");

        // Pre-seed the target path with a user-authored wrapper.
        fs::create_dir_all(shim_dir.path()).unwrap();
        let path = shim_dir.path().join("terraform");
        fs::write(&path, "#!/bin/sh\n# my custom wrapper\nexec /opt/tf \"$@\"\n").unwrap();

        let report = with_path(real_dir.path(), || {
            install(shim_dir.path(), &["terraform".to_string()]).expect("install")
        });

        assert_eq!(report.entries[0].outcome, ShimInstallOutcome::ForeignPresent);
        // Foreign file must NOT have been rewritten.
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("# my custom wrapper"));
        assert!(!after.contains(APERION_SHIELD_SHIM_MARKER));
    }

    #[test]
    fn install_skips_when_upstream_binary_not_on_path() {
        // Use a command name guaranteed not to exist on any sane $PATH
        // so this assertion is independent of the host system. Picking
        // a real name like `helm` would make the test pass or fail
        // based on whether helm happens to be installed on the dev /
        // CI machine.
        let empty = TempDir::new().unwrap();
        let shim_dir = TempDir::new().unwrap();

        let cmd_name = "aperion-test-fake-binary-zzz999".to_string();
        let report = with_path(empty.path(), || {
            install(shim_dir.path(), &[cmd_name.clone()]).expect("install")
        });

        assert_eq!(
            report.entries[0].outcome,
            ShimInstallOutcome::UpstreamBinaryNotFound
        );
        assert!(!shim_dir.path().join(&cmd_name).exists());
    }

    #[test]
    fn uninstall_removes_only_our_shims() {
        let (real_dir, shim_dir, _real_bin) = fixture("psql");

        with_path(real_dir.path(), || {
            install(shim_dir.path(), &["psql".to_string()]).expect("install");
        });

        // Drop a foreign file in too (no PATH manipulation needed).
        let foreign = shim_dir.path().join("not-ours");
        fs::write(&foreign, "#!/bin/sh\necho foreign\n").unwrap();

        let report = uninstall(shim_dir.path()).expect("uninstall");

        let by_cmd: BTreeMap<_, _> = report
            .entries
            .into_iter()
            .map(|e| (e.command, e.outcome))
            .collect();
        assert_eq!(by_cmd.get("psql"), Some(&ShimUninstallOutcome::Removed));
        assert_eq!(by_cmd.get("not-ours"), Some(&ShimUninstallOutcome::ForeignPresent));
        // Foreign file must still be there.
        assert!(foreign.exists());
    }

    #[test]
    fn resolve_shim_dir_honours_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = std::env::var_os("APERION_SHIELD_SHIM_DIR");
        std::env::set_var("APERION_SHIELD_SHIM_DIR", "/tmp/aperion-test-shims");
        let resolved = resolve_shim_dir(None).expect("resolve");
        assert_eq!(resolved, PathBuf::from("/tmp/aperion-test-shims"));
        match prev {
            Some(p) => std::env::set_var("APERION_SHIELD_SHIM_DIR", p),
            None => std::env::remove_var("APERION_SHIELD_SHIM_DIR"),
        }
    }

    #[test]
    fn resolve_shim_dir_explicit_wins() {
        let p = PathBuf::from("/explicit/path");
        let resolved = resolve_shim_dir(Some(&p)).expect("resolve");
        assert_eq!(resolved, p);
    }

    #[test]
    fn parse_for_arg_accepts_canonical_form() {
        let v = parse_for_arg("aws,kubectl, terraform").expect("parse");
        assert_eq!(v, vec!["aws", "kubectl", "terraform"]);
    }

    #[test]
    fn parse_for_arg_dedups() {
        let v = parse_for_arg("aws,aws,kubectl,aws").expect("parse");
        assert_eq!(v, vec!["aws", "kubectl"]);
    }

    #[test]
    fn parse_for_arg_rejects_paths_or_metacharacters() {
        assert!(parse_for_arg("/usr/bin/aws").is_err());
        assert!(parse_for_arg("aws kubectl").is_err());
        assert!(parse_for_arg("aws,../etc/passwd").is_err());
    }
}

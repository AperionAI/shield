//! Which `aperion-shield` path to write into hooks, managed settings,
//! Claude Desktop config and launchd units.
//!
//! A path under a cargo `target/debug` or `target/release` folder changes
//! on every rebuild. On macOS each rebuild is a new binary to the
//! keychain, so a hook pinned there asks for the login password on every
//! call. These writers use the installed copy instead.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

const BIN: &str = "aperion-shield";

/// Path to bake into config files.
///
/// `$APERION_SHIELD_BIN` wins when it names a file, so a build folder can
/// still be used on purpose. Otherwise a build-folder binary is swapped
/// for the first installed copy on `PATH` or in the usual install
/// folders, and Shield refuses when there isn't one.
pub fn stable_bin() -> Result<PathBuf> {
    let explicit = std::env::var_os("APERION_SHIELD_BIN").map(PathBuf::from);
    let exe = std::env::current_exe()?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let (bin, swapped) = pick(explicit, exe.clone(), &installed_candidates())?;
    if swapped {
        eprintln!(
            "[shield] {} is a build folder. Writing the installed copy instead: {}",
            exe.display(),
            bin.display()
        );
    }
    Ok(bin)
}

/// True for cargo build output (`target/debug`, `target/release`,
/// `target/<triple>/release`).
pub fn is_build_output(p: &Path) -> bool {
    let parts: Vec<&str> = p
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    parts.iter().enumerate().any(|(i, c)| {
        *c == "target"
            && parts[i + 1..]
                .iter()
                .any(|d| *d == "debug" || *d == "release")
    })
}

fn pick(
    explicit: Option<PathBuf>,
    exe: PathBuf,
    candidates: &[PathBuf],
) -> Result<(PathBuf, bool)> {
    if let Some(p) = explicit.filter(|p| p.is_file()) {
        return Ok((p, false));
    }
    if !is_build_output(&exe) {
        return Ok((exe, false));
    }
    candidates
        .iter()
        .find(|c| c.is_file() && !is_build_output(c))
        .map(|c| (c.clone(), true))
        .ok_or_else(|| {
            anyhow!(
                "{} is a build folder, and pinning hooks to it makes macOS ask for the keychain \
                 password after every rebuild. Install Shield (brew install \
                 AperionAI/tap/aperion-shield or cargo install aperion-shield) and run this again, or set APERION_SHIELD_BIN to \
                 this path to use it anyway.",
                exe.display()
            )
        })
}

fn installed_candidates() -> Vec<PathBuf> {
    let name = format!("{BIN}{}", std::env::consts::EXE_SUFFIX);
    let mut out: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).map(|d| d.join(&name)).collect())
        .unwrap_or_default();
    for dir in ["/opt/homebrew/bin", "/usr/local/bin"] {
        out.push(Path::new(dir).join(&name));
    }
    if let Some(home) = dirs::home_dir() {
        out.push(home.join(".cargo").join("bin").join(&name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, rel: &str) -> PathBuf {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"").unwrap();
        p
    }

    #[test]
    fn spots_cargo_build_folders() {
        assert!(is_build_output(Path::new(
            "/src/shield/target/debug/aperion-shield"
        )));
        assert!(is_build_output(Path::new(
            "/src/shield/target/release/aperion-shield"
        )));
        assert!(is_build_output(Path::new(
            "/src/shield/target/aarch64-apple-darwin/release/aperion-shield"
        )));
        assert!(!is_build_output(Path::new(
            "/opt/homebrew/bin/aperion-shield"
        )));
        assert!(!is_build_output(Path::new(
            "/Users/me/.cargo/bin/aperion-shield"
        )));
    }

    #[test]
    fn installed_binary_is_kept() {
        let t = tempfile::tempdir().unwrap();
        let exe = touch(t.path(), "bin/aperion-shield");
        assert_eq!(pick(None, exe.clone(), &[]).unwrap(), (exe, false));
    }

    #[test]
    fn build_binary_swaps_to_installed_copy() {
        let t = tempfile::tempdir().unwrap();
        let exe = touch(t.path(), "repo/target/debug/aperion-shield");
        let other_build = touch(t.path(), "repo2/target/release/aperion-shield");
        let installed = touch(t.path(), "brew/bin/aperion-shield");
        let missing = t.path().join("nope/aperion-shield");
        let (bin, swapped) = pick(None, exe, &[missing, other_build, installed.clone()]).unwrap();
        assert_eq!(bin, installed);
        assert!(swapped);
    }

    #[test]
    fn build_binary_without_install_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let exe = touch(t.path(), "repo/target/debug/aperion-shield");
        let err = pick(None, exe, &[]).unwrap_err().to_string();
        assert!(err.contains("APERION_SHIELD_BIN"), "{err}");
    }

    #[test]
    fn explicit_override_allows_a_build() {
        let t = tempfile::tempdir().unwrap();
        let exe = touch(t.path(), "repo/target/debug/aperion-shield");
        let (bin, swapped) = pick(Some(exe.clone()), exe.clone(), &[]).unwrap();
        assert_eq!(bin, exe);
        assert!(!swapped);
    }
}

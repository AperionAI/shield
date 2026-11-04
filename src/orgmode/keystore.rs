//! Secret storage for org-mode device secrets (signing key, vkey).
//!
//! macOS: Keychain. Windows: Credential Manager (DPAPI-backed). Linux and
//! `APERION_SHIELD_KEYSTORE=file`: a 0600 file under `<shield dir>/keys/`.

use anyhow::Context;

const SERVICE: &str = "ai.aperion.shield";

fn use_file() -> bool {
    std::env::var("APERION_SHIELD_KEYSTORE").map_or(!cfg!(any(target_os = "macos", target_os = "windows")), |v| {
        v.eq_ignore_ascii_case("file")
    })
}

fn file_path(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = super::state::shield_dir()?.join("keys");
    std::fs::create_dir_all(&dir).context("create keys dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir.join(name))
}

/// Human-readable location, for `--status`.
pub fn backend() -> &'static str {
    if use_file() {
        "file"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "Windows Credential Manager"
    }
}

pub fn put(name: &str, secret: &str) -> anyhow::Result<()> {
    if use_file() {
        return super::write_private(&file_path(name)?, secret.as_bytes());
    }
    os_put(name, secret)
}

pub fn get(name: &str) -> anyhow::Result<Option<String>> {
    if use_file() {
        let p = file_path(name)?;
        return match std::fs::read_to_string(&p) {
            Ok(s) => Ok(Some(s.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
        };
    }
    os_get(name)
}

pub fn delete(name: &str) -> anyhow::Result<()> {
    if use_file() {
        let p = file_path(name)?;
        if p.exists() {
            std::fs::remove_file(p)?;
        }
        return Ok(());
    }
    os_delete(name)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn entry(name: &str) -> anyhow::Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, name).context("open keystore entry")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn os_put(name: &str, secret: &str) -> anyhow::Result<()> {
    entry(name)?.set_password(secret).context("write keystore")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn os_get(name: &str) -> anyhow::Result<Option<String>> {
    match entry(name)?.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("read keystore"),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn os_delete(name: &str) -> anyhow::Result<()> {
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("delete keystore entry"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn os_put(name: &str, secret: &str) -> anyhow::Result<()> {
    super::write_private(&file_path(name)?, secret.as_bytes())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn os_get(name: &str) -> anyhow::Result<Option<String>> {
    Ok(std::fs::read_to_string(file_path(name)?).ok().map(|s| s.trim().to_string()))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn os_delete(name: &str) -> anyhow::Result<()> {
    let p = file_path(name)?;
    if p.exists() {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

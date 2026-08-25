//! Live Landlock integration tests (Linux only).
//!
//! Spawns the real `aperion-shield` helper (`--internal-sandbox-exec`)
//! so confinement is applied the same way the proxy wraps an upstream.

#![cfg(target_os = "linux")]

use aperion_shield::sandbox::linux::ExecSpec;
use aperion_shield::sandbox::{paths, wrap_command, SandboxConfig, SandboxLevel};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn run_wrapped(cfg: &SandboxConfig, argv: &[&str]) -> std::process::Output {
    let spec = serde_json::to_string(&ExecSpec::from(cfg)).expect("spec");
    let bin = env!("CARGO_BIN_EXE_aperion-shield");
    Command::new(bin)
        .arg("--internal-sandbox-exec")
        .arg(&spec)
        .arg("--")
        .args(argv)
        .output()
        .expect("spawn sandbox helper")
}

fn temp_home_with_secret() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let secret = ssh.join("id_ed25519");
    std::fs::write(&secret, "PRIVATE KEY MATERIAL").unwrap();
    let benign = home.path().join("notes.txt");
    std::fs::write(&benign, "ordinary file").unwrap();
    (home, secret, benign)
}

/// Why a secret read was not denied. `None` means Landlock blocked it.
#[derive(Debug)]
enum SecretRead {
    Blocked,
    NotEnforced,
    UnexpectedAllow { stderr: String },
}

fn probe_secret_read(home: &Path, secret: &Path) -> SecretRead {
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        allow_paths: vec![],
        allow_network: false,
        home: Some(home.to_path_buf()),
    };
    let denied = run_wrapped(&cfg, &["/bin/cat", secret.to_str().unwrap()]);
    if !denied.status.success() {
        return SecretRead::Blocked;
    }
    let stderr = String::from_utf8_lossy(&denied.stderr).into_owned();
    if stderr.contains("Landlock not enforced") || stderr.contains("Landlock apply failed") {
        SecretRead::NotEnforced
    } else {
        SecretRead::UnexpectedAllow { stderr }
    }
}

fn require_landlock(home: &Path, secret: &Path) -> bool {
    match probe_secret_read(home, secret) {
        SecretRead::Blocked => true,
        SecretRead::NotEnforced => {
            eprintln!("skipping: Landlock not enforced on this kernel");
            false
        }
        SecretRead::UnexpectedAllow { stderr } => {
            panic!("Landlock appeared to apply but ~/.ssh was still readable: {stderr}");
        }
    }
}

#[test]
fn secrets_level_blocks_ssh_key_but_allows_other_reads() {
    let (home, secret, benign) = temp_home_with_secret();
    if !require_landlock(home.path(), &secret) {
        return;
    }
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        allow_paths: vec![],
        allow_network: false,
        home: Some(home.path().to_path_buf()),
    };

    let denied = run_wrapped(&cfg, &["/bin/cat", secret.to_str().unwrap()]);
    assert!(
        !denied.status.success(),
        "reading ~/.ssh under `secrets` must fail, stderr={}",
        String::from_utf8_lossy(&denied.stderr)
    );

    let allowed = run_wrapped(&cfg, &["/bin/cat", benign.to_str().unwrap()]);
    assert!(
        allowed.status.success(),
        "non-credential reads must still work: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&allowed.stdout), "ordinary file");
}

#[test]
fn secrets_level_sandbox_allow_exempts_path() {
    let (home, secret, _benign) = temp_home_with_secret();
    if !require_landlock(home.path(), &secret) {
        return;
    }
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        allow_paths: vec![home.path().join(".ssh")],
        allow_network: false,
        home: Some(home.path().to_path_buf()),
    };
    let out = run_wrapped(&cfg, &["/bin/cat", secret.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "--sandbox-allow ~/.ssh must re-permit the read: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn wrap_argv_uses_helper() {
    let cmd = vec!["/bin/true".to_string()];
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        ..SandboxConfig::default()
    };
    let (wrapped, conf) = wrap_command(&cmd, &cfg).unwrap();
    assert_eq!(wrapped[1], "--internal-sandbox-exec");
    assert!(matches!(
        conf,
        aperion_shield::sandbox::Confinement::Landlock { .. }
    ));
    let _ = paths::SYSTEM_PREFIXES;
}

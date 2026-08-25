//! Live Seatbelt integration tests (macOS only).
//!
//! These do not mock anything: they render the same SBPL profiles the
//! proxy uses and run real processes under `/usr/bin/sandbox-exec`,
//! asserting that denied reads actually fail and allowed reads
//! actually succeed. On non-macOS targets the whole file compiles to
//! nothing.

#![cfg(target_os = "macos")]

use aperion_shield::sandbox::{seatbelt_profile, SandboxConfig, SandboxLevel};
use std::path::PathBuf;
use std::process::Command;

fn run_sandboxed(profile: &str, argv: &[&str]) -> std::process::Output {
    Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .args(argv)
        .output()
        .expect("sandbox-exec must exist on macOS")
}

fn temp_home_with_secret() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let secret = ssh.join("id_ed25519");
    std::fs::write(&secret, "PRIVATE KEY MATERIAL").unwrap();
    let benign = home.path().join("notes.txt");
    std::fs::write(&benign, "ordinary file").unwrap();
    // canonicalize: /var -> /private/var on macOS; Seatbelt matches on
    // the real path, so the profile must be built from it too.
    let secret = secret.canonicalize().unwrap();
    let benign = benign.canonicalize().unwrap();
    (home, secret, benign)
}

#[test]
fn secrets_level_blocks_ssh_key_but_allows_other_reads() {
    let (home, secret, benign) = temp_home_with_secret();
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        allow_paths: vec![],
        allow_network: false,
        home: Some(home.path().canonicalize().unwrap()),
    };
    let profile = seatbelt_profile(&cfg);

    let denied = run_sandboxed(&profile, &["/bin/cat", secret.to_str().unwrap()]);
    assert!(
        !denied.status.success(),
        "reading ~/.ssh under `secrets` must fail, got: {}",
        String::from_utf8_lossy(&denied.stdout)
    );

    let allowed = run_sandboxed(&profile, &["/bin/cat", benign.to_str().unwrap()]);
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
    let home_real = home.path().canonicalize().unwrap();
    let cfg = SandboxConfig {
        level: SandboxLevel::Secrets,
        allow_paths: vec![home_real.join(".ssh")],
        allow_network: false,
        home: Some(home_real),
    };
    let profile = seatbelt_profile(&cfg);
    let out = run_sandboxed(&profile, &["/bin/cat", secret.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "--sandbox-allow ~/.ssh must re-permit the read: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn strict_level_confines_writes_to_granted_prefixes() {
    let (home, secret, _benign) = temp_home_with_secret();
    let cfg = SandboxConfig {
        level: SandboxLevel::Strict,
        allow_paths: vec![],
        allow_network: false,
        home: Some(home.path().canonicalize().unwrap()),
    };
    let profile = seatbelt_profile(&cfg);

    // Credential reads stay denied in strict.
    let denied_read = run_sandboxed(&profile, &["/bin/cat", secret.to_str().unwrap()]);
    assert!(
        !denied_read.status.success(),
        "strict must deny credential reads"
    );

    // Write OUTSIDE cwd/tmp: the real $HOME is user-writable, so a
    // failure here can only come from the sandbox.
    let target = PathBuf::from(std::env::var("HOME").unwrap()).join(format!(
        ".aperion-shield-sandbox-test-{}",
        std::process::id()
    ));
    let denied_write = run_sandboxed(&profile, &["/usr/bin/touch", target.to_str().unwrap()]);
    let leaked = target.exists();
    let _ = std::fs::remove_file(&target);
    assert!(
        !denied_write.status.success() && !leaked,
        "strict must deny writes outside granted prefixes"
    );

    // Write INSIDE the working directory (cwd is the crate root at
    // profile-render time): allowed.
    let cwd_target = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("sandbox-test-{}", std::process::id()));
    let allowed = run_sandboxed(&profile, &["/usr/bin/touch", cwd_target.to_str().unwrap()]);
    let ok = cwd_target.exists();
    let _ = std::fs::remove_file(&cwd_target);
    assert!(
        allowed.status.success() && ok,
        "strict must allow writes in the working directory: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn strict_level_blocks_network_unless_allowed() {
    let base = SandboxConfig {
        level: SandboxLevel::Strict,
        allow_paths: vec![],
        allow_network: false,
        home: None,
    };
    // python3 lives under /usr/bin or /opt/homebrew -- both readable in
    // strict. A plain TCP connect to localhost must fail without
    // --sandbox-allow-network. We bind a listener so the failure mode
    // is the sandbox, not a connection refusal.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!(
        "import socket; socket.create_connection(('127.0.0.1', {port}), timeout=3); print('CONNECTED')"
    );

    let denied = run_sandboxed(
        &seatbelt_profile(&base),
        &["/usr/bin/python3", "-c", &script],
    );
    assert!(
        !denied.status.success(),
        "strict without --sandbox-allow-network must block sockets, got: {}",
        String::from_utf8_lossy(&denied.stdout)
    );

    let mut allow = base.clone();
    allow.allow_network = true;
    let allowed = run_sandboxed(
        &seatbelt_profile(&allow),
        &["/usr/bin/python3", "-c", &script],
    );
    assert!(
        allowed.status.success(),
        "--sandbox-allow-network must permit the connect: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

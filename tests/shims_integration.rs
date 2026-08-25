//! End-to-end tests for `--install-shims` and the resulting shim
//! wrappers.
//!
//! The interesting cases for this feature live at the boundary
//! between Rust install logic and the on-disk shell scripts that
//! actually intercept invocations. Unit tests in `src/shims/` cover
//! the Rust side; these tests exercise the script we generate by
//! running it through `/bin/sh` against a fake "real" binary and
//! asserting the right thing happens.
//!
//! Skipped on Windows because the shim scripts are POSIX `/bin/sh`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Locate the release binary built by `cargo test` so the shim's
/// `aperion-shield --check-cmd` line resolves to our actual code path.
fn aperion_shield_binary() -> PathBuf {
    let dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(dir).join("target/release/aperion-shield");
    assert!(
        path.exists(),
        "expected release binary at {} -- run `cargo build --release` before integration tests",
        path.display()
    );
    path
}

/// Create a tempdir holding a fake `aws` binary that echoes its argv
/// to stdout when invoked. The shim will exec this when allowed.
fn make_fake_real_dir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let real_aws = dir.path().join("aws");
    fs::write(
        &real_aws,
        "#!/bin/sh\necho \"real-aws-invoked\" \"$@\"\nexit 0\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&real_aws).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&real_aws, perms).unwrap();
    (dir, real_aws)
}

/// Run `aperion-shield --install-shims --for <cmd> --shim-dir <dir>` with
/// `PATH` set to a known directory so the resolver finds our fake real
/// binary, not the user's actual `aws`.
fn install_shim_for(cmd: &str, shim_dir: &Path, real_dir: &Path) -> std::process::Output {
    Command::new(aperion_shield_binary())
        .args([
            "--install-shims",
            "--for",
            cmd,
            "--shim-dir",
            shim_dir.to_str().unwrap(),
        ])
        .env("PATH", real_dir)
        .output()
        .expect("install-shims")
}

/// Run the shim itself by `/bin/sh <shim_path> <args...>`. We invoke
/// `/bin/sh` via its absolute path so the child can have a totally
/// restricted `$PATH` without losing access to the shell interpreter
/// itself. Inside the child, `$PATH` is set to include:
///
///  * the directory holding our `aperion-shield` release binary
///    (so the shim's `command -v aperion-shield` succeeds),
///  * the fake-real-binary dir (defence in depth -- the shim has the
///    absolute path baked in, but a debug-mode shim or a future
///    refactor might reach into PATH again), and
///  * `/bin` and `/usr/bin` (so the shim's `command -v` invocation
///    itself can find `command`, which on macOS is a shell builtin
///    and therefore doesn't need PATH, but on Linux some shells
///    resolve it as an external binary; we err on the side of
///    "match a real user's PATH").
fn run_shim(
    shim: &Path,
    real_dir: &Path,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> std::process::Output {
    let aperion = aperion_shield_binary();
    let aperion_dir = aperion.parent().unwrap();

    let path = format!(
        "{}:{}:/bin:/usr/bin",
        aperion_dir.display(),
        real_dir.display()
    );

    let mut cmd = Command::new("/bin/sh");
    cmd.arg(shim);
    cmd.args(args);
    cmd.env("PATH", &path);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("run shim")
}

#[test]
fn shim_passes_through_an_allowed_invocation() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(
        install.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );

    // `aws s3 ls` doesn't trip any rule -- should be allowed and the
    // real fake-aws should execute.
    let shim = shim_dir.path().join("aws");
    let out = run_shim(&shim, real.path(), &[], &["s3", "ls"]);
    assert!(
        out.status.success(),
        "shim exit failed: {}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("real-aws-invoked"),
        "real binary should have run; got stdout: {}",
        stdout
    );
}

#[test]
fn shim_blocks_a_destructive_invocation_and_does_not_run_the_real_binary() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(install.status.success());

    // The default shieldset gates `aws s3 rm --recursive` as
    // Approval-severity. From the shim path this surfaces as exit 2
    // (approvals can't prompt) and the real fake-aws must NOT run.
    let shim = shim_dir.path().join("aws");
    let out = run_shim(
        &shim,
        real.path(),
        &[],
        &["s3", "rm", "--recursive", "s3://prod-bucket"],
    );
    assert!(
        !out.status.success(),
        "shim should have refused; got success with stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("real-aws-invoked"),
        "real binary must NOT have been exec'd on a refused call; got stdout: {}",
        stdout
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("APPROVAL-REQUIRED") || stderr.contains("BLOCKED"),
        "expected refusal banner; got stderr: {}",
        stderr
    );
}

#[test]
fn shield_shims_disable_env_var_lets_a_blocked_call_through() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(install.status.success());

    let shim = shim_dir.path().join("aws");
    let out = run_shim(
        &shim,
        real.path(),
        &[("SHIELD_SHIMS_DISABLE", "1")],
        &["s3", "rm", "--recursive", "s3://prod-bucket"],
    );
    assert!(
        out.status.success(),
        "SHIELD_SHIMS_DISABLE=1 should bypass the engine; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("real-aws-invoked"),
        "real binary must have run when bypass is set; got stdout: {}",
        stdout
    );
}

#[test]
fn install_then_uninstall_removes_the_shim_file() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(install.status.success());
    assert!(shim_dir.path().join("aws").exists());

    let uninstall = Command::new(aperion_shield_binary())
        .args([
            "--uninstall-shims",
            "--shim-dir",
            shim_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("uninstall");
    assert!(
        uninstall.status.success(),
        "uninstall failed:\n{}",
        String::from_utf8_lossy(&uninstall.stderr)
    );
    assert!(
        !shim_dir.path().join("aws").exists(),
        "shim file should be gone after --uninstall-shims"
    );
}

#[test]
fn install_skips_a_foreign_file_at_the_target_path() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();
    fs::create_dir_all(shim_dir.path()).unwrap();

    // User-authored wrapper. We must NEVER overwrite this.
    let target = shim_dir.path().join("aws");
    fs::write(
        &target,
        "#!/bin/sh\n# user wrapper\nexec /weird/aws \"$@\"\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&target, perms).unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    // Foreign-file collision => exit 1 (documented contract).
    assert!(
        !install.status.success(),
        "install should report collision; stderr:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let after = fs::read_to_string(&target).unwrap();
    assert!(
        after.contains("# user wrapper"),
        "user-authored wrapper must be preserved; got: {}",
        after
    );
    assert!(
        !after.contains("APERION-SHIELD-SHIM"),
        "user-authored wrapper must NOT be replaced with our shim"
    );
}

#[test]
fn list_shims_reports_shield_and_foreign_separately() {
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();
    fs::create_dir_all(shim_dir.path()).unwrap();

    // Install one real shim.
    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(install.status.success());

    // Drop a foreign file.
    let foreign = shim_dir.path().join("custom-thing");
    fs::write(&foreign, "#!/bin/sh\necho foreign\n").unwrap();

    let out = Command::new(aperion_shield_binary())
        .args([
            "--list-shims",
            "--shim-dir",
            shim_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("list-shims");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[shield ] aws"), "got:\n{}", stderr);
    assert!(
        stderr.contains("[foreign] custom-thing"),
        "got:\n{}",
        stderr
    );
}

#[test]
fn shim_falls_through_when_aperion_shield_is_not_on_path() {
    // Simulates the "teammate cloned the dotfiles but doesn't have
    // Shield installed yet" scenario. The shim must exec the real
    // binary directly rather than failing closed -- the alternative
    // is breaking aws/kubectl/etc. for everyone on the team.
    let (real, _real_path) = make_fake_real_dir();
    let shim_dir = TempDir::new().unwrap();

    let install = install_shim_for("aws", shim_dir.path(), real.path());
    assert!(install.status.success());

    // Run the shim with a PATH that contains the real-binary dir +
    // /bin (so `sh` itself works) but NOT aperion-shield's dir. The
    // shim should detect the missing binary and fall through.
    let shim = shim_dir.path().join("aws");
    let no_aperion_path = format!("{}:/bin:/usr/bin", real.path().display());
    let out = Command::new("/bin/sh")
        .arg(&shim)
        .args(["s3", "ls"])
        .env("PATH", no_aperion_path)
        .output()
        .expect("run shim");

    assert!(
        out.status.success(),
        "fall-through path should succeed; got:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("real-aws-invoked"),
        "real binary should have run via fall-through; got: {}",
        stdout
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("binary not on $PATH"),
        "fall-through notice should be printed; got: {}",
        stderr
    );
}

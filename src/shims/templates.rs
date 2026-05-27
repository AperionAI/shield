//! Bash sources for the per-command shims installed by `--install-shims`.
//!
//! Each shim is a tiny shell wrapper that lives on `$PATH` ahead of the
//! real binary and routes every invocation through Shield's engine
//! before allowing the call to reach the actual command. The pattern is
//! deliberately the same as the git hooks (`src/hooks/templates.rs`):
//!
//!  1. Identify ourselves with the `APERION_SHIELD_SHIM_MARKER` line so
//!     the installer can re-recognise (and safely overwrite) its own
//!     shims without clobbering anything the user wrote by hand.
//!  2. Honour the documented bypass switches:
//!       * `SHIELD_SHIMS_DISABLE=1`  (env override; useful in CI and
//!         for legitimate ad-hoc invocations the operator decides to
//!         allow). When set, the shim execs the real binary directly,
//!         skipping the engine entirely.
//!  3. Fall back gracefully when the `aperion-shield` binary isn't on
//!     `$PATH`. This matters when teammates inherit a shim directory
//!     via a shared dotfiles repo but haven't installed Shield yet --
//!     we don't want `aws`, `kubectl`, etc. to start failing for them.
//!     Same fail-open posture as the hooks.
//!  4. Run `aperion-shield --check-cmd -- <command> "$@"` and either
//!     exec the real binary (exit 0) or refuse with whatever banner +
//!     exit code Shield emitted.
//!
//! ## Why we resolve the real binary path at install time
//!
//! The shim's last line is `exec /resolved/path/to/aws "$@"`. We resolve
//! `which aws` at install time and bake the absolute path into the
//! generated script. Two reasons:
//!
//!  * **No PATH loops.** If we did `exec aws "$@"` the shell would re-
//!    resolve `aws` against `$PATH` and pick the shim itself (which is
//!    presumably earlier on `$PATH` -- that's why it gets called at
//!    all), giving us an infinite loop.
//!  * **Predictability.** The shim does exactly what `which aws` did
//!    at install time. If the user moves their `aws` binary later,
//!    they can re-run `--install-shims` to refresh.
//!
//! There's a smaller fallback for the unusual case where the real
//! binary disappears between install and invocation: the shim exits
//! cleanly with a stderr notice rather than panicking.

/// Stable marker line that identifies an Aperion-installed shim. The
/// installer matches on this line so we can evolve the shim body across
/// versions without losing the ability to recognise our own footprint.
pub const APERION_SHIELD_SHIM_MARKER: &str = "# APERION-SHIELD-SHIM v1 -- managed by `aperion-shield --install-shims`";

/// Render a shim wrapper for `command_name` whose real binary lives at
/// `real_binary_path`. Returns a complete shell script suitable for
/// writing to `${shim_dir}/${command_name}` and chmod 0755.
///
/// The script is `/bin/sh`-compatible (not bash-specific) so it runs
/// under any POSIX shell, including macOS's default `/bin/sh` and busy-
/// box `ash` on Alpine.
pub fn shim_script(command_name: &str, real_binary_path: &str) -> String {
    format!(
        r#"#!/bin/sh
{marker}
#
# What this does:
#   * Routes every invocation of `{cmd}` through `aperion-shield --check-cmd`
#     before letting it reach the real binary.
#   * Blocks (with the banner Shield emits) on destructive operations
#     that trip a rule in your active shieldset.
#   * Falls back to exec-ing the real binary directly when Shield isn't
#     available, so this never hard-breaks for teammates without Shield
#     installed (e.g. on a fresh laptop pulling shared dotfiles).
#
# Bypass for a single invocation:
#   SHIELD_SHIMS_DISABLE=1 {cmd} <args...>
#
# To remove every shim Shield has installed:
#   aperion-shield --uninstall-shims

set -e

if [ "${{SHIELD_SHIMS_DISABLE:-}}" = "1" ]; then
    exec "{real}" "$@"
fi

if ! command -v aperion-shield >/dev/null 2>&1; then
    echo "[aperion-shield] binary not on \$PATH; skipping shim guardrail for `{cmd}`" >&2
    echo "[aperion-shield] install: brew install AperionAI/tap/aperion-shield" >&2
    exec "{real}" "$@"
fi

if [ ! -x "{real}" ]; then
    echo "[aperion-shield] real `{cmd}` binary not found at {real}" >&2
    echo "[aperion-shield] re-run `aperion-shield --install-shims` to refresh, or uninstall the shim" >&2
    exit 127
fi

aperion-shield --check-cmd -- "{cmd}" "$@"
exit_code=$?
if [ "$exit_code" -ne 0 ]; then
    # Shield refused. Banner is already on stderr; propagate the exit code.
    exit "$exit_code"
fi

exec "{real}" "$@"
"#,
        marker = APERION_SHIELD_SHIM_MARKER,
        cmd = command_name,
        real = real_binary_path,
    )
}

/// The set of commands Shield knows how to shim out-of-the-box. Each
/// entry is the binary name (as it appears on `$PATH`). The shieldset
/// is what actually decides whether any given invocation is destructive
/// -- this list just enumerates which commands `--install-shims` will
/// instrument when invoked without an explicit `--for` filter.
///
/// Why these ten:
///
///  * `aws` / `gcloud` / `az` -- the three big cloud CLIs, each with
///    well-documented destructive verbs (`s3 rm --recursive`,
///    `iam delete-*`, `compute instances delete`, etc.).
///  * `kubectl` / `helm` -- the two production-grade Kubernetes
///    control surfaces. Agents love to issue `kubectl delete namespace`
///    or `helm uninstall` when chasing a "clean state".
///  * `terraform` -- the most common IaC tool. `terraform destroy`
///    is the canonical agent foot-gun.
///  * `psql` / `mongosh` / `redis-cli` -- DB clients. Same engine
///    matches whether the SQL came from MCP or a shell pipe.
///  * `rm` -- the universal one. `rm -rf` from an agent shell that
///    "thinks it's cleaning up" remains the #1 reported failure
///    mode in the v0.7 issue threads.
pub const DEFAULT_SHIMMED_COMMANDS: &[&str] = &[
    "aws",
    "gcloud",
    "az",
    "kubectl",
    "helm",
    "terraform",
    "psql",
    "mongosh",
    "redis-cli",
    "rm",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_script_contains_marker_and_command() {
        let s = shim_script("aws", "/usr/local/bin/aws");
        assert!(s.contains(APERION_SHIELD_SHIM_MARKER));
        assert!(s.contains("aperion-shield --check-cmd -- \"aws\""));
        assert!(s.contains("exec \"/usr/local/bin/aws\""));
    }

    #[test]
    fn shim_script_uses_real_path_in_bypass_branch_too() {
        // The bypass branch (SHIELD_SHIMS_DISABLE=1) must `exec` the
        // real binary, not re-resolve via $PATH (which would loop).
        let s = shim_script("kubectl", "/opt/homebrew/bin/kubectl");
        // The bypass exec must reference the resolved absolute path.
        let bypass_idx = s.find("SHIELD_SHIMS_DISABLE").expect("bypass branch");
        let after_bypass = &s[bypass_idx..];
        assert!(after_bypass.contains("exec \"/opt/homebrew/bin/kubectl\""));
    }

    #[test]
    fn default_commands_contains_the_ten_we_announce() {
        // Lock in the docs commitment: README and release notes say
        // "10 cloud / k8s / IaC / DB / filesystem CLIs". If you change
        // this list you also need to update README + release notes.
        assert_eq!(DEFAULT_SHIMMED_COMMANDS.len(), 10);
        for required in ["aws", "kubectl", "terraform", "rm", "psql"] {
            assert!(
                DEFAULT_SHIMMED_COMMANDS.contains(&required),
                "missing required command in DEFAULT_SHIMMED_COMMANDS: {}",
                required
            );
        }
    }
}

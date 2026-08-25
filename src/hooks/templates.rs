//! Bash sources for the git hooks installed by `--install-hooks`.
//!
//! Each script:
//!
//!  1. Identifies itself with the `APERION_SHIELD_HOOK_MARKER` line so
//!     the installer can re-recognise (and safely overwrite) its own
//!     hooks without clobbering user-authored ones.
//!  2. Honours the documented bypass switches:
//!       * `git commit --no-verify` / `git push --no-verify` (built into
//!         git -- there's nothing for us to do, but we tell the user).
//!       * `SHIELD_HOOKS_DISABLE=1`  (environment override; useful for
//!         non-interactive automation that can't pass `--no-verify`).
//!  3. Falls back gracefully (exit 0 with a stderr notice) when the
//!     `aperion-shield` binary isn't on `PATH`. This matters when
//!     teammates clone a repo where someone installed Shield hooks but
//!     haven't installed Shield themselves yet -- we don't want git
//!     operations to break for them.
//!  4. Calls the appropriate engine mode (`--check-staged` /
//!     `--check-pushed-refs`) and exits with whatever exit code Shield
//!     returned. Shield's own exit-code policy is the source of truth
//!     for what blocks the commit/push.
//!
//! Keeping the hook scripts thin (and deterministic) is on purpose -- if
//! the user inspects `.git/hooks/pre-commit` they should be able to
//! read it in under 30 seconds and trust what it does.

/// Stable marker line that identifies an Aperion-installed hook. The
/// installer matches on this line (not on whole-file checksum) so we
/// can evolve the hook body across versions without losing the ability
/// to recognise our own footprint.
pub const APERION_HOOK_MARKER: &str =
    "# APERION-SHIELD-HOOK v1 -- managed by `aperion-shield --install-hooks`";

/// Pre-commit hook. Runs the engine against staged changes (lines being
/// ADDED or MODIFIED) and refuses the commit if any line trips a Block
/// rule under the active shieldset.
pub fn pre_commit_script() -> String {
    format!(
        r#"#!/bin/sh
{marker}
#
# What this does:
#   * Asks `aperion-shield --check-staged` to scan the lines being
#     ADDED / MODIFIED in this commit.
#   * Blocks the commit (exit 1) if any line trips a destructive rule
#     (DROP DATABASE, rm -rf /, git push --force, etc.).
#   * No-ops cleanly when `aperion-shield` isn't on $PATH.
#
# Bypass switches (in order of preference):
#   git commit --no-verify        # skip all hooks for this commit
#   SHIELD_HOOKS_DISABLE=1 git ...  # env override; works in CI
#
# To remove this hook entirely:
#   aperion-shield --uninstall-hooks

set -e

if [ "${{SHIELD_HOOKS_DISABLE:-}}" = "1" ]; then
    exit 0
fi

if ! command -v aperion-shield >/dev/null 2>&1; then
    echo "[aperion-shield] binary not on \$PATH; skipping pre-commit guardrail" >&2
    echo "[aperion-shield] install: brew install AperionAI/tap/aperion-shield" >&2
    exit 0
fi

exec aperion-shield --check-staged
"#,
        marker = APERION_HOOK_MARKER,
    )
}

/// Pre-push hook. Reads the standard git-supplied stdin describing the
/// refs being pushed and refuses any force-push to a protected branch
/// unless `--no-verify` is passed.
pub fn pre_push_script() -> String {
    format!(
        r#"#!/bin/sh
{marker}
#
# What this does:
#   * Reads git's standard pre-push stdin (one `local_ref local_sha
#     remote_ref remote_sha` line per ref being pushed).
#   * Asks `aperion-shield --check-pushed-refs` whether any ref is a
#     destructive force-push or branch-deletion of a protected branch
#     (main, master, prod, release/*, by default).
#   * Blocks the push (exit 1) if any ref is destructive.
#   * No-ops cleanly when `aperion-shield` isn't on $PATH.
#
# Bypass switches:
#   git push --no-verify
#   SHIELD_HOOKS_DISABLE=1 git push ...
#
# To remove this hook entirely:
#   aperion-shield --uninstall-hooks

set -e

if [ "${{SHIELD_HOOKS_DISABLE:-}}" = "1" ]; then
    exit 0
fi

if ! command -v aperion-shield >/dev/null 2>&1; then
    echo "[aperion-shield] binary not on \$PATH; skipping pre-push guardrail" >&2
    exit 0
fi

# git supplies pre-push refs on stdin; pipe straight through.
exec aperion-shield --check-pushed-refs
"#,
        marker = APERION_HOOK_MARKER,
    )
}

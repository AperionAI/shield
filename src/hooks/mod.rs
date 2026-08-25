//! Git-hook integration (v0.7+) and native agent hooks (v1.5).
//!
//! Git concerns:
//!
//!   * `install`        -- write / remove `.git/hooks/pre-commit` and
//!                         `.git/hooks/pre-push` (`--install-hooks`,
//!                         `--uninstall-hooks`).
//!   * `templates`      -- the bash sources the installer writes.
//!   * `check_staged`   -- the engine path invoked by the pre-commit
//!                         hook (`--check-staged`). Inspects added /
//!                         modified lines of the staged diff and refuses
//!                         the commit if any line trips a Block rule.
//!   * `check_pushed`   -- the engine path invoked by the pre-push
//!                         hook (`--check-pushed-refs`). Reads git's
//!                         pre-push stdin and refuses force-pushes /
//!                         deletions of protected branches.
//!
//! Native agent concerns (v1.5):
//!
//!   * `agent`          -- `--check-hook` stdin JSON adapter (Claude /
//!                         Cursor dialects).
//!   * `agent_install`  -- `--install-agent-hooks` / `--uninstall-agent-hooks`
//!                         user-level Claude `settings.json` + Cursor
//!                         `hooks.json` merge, fail-closed wrappers.
//!
//! See `docs/hooks.md` for the git-hook contract.

pub mod agent;
pub mod agent_install;
pub mod check_pushed;
pub mod check_staged;
pub mod install;
pub mod templates;

pub use install::{
    install, resolve_hooks_dir, uninstall, HookInstallOutcome, HookKind, InstallReport,
    UninstallReport,
};

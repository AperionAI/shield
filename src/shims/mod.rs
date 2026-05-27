//! `aperion-shield --install-shims` and friends: per-command shell
//! wrappers that route invocations through Shield's engine before they
//! reach the real binary.
//!
//! This is the v0.8 follow-on to the git hooks shipped in v0.7. The
//! hooks closed the bypass surface where the agent reaches around MCP
//! and lets a destructive change land in a commit; the shims close the
//! surface where the agent reaches around MCP and runs a destructive
//! command directly (`aws s3 rm --recursive`, `kubectl delete
//! namespace`, `rm -rf $HOME`, ...).
//!
//! Architecture:
//!
//! ```text
//!  user shell (zsh / bash)
//!         │ resolves `aws` via $PATH
//!         v
//!   ~/.aperion-shield/bin/aws        (shim, ~30 lines of /bin/sh)
//!         │ exec aperion-shield --check-cmd -- aws "$@"
//!         v
//!   aperion-shield  (Engine.evaluate("shell", {"command": "aws s3 rm ..."}))
//!         │ exit 0 (allow)  →  exec /usr/local/bin/aws "$@"
//!         │ exit ≥1 (block) →  refuse with banner, propagate code
//!         v
//!     real /usr/local/bin/aws    (only reached on exit 0)
//! ```
//!
//! Public surface from this module:
//!
//!  * `install::install / uninstall / list / resolve_shim_dir / parse_for_arg`
//!  * `check_cmd::run / refusal_banner / CheckCmdReport`
//!  * `templates::shim_script / DEFAULT_SHIMMED_COMMANDS / APERION_SHIELD_SHIM_MARKER`
//!
//! Everything else is private and subject to change.

pub mod check_cmd;
pub mod install;
pub mod templates;

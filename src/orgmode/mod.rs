//! Aperion Shield -- org-mode client.
//!
//! When `aperion-shield enroll <token>` is run, this module bootstraps a
//! persistent record at `~/.aperion-shield/orgmode.json` and switches the
//! binary into "org mode":
//!
//!   - Policy is pulled from Smartflow every 30 s, hot-reloaded on
//!     version bump.
//!   - Audit events are streamed to `/api/enterprise/shield/events`.
//!   - Identity-gated rules use the `SmartflowProvider`, which delegates
//!     to Smartflow as the relying party (which in turn talks to ID.me
//!     or any configured OIDC IdP).
//!   - A heartbeat keeps the fleet dashboard accurate.
//!
//! When no enrollment record exists, none of this code runs and the
//! binary behaves byte-identically to the free standalone tier. The
//! org-mode plumbing is intentionally optional and additive.
//!
//! Module layout:
//!
//! ```text
//! orgmode/
//!   mod.rs               -- public OrgClient + top-level coordinator
//!   state.rs             -- on-disk enrollment record
//!   client.rs            -- thin reqwest wrapper around the smartflow REST API
//!   enroll.rs            -- `aperion-shield enroll <token>` impl
//!   heartbeat.rs         -- 30 s heartbeat task
//!   policy_pull.rs       -- 30 s policy version poll + hot-reload publisher
//!   audit_sink.rs        -- bounded queue, batched POST every 5 s
//!   smartflow_provider.rs -- IdentityProvider implementation
//! ```

#![allow(clippy::module_inception)]

pub mod audit_sink;
pub mod client;
pub mod enroll;
pub mod heartbeat;
pub mod policy_pull;
pub mod smartflow_provider;
pub mod state;

pub use audit_sink::{AuditEvent, AuditSink};
pub use client::{OrgApi, OrgApiError};
pub use enroll::{run_disenroll, run_enroll, run_status};
pub use heartbeat::start_heartbeat;
pub use policy_pull::{start_policy_pull, PolicyPullHandle};
pub use smartflow_provider::SmartflowProvider;
pub use state::{OrgState, ORG_STATE_FILE};

use std::sync::Arc;

use crate::Engine;

/// Outcome of attempting to bootstrap org mode at startup.
pub enum OrgBootstrap {
    /// No `orgmode.json` was found -- behave as plain standalone.
    Standalone,
    /// Enrolled with smartflow. The contained handles are the policy
    /// pull / heartbeat / audit-sink machinery; dropping any of them
    /// drains the corresponding task.
    Enrolled(EnrolledHandles),
}

/// Handles returned when org mode is active. Held by `main()` for the
/// lifetime of the process.
pub struct EnrolledHandles {
    pub state: OrgState,
    pub api: Arc<OrgApi>,
    pub policy: PolicyPullHandle,
    pub audit: Arc<AuditSink>,
    pub _heartbeat_task: tokio::task::JoinHandle<()>,
}

/// Helper used by `main()` to load the engine that should be active at
/// process start: org-mode shieldset if enrolled (and reachable), local
/// rules otherwise.
///
/// On failure to reach Smartflow we fall back to the local engine and
/// log a warning -- this matches the `cached_policy` default offline
/// behaviour documented in the strategy memo.
pub async fn load_initial_engine(state: &OrgState, api: &OrgApi, fallback: Engine) -> Engine {
    match api.get_shieldset(&state.policy_group).await {
        Ok((yaml, version)) => {
            log::warn!(
                "[shield] org-mode policy pulled from {} group={} version={}",
                state.smartflow_url,
                state.policy_group,
                version
            );
            match crate::Engine::from_yaml(&yaml) {
                Ok(eng) => eng,
                Err(e) => {
                    log::error!(
                        "[shield] failed to compile pulled shieldset (group={}): {}. \
                         Falling back to local rules.",
                        state.policy_group,
                        e
                    );
                    fallback
                }
            }
        }
        Err(e) => {
            log::warn!(
                "[shield] could not pull policy from Smartflow ({}); using local rules: {}",
                state.smartflow_url,
                e
            );
            fallback
        }
    }
}

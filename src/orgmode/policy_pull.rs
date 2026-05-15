//! Policy fan-out -- pull side.
//!
//! Polls `/api/enterprise/shield/shieldset/<group>/version` every 30 s.
//! When the server reports a newer version, downloads the YAML and
//! publishes a fresh [`crate::Engine`] on a `tokio::sync::watch` channel
//! that the MCP middleman snapshots on every tool call.
//!
//! The polling cadence is intentionally generous -- this is M2 first
//! cut; we can swap in SSE / WebSocket fan-out in M2.5 without changing
//! the consumer API (still a `watch::Receiver<Arc<Engine>>`).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use super::client::OrgApi;
use super::state::OrgState;
use crate::Engine;

/// How often we probe for a new policy version.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Handle returned to `main()`. Holds the receiver side of the watch
/// channel + the running task. Dropping it cancels the task.
pub struct PolicyPullHandle {
    pub current: watch::Receiver<Arc<Engine>>,
    pub killswitch: watch::Receiver<bool>,
    /// Latest version we've seen from the server, exposed for the
    /// status / metrics path.
    pub version: Arc<tokio::sync::Mutex<u64>>,
    pub _task: tokio::task::JoinHandle<()>,
}

/// Spawn the policy-pull loop. `initial_engine` is the engine the
/// process started with -- usually the result of
/// `orgmode::load_initial_engine` -- and is published as the first
/// value on the watch channel.
pub fn start_policy_pull(
    api: Arc<OrgApi>,
    state: OrgState,
    initial_engine: Arc<Engine>,
    initial_version: u64,
) -> PolicyPullHandle {
    let (tx, rx) = watch::channel(initial_engine);
    let (ks_tx, ks_rx) = watch::channel(false);
    let version = Arc::new(tokio::sync::Mutex::new(initial_version));
    let version_for_task = version.clone();

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately -- skip; we already published
        // the initial engine.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let probe = match api.get_shieldset_version(&state.policy_group).await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("[shield] policy version probe failed: {}", e);
                    continue;
                }
            };

            // Killswitch publishes independently so we can react fast
            // without re-pulling policy.
            let _ = ks_tx.send(probe.killswitch.on);
            if probe.killswitch.on {
                log::warn!(
                    "[shield] killswitch ON (reason={:?}) -- block-all in effect",
                    probe.killswitch.reason
                );
            }

            let cur = version_for_task.lock().await;
            if probe.version <= *cur {
                continue;
            }
            drop(cur); // free the lock for the duration of the fetch

            let pulled = match api.get_shieldset(&state.policy_group).await {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("[shield] shieldset fetch failed: {}", e);
                    continue;
                }
            };
            let (yaml, new_version) = pulled;
            let new_engine = match Engine::from_yaml(&yaml) {
                Ok(e) => e,
                Err(e) => {
                    log::error!(
                        "[shield] pulled shieldset is invalid (version={}): {}. Keeping previous policy.",
                        new_version, e
                    );
                    continue;
                }
            };
            let mut cur = version_for_task.lock().await;
            *cur = new_version;
            drop(cur);

            log::warn!(
                "[shield] hot-reloaded policy: group={} version={} rules={}",
                state.policy_group,
                new_version,
                new_engine.rules.len()
            );
            // `send` returns Err only if every receiver has been
            // dropped; in that case the process is shutting down.
            let _ = tx.send(Arc::new(new_engine));
        }
    });

    PolicyPullHandle {
        current: rx,
        killswitch: ks_rx,
        version,
        _task: task,
    }
}

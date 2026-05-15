//! 30-second heartbeat task.
//!
//! Calls `POST /api/enterprise/devices/{id}/heartbeat`. Failures are
//! logged at warn level but never crash the binary -- we want the local
//! MCP guardrail to keep working even if the dashboard is down.

use std::sync::Arc;
use std::time::Duration;

use super::client::OrgApi;
use super::state::OrgState;

/// How often we ping. Matches the value the strategy memo committed to.
const INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the heartbeat task and return its `JoinHandle`. Holding the
/// handle keeps the task alive; dropping it sends a cooperative cancel
/// (the task notices on its next sleep tick).
pub fn start_heartbeat(api: Arc<OrgApi>, state: OrgState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // First heartbeat ASAP so the fleet view picks the device up.
        if let Err(e) = api.heartbeat(&state.device_id).await {
            log::warn!("[shield] initial heartbeat failed: {}", e);
        }
        let mut ticker = tokio::time::interval(INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediately-fires first tick -- we already heartbeat'd.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = api.heartbeat(&state.device_id).await {
                log::warn!("[shield] heartbeat failed: {}", e);
            }
        }
    })
}

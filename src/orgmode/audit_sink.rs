//! Audit sink for the MCP middleman.
//!
//! [`AuditSink::record`] writes the decision to the on-disk spool (see
//! [`super::spool`]), so a crash or an outage doesn't lose it. A flusher
//! forwards the spool every 5 s. Allows are tallied, not sent one by one.
//! A 401 means the device was revoked; forwarding stops and the events
//! stay on disk.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::client::{OrgApi, OrgApiError};
use super::spool::Spool;

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub rule_id: String,
    pub decision: String,
    pub severity: String,
    pub tool: String,
    pub fingerprint: String,
    #[serde(default)]
    pub context: serde_json::Value,
}

/// Write one hook or proxy decision to the spool.
pub fn spool_decision(spool: &Spool, ev: &AuditEvent) -> anyhow::Result<()> {
    if ev.decision == "allow" {
        spool.count_allow(&ev.tool)
    } else {
        spool.append(ev).map(|_| ())
    }
}

pub struct AuditSink {
    spool: Option<Spool>,
    api: Arc<OrgApi>,
    revoked: AtomicBool,
}

impl AuditSink {
    pub fn new(api: Arc<OrgApi>) -> Arc<Self> {
        let spool = Spool::open()
            .map_err(|e| log::error!("[shield] audit spool unavailable: {e}"))
            .ok();
        let sink = Arc::new(Self {
            spool,
            api,
            revoked: AtomicBool::new(false),
        });
        let sink_for_task = sink.clone();
        tokio::spawn(async move {
            sink_for_task.run_flusher().await;
        });
        sink
    }

    pub async fn record(&self, ev: AuditEvent) {
        let Some(spool) = &self.spool else {
            return log::warn!("[shield] audit not spooled (no spool): rule_id={}", ev.rule_id);
        };
        if let Err(e) = spool_decision(spool, &ev) {
            log::warn!("[shield] audit spool write failed rule_id={}: {e}", ev.rule_id);
        }
    }

    async fn flush_once(&self) -> Result<(), OrgApiError> {
        let Some(spool) = &self.spool else { return Ok(()) };
        if let Err(e) = spool.flush_allow_counts() {
            log::warn!("[shield] allow tally flush failed: {e}");
        }
        spool.forward(&self.api).await.map(|_| ())
    }

    async fn run_flusher(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;
            if self.revoked.load(Ordering::Relaxed) {
                continue;
            }
            match self.flush_once().await {
                Ok(()) => backoff = Duration::from_secs(1),
                Err(OrgApiError::Unauthorized) => {
                    self.revoked.store(true, Ordering::Relaxed);
                    log::error!("[shield] Smartflow rejected this device (401). Audit forwarding stopped; events stay in the spool.");
                }
                Err(e) => {
                    log::warn!("[shield] audit ship failed: {e} -- retry in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    /// One last forward on shutdown.
    pub async fn drain(&self) {
        if self.revoked.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = self.flush_once().await {
            log::warn!("[shield] audit drain failed: {e}");
        }
    }
}

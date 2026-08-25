//! Audit sink -- bounded in-memory queue, batched POST every 5 s.
//!
//! The MCP middleman calls [`AuditSink::record`] every time the engine
//! produces a decision. The sink buffers up to 1000 entries; the
//! background flusher batches them in groups of 200 and POSTs to
//! `/api/enterprise/shield/events`. Failures are retried with
//! exponential backoff, never lose more than the in-memory buffer.
//!
//! Designed to never block the hot path. `record()` is a non-async
//! `try_send` -- if the queue is full we drop the oldest event and
//! log at warn level (the in-process stderr log line still happens
//! either way, so we never *silently* lose data).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::client::OrgApi;

/// Maximum number of events held in memory before we start dropping.
const QUEUE_CAP: usize = 1000;

/// Maximum events shipped per POST.
const BATCH_SIZE: usize = 200;

/// How often the flusher wakes up to ship a batch.
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

pub struct AuditSink {
    queue: Mutex<Vec<AuditEvent>>,
    api: Arc<OrgApi>,
}

impl AuditSink {
    /// Create a sink + spawn the background flusher. Returns the sink
    /// wrapped in `Arc` so producers + flusher share state.
    pub fn new(api: Arc<OrgApi>) -> Arc<Self> {
        let sink = Arc::new(Self {
            queue: Mutex::new(Vec::with_capacity(QUEUE_CAP)),
            api,
        });
        let sink_for_task = sink.clone();
        tokio::spawn(async move {
            sink_for_task.run_flusher().await;
        });
        sink
    }

    /// Non-blocking enqueue. Drops the oldest event if the queue is
    /// full, surfacing a warn-log so operators notice.
    ///
    /// Async because we await the queue lock (it's a `tokio::Mutex`).
    /// In practice this is a contended lock for sub-microsecond bursts
    /// only; the await never crosses an I/O boundary.
    pub async fn record(&self, ev: AuditEvent) {
        let mut q = self.queue.lock().await;
        if q.len() >= QUEUE_CAP {
            let dropped = q.remove(0);
            log::warn!(
                "[shield] audit queue full ({} events buffered); dropped oldest rule_id={} ts={}",
                QUEUE_CAP,
                dropped.rule_id,
                dropped.ts
            );
        }
        q.push(ev);
    }

    async fn run_flusher(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;

            // Snapshot up to BATCH_SIZE events from the queue.
            let batch = {
                let mut q = self.queue.lock().await;
                if q.is_empty() {
                    continue;
                }
                let n = q.len().min(BATCH_SIZE);
                q.drain(..n).collect::<Vec<_>>()
            };

            let payload: Vec<serde_json::Value> = batch
                .iter()
                .filter_map(|e| serde_json::to_value(e).ok())
                .collect();

            match self.api.post_events(&payload).await {
                Ok(ack) => {
                    log::debug!(
                        "[shield] audit shipped: received={} batch_size={}",
                        ack.received,
                        batch.len()
                    );
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    // Re-enqueue at the front so we don't lose data.
                    let mut q = self.queue.lock().await;
                    for ev in batch.into_iter().rev() {
                        if q.len() >= QUEUE_CAP {
                            // Drop oldest from the *back* (these are
                            // the newest unflushed) to keep the older
                            // re-queued ones near head. The net effect:
                            // on prolonged outage we keep the *oldest*
                            // QUEUE_CAP events.
                            let _ = q.pop();
                        }
                        q.insert(0, ev);
                    }
                    drop(q);
                    log::warn!(
                        "[shield] audit ship failed: {} -- retry in {:?}",
                        e,
                        backoff
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    /// Best-effort drain on shutdown. The caller awaits a short timeout
    /// to give the background flusher one last chance to ship.
    pub async fn drain(&self) {
        let q = self.queue.lock().await;
        let n = q.len();
        drop(q);
        if n == 0 {
            return;
        }
        log::info!("[shield] draining {} pending audit events before exit", n);
        // Give the flusher one full cycle.
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_millis(500)).await;
    }
}

//! In-process burst detector. Maintains a sliding window of the
//! timestamps at which Shield observed a destructive (non-Allow)
//! match. When the count within the window crosses the threshold,
//! `in_burst()` returns true and the engine bumps every subsequent
//! match by one tier until the burst window quiets.
//!
//! Process-local on purpose: the standalone is single-process per
//! upstream MCP server, and this is the free tier. Enterprise gets
//! shared bursts via Redis.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::engine::BurstDetectorCfg;

#[derive(Debug)]
pub struct BurstDetector {
    cfg: BurstDetectorCfg,
    events: Mutex<VecDeque<Instant>>,
}

impl BurstDetector {
    pub fn new(cfg: BurstDetectorCfg) -> Self {
        Self { cfg, events: Mutex::new(VecDeque::new()) }
    }

    /// Record a destructive event observed at `Instant::now()` and
    /// return whether we are currently inside a burst (count ≥ threshold
    /// within the trailing window).
    pub fn observe(&self) -> bool {
        if !self.cfg.enabled { return false; }
        let now = Instant::now();
        let window = Duration::from_secs(self.cfg.window_seconds as u64);
        let mut q = self.events.lock().expect("burst mutex poisoned");
        q.push_back(now);
        // Trim events older than the window.
        while let Some(&front) = q.front() {
            if now.duration_since(front) > window {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len() as u32 >= self.cfg.threshold
    }

    /// Read-only check without recording. Used when we want to know if
    /// a burst is "still in progress" while deciding the *current*
    /// event without double-counting it.
    pub fn in_burst(&self) -> bool {
        if !self.cfg.enabled { return false; }
        let now = Instant::now();
        let window = Duration::from_secs(self.cfg.window_seconds as u64);
        let q = self.events.lock().expect("burst mutex poisoned");
        q.iter()
            .rev()
            .take_while(|&&t| now.duration_since(t) <= window)
            .count() as u32
            >= self.cfg.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: u32, window_seconds: u32) -> BurstDetectorCfg {
        BurstDetectorCfg {
            enabled: true,
            window_seconds,
            threshold,
        }
    }

    #[test]
    fn below_threshold_no_burst() {
        let b = BurstDetector::new(cfg(5, 60));
        for _ in 0..4 {
            assert!(!b.observe());
        }
    }

    #[test]
    fn at_threshold_triggers_burst() {
        let b = BurstDetector::new(cfg(3, 60));
        assert!(!b.observe());
        assert!(!b.observe());
        assert!(b.observe()); // third event hits threshold
        assert!(b.in_burst());
    }

    #[test]
    fn window_expiry_resets_burst() {
        let b = BurstDetector::new(cfg(2, 0)); // zero-second window: every observe trims everything before it
        b.observe();
        std::thread::sleep(Duration::from_millis(5));
        // Second observe trims the prior one; we have 1 event, threshold 2 → no burst.
        assert!(!b.observe());
    }

    #[test]
    fn disabled_never_fires() {
        let mut c = cfg(1, 60);
        c.enabled = false;
        let b = BurstDetector::new(c);
        for _ in 0..10 {
            assert!(!b.observe());
        }
    }
}

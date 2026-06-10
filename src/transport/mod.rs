//! Transports (v0.9).
//!
//! Until v0.8 Shield spoke exactly one dialect: stdio on both sides
//! (IDE <-> shield <-> spawned child process). v0.9 generalises both
//! seams behind a channel pair so the relay core in `main.rs` doesn't
//! care what carries the frames:
//!
//! * **Upstream** (toward the MCP server):
//!   - [`spawn_stdio_upstream`] -- the classic spawned child process.
//!   - [`http_upstream::spawn_http_upstream`] -- a remote MCP server
//!     speaking Streamable HTTP (JSON-RPC over POST, with optional SSE
//!     response streams). This closes the remote-server bypass: agents
//!     using hosted MCP servers get the same shieldset enforcement as
//!     local stdio ones.
//!
//! * **Downstream** (toward the IDE):
//!   - stdio (default, unchanged).
//!   - [`http_server::run_http_downstream`] -- Shield itself listens as
//!     a Streamable HTTP MCP server (`--http-listen`), so hosts that
//!     only speak HTTP can still sit behind Shield.
//!
//! Frames are newline-free JSON-RPC message strings. Channels are
//! bounded ([`CHANNEL_DEPTH`]) so a slow consumer backpressures the
//! producer instead of buffering unboundedly -- for the SSE relay this
//! propagates all the way down to TCP.

use anyhow::{anyhow, Context};
use log::{debug, error};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

pub mod http_server;
pub mod http_upstream;

/// Bounded channel depth for both directions. Deep enough to absorb a
/// burst of notifications, shallow enough that backpressure reaches the
/// wire quickly.
pub const CHANNEL_DEPTH: usize = 64;

/// A running upstream connection, whatever the wire.
pub struct UpstreamHandle {
    /// Frames the relay wants delivered to the MCP server.
    pub tx: mpsc::Sender<String>,
    /// Frames the MCP server produced (responses + notifications).
    pub rx: mpsc::Receiver<String>,
    /// Human-readable label (command line or URL) -- used for log lines
    /// and as the supply-chain pin key.
    pub label: String,
    /// Held so the child process is killed when the handle drops.
    /// `None` for network upstreams.
    pub child: Option<Child>,
}

/// Spawn the classic stdio upstream: run the command, pump its stdout
/// lines into `rx`, deliver `tx` frames to its stdin.
pub fn spawn_stdio_upstream(cmd: &[String]) -> anyhow::Result<UpstreamHandle> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| anyhow!("empty upstream command"))?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn upstream '{}'", program))?;
    let mut child_in = child.stdin.take().ok_or_else(|| anyhow!("missing child stdin"))?;
    let child_out = child.stdout.take().ok_or_else(|| anyhow!("missing child stdout"))?;

    let (to_tx, mut to_rx) = mpsc::channel::<String>(CHANNEL_DEPTH);
    let (from_tx, from_rx) = mpsc::channel::<String>(CHANNEL_DEPTH);

    // Pump: relay -> child stdin.
    tokio::spawn(async move {
        while let Some(frame) = to_rx.recv().await {
            if let Err(e) = child_in.write_all(frame.as_bytes()).await {
                error!("[shield] child stdin write error: {}", e);
                break;
            }
            if let Err(e) = child_in.write_all(b"\n").await {
                error!("[shield] child stdin write error: {}", e);
                break;
            }
            let _ = child_in.flush().await;
        }
        let _ = child_in.shutdown().await;
    });

    // Pump: child stdout -> relay.
    tokio::spawn(async move {
        let mut reader = BufReader::new(child_out);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    debug!("[shield] child EOF");
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    error!("[shield] child read error: {}", e);
                    break;
                }
            }
            let frame = line.trim_end();
            if frame.is_empty() {
                continue;
            }
            // .send() awaiting = bounded-channel backpressure.
            if from_tx.send(frame.to_string()).await.is_err() {
                break;
            }
        }
    });

    Ok(UpstreamHandle {
        tx: to_tx,
        rx: from_rx,
        label: cmd.join(" "),
        child: Some(child),
    })
}

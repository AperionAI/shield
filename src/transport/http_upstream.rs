//! Streamable HTTP upstream client (v0.9).
//!
//! Connects Shield to a *remote* MCP server per the MCP Streamable HTTP
//! transport: every JSON-RPC message is POSTed to the server's single
//! MCP endpoint; the response is either `application/json` (one message)
//! or `text/event-stream` (a stream of messages that ends once the
//! request's response has been delivered). A long-lived GET stream picks
//! up server-initiated messages when the server supports one.
//!
//! Session handling: if the server returns an `Mcp-Session-Id` header on
//! the `initialize` response, it is echoed on every subsequent request.
//!
//! Backpressure: SSE bytes are only pulled off the socket as fast as the
//! relay drains the bounded channel -- `from_tx.send().await` suspends
//! the read loop, which suspends the TCP window. No unbounded buffering.

use anyhow::Context;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use super::{UpstreamHandle, CHANNEL_DEPTH};

/// Parse `K: V` header args from the CLI.
pub fn parse_header(raw: &str) -> anyhow::Result<(String, String)> {
    let (k, v) = raw
        .split_once(':')
        .with_context(|| format!("--upstream-header '{}' is not 'Name: value'", raw))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

pub fn spawn_http_upstream(
    url: &str,
    extra_headers: Vec<(String, String)>,
) -> anyhow::Result<UpstreamHandle> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        // No total-request timeout: SSE response streams are long-lived.
        .build()
        .context("building HTTP client for upstream")?;

    let (to_tx, mut to_rx) = mpsc::channel::<String>(CHANNEL_DEPTH);
    let (from_tx, from_rx) = mpsc::channel::<String>(CHANNEL_DEPTH);

    let session: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let url_owned = url.to_string();

    // POST pump: every frame from the relay becomes one POST. Responses
    // (JSON or SSE) flow back into `from_tx`. Requests are sent
    // sequentially -- MCP initialize handshakes require ordering, and
    // agent traffic is effectively serial anyway.
    {
        let client = client.clone();
        let url = url_owned.clone();
        let from_tx = from_tx.clone();
        let session = session.clone();
        tokio::spawn(async move {
            while let Some(frame) = to_rx.recv().await {
                let is_initialize = frame.contains("\"initialize\"");
                let mut req = client
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("accept", "application/json, text/event-stream");
                for (k, v) in &extra_headers {
                    req = req.header(k, v);
                }
                if let Some(sid) = session.lock().await.clone() {
                    req = req.header("mcp-session-id", sid);
                }
                let resp = match req.body(frame.clone()).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("[shield] upstream POST failed: {}", e);
                        // Surface a JSON-RPC error for requests so the IDE
                        // isn't left hanging on a dead upstream.
                        if let Some(err) = transport_error_for(&frame, &e.to_string()) {
                            let _ = from_tx.send(err).await;
                        }
                        continue;
                    }
                };

                // Capture the session id the server assigns on initialize.
                if is_initialize {
                    if let Some(sid) = resp
                        .headers()
                        .get("mcp-session-id")
                        .and_then(|v| v.to_str().ok())
                    {
                        info!("[shield] upstream assigned MCP session id");
                        *session.lock().await = Some(sid.to_string());
                    }
                }

                let status = resp.status();
                if status == reqwest::StatusCode::ACCEPTED {
                    // 202 = notification/response accepted, nothing to read.
                    continue;
                }
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        "[shield] upstream POST returned {}: {}",
                        status,
                        body.chars().take(300).collect::<String>()
                    );
                    if let Some(err) =
                        transport_error_for(&frame, &format!("upstream returned {}", status))
                    {
                        let _ = from_tx.send(err).await;
                    }
                    continue;
                }

                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if ct.starts_with("text/event-stream") {
                    if let Err(e) = pump_sse(resp, &from_tx).await {
                        warn!("[shield] upstream SSE stream ended with error: {}", e);
                    }
                } else {
                    match resp.text().await {
                        Ok(body) if !body.trim().is_empty() => {
                            if from_tx.send(body.trim().to_string()).await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => error!("[shield] upstream body read error: {}", e),
                    }
                }
            }
            debug!("[shield] upstream POST pump finished");
        });
    }

    // Optional GET pump: a long-lived SSE stream for server-initiated
    // messages. Many servers don't support it -- a 4xx/405 just disables
    // the feature.
    {
        let url = url_owned.clone();
        tokio::spawn(async move {
            // Give initialize a moment to establish the session first.
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let mut req = client
                .get(&url)
                .header("accept", "text/event-stream");
            if let Some(sid) = session.lock().await.clone() {
                req = req.header("mcp-session-id", sid);
            }
            match req.send().await {
                Ok(resp)
                    if resp.status().is_success()
                        && resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|ct| ct.starts_with("text/event-stream"))
                            .unwrap_or(false) =>
                {
                    info!("[shield] upstream GET SSE stream open (server-initiated messages)");
                    if let Err(e) = pump_sse(resp, &from_tx).await {
                        debug!("[shield] upstream GET SSE stream closed: {}", e);
                    }
                }
                Ok(resp) => {
                    debug!(
                        "[shield] upstream has no GET SSE stream (status {}) -- skipping",
                        resp.status()
                    );
                }
                Err(e) => debug!("[shield] upstream GET SSE probe failed: {}", e),
            }
        });
    }

    Ok(UpstreamHandle {
        tx: to_tx,
        rx: from_rx,
        label: url_owned,
        child: None,
    })
}

/// Drain one SSE response: parse `data:` payloads out of the byte stream
/// and forward each as a frame. Multi-line `data:` fields are joined per
/// the SSE spec.
async fn pump_sse(
    resp: reqwest::Response,
    from_tx: &mpsc::Sender<String>,
) -> anyhow::Result<()> {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("SSE chunk")?;
        buf.extend_from_slice(&chunk);
        // Process complete events (separated by a blank line).
        loop {
            let Some(pos) = find_event_boundary(&buf) else { break };
            let event_bytes: Vec<u8> = buf.drain(..pos.end).collect();
            let event = String::from_utf8_lossy(&event_bytes[..pos.start]).to_string();
            let mut data_lines: Vec<&str> = Vec::new();
            for line in event.lines() {
                if let Some(rest) = line.strip_prefix("data:") {
                    data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
                }
            }
            if data_lines.is_empty() {
                continue;
            }
            let payload = data_lines.join("\n");
            if payload.trim().is_empty() {
                continue;
            }
            // Bounded send = backpressure all the way to TCP.
            if from_tx.send(payload).await.is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

struct EventBoundary {
    /// Bytes of the event itself (exclusive of the separator).
    start: usize,
    /// Bytes to drain (event + separator).
    end: usize,
}

/// Find the first complete SSE event in `buf`, handling both `\n\n` and
/// `\r\n\r\n` separators. Returns the event extent and total drain
/// length.
fn find_event_boundary(buf: &[u8]) -> Option<EventBoundary> {
    let lf = buf.windows(2).position(|w| w == b"\n\n");
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(a), Some(b)) if b < a => Some(EventBoundary { start: b, end: b + 4 }),
        (Some(a), _) => Some(EventBoundary { start: a, end: a + 2 }),
        (None, Some(b)) => Some(EventBoundary { start: b, end: b + 4 }),
        (None, None) => None,
    }
}

/// Build a JSON-RPC error response for a *request* frame whose POST
/// failed in transport. Notifications (no id) return None.
fn transport_error_for(frame: &str, detail: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(frame).ok()?;
    let id = parsed.get("id")?.clone();
    if id.is_null() {
        return None;
    }
    Some(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": "shield_upstream_transport_error",
                "data": { "detail": detail }
            }
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_ok() {
        let (k, v) = parse_header("Authorization: Bearer abc").unwrap();
        assert_eq!(k, "Authorization");
        assert_eq!(v, "Bearer abc");
    }

    #[test]
    fn parse_header_rejects_missing_colon() {
        assert!(parse_header("not-a-header").is_err());
    }

    #[test]
    fn event_boundary_lf() {
        let buf = b"data: {\"a\":1}\n\nrest";
        let b = find_event_boundary(buf).unwrap();
        assert_eq!(&buf[..b.start], b"data: {\"a\":1}");
        assert_eq!(b.end - b.start, 2);
    }

    #[test]
    fn event_boundary_crlf() {
        let buf = b"data: x\r\n\r\n";
        let b = find_event_boundary(buf).unwrap();
        assert_eq!(&buf[..b.start], b"data: x");
        assert_eq!(b.end - b.start, 4);
    }

    #[test]
    fn transport_error_only_for_requests() {
        assert!(transport_error_for(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#, "boom").is_some());
        assert!(transport_error_for(r#"{"jsonrpc":"2.0","method":"notify"}"#, "boom").is_none());
        assert!(transport_error_for("not json", "boom").is_none());
    }
}

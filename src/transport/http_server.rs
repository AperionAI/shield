//! IDE-facing Streamable HTTP MCP server (v0.9, `--http-listen`).
//!
//! Shield itself listens as an MCP server speaking the Streamable HTTP
//! transport, so hosts that only talk HTTP can still put Shield in
//! front of any upstream (stdio child process or remote HTTP server):
//!
//! * `POST <any path>` with a JSON-RPC **request** -> the request runs
//!   through the same Shield gate as the stdio path (Block / Approval /
//!   Warn / identity), is forwarded upstream on pass, and the matching
//!   upstream response is returned as `application/json`.
//! * `POST` with a **notification or client response** -> forwarded
//!   upstream, `202 Accepted`.
//! * `GET` with `Accept: text/event-stream` -> a long-lived SSE stream
//!   carrying server-initiated messages (notifications, requests the
//!   upstream pushes outside a POST exchange).
//! * `DELETE` -> `200` (session termination; sessions here are lenient).
//!
//! An `Mcp-Session-Id` is minted on `initialize` and echoed back; Shield
//! does not currently reject requests with missing/stale session ids
//! (lenient mode -- enforcement adds nothing while Shield fronts exactly
//! one upstream per process).
//!
//! JSON-RPC batch arrays are rejected with 400 -- the 2025-06-18 MCP
//! revision removed batching support.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{error, info, warn};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

type RespBody = BoxBody<Bytes, Infallible>;

/// How the relay core lets the HTTP server run requests through the
/// Shield gate. Implemented by `main.rs` on its `Shield` state.
#[async_trait::async_trait]
pub trait RequestGate: Send + Sync {
    /// `Some(response)` when Shield answers the request itself (block /
    /// denied approval / pending identity); `None` to forward upstream.
    async fn intercept(&self, req: &Value) -> Option<Value>;

    /// Rewrite a to-be-forwarded request frame before it goes upstream.
    /// `Some(frame)` replaces the outbound frame (v1.4 secret cloaking
    /// resolves `{{cloak:NAME}}` placeholders here); `None` forwards the
    /// original frame unchanged. Default: no rewrite.
    async fn transform_outbound(&self, _req: &Value) -> Option<String> {
        None
    }
}

/// Shared state between the HTTP server and the relay core.
pub struct HttpDownstream {
    /// Responses the HTTP layer is waiting on, keyed by canonical id.
    pub pending: Mutex<HashMap<String, oneshot::Sender<String>>>,
    /// Frames with no waiting POST (server-initiated traffic) fan out to
    /// every open GET SSE stream.
    pub broadcast: broadcast::Sender<String>,
}

impl HttpDownstream {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(super::CHANNEL_DEPTH);
        Arc::new(Self {
            pending: Mutex::new(HashMap::new()),
            broadcast: tx,
        })
    }

    /// Route one upstream frame: complete the waiting POST if there is
    /// one, otherwise broadcast to SSE subscribers. Called by the relay
    /// core for every (post-interception) upstream frame.
    pub async fn route_upstream_frame(&self, frame: String) {
        if let Ok(parsed) = serde_json::from_str::<Value>(&frame) {
            if let Some(id) = parsed.get("id") {
                if !id.is_null() && parsed.get("method").is_none() {
                    let key = canonical_id(id);
                    if let Some(tx) = self.pending.lock().await.remove(&key) {
                        let _ = tx.send(frame);
                        return;
                    }
                }
            }
        }
        // No waiter -- fan out (errors just mean no open GET streams).
        let _ = self.broadcast.send(frame);
    }
}

/// Canonical map key for a JSON-RPC id (number or string).
pub fn canonical_id(id: &Value) -> String {
    id.to_string()
}

/// Serve the downstream HTTP endpoint until the process exits.
pub async fn serve(
    addr: SocketAddr,
    gate: Arc<dyn RequestGate>,
    to_upstream: mpsc::Sender<String>,
    state: Arc<HttpDownstream>,
) -> anyhow::Result<()> {
    if !addr.ip().is_loopback() {
        warn!(
            "[shield] --http-listen {} is NOT loopback -- anyone who can reach this port \
             can drive your MCP tools. Prefer 127.0.0.1.",
            addr
        );
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        "[shield] HTTP downstream listening on http://{} (Streamable HTTP MCP)",
        addr
    );
    serve_on(listener, gate, to_upstream, state).await
}

/// Accept-loop over an already-bound listener. Split out from [`serve`]
/// so integration tests can bind port 0 and learn the real address.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    gate: Arc<dyn RequestGate>,
    to_upstream: mpsc::Sender<String>,
    state: Arc<HttpDownstream>,
) -> anyhow::Result<()> {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!("[shield] http accept error: {}", e);
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let gate = gate.clone();
        let to_upstream = to_upstream.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let gate = gate.clone();
                let to_upstream = to_upstream.clone();
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(req, gate, to_upstream, state).await) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                // Normal for SSE streams the client drops.
                log::debug!("[shield] http connection ended: {}", e);
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    gate: Arc<dyn RequestGate>,
    to_upstream: mpsc::Sender<String>,
    state: Arc<HttpDownstream>,
) -> Response<RespBody> {
    match *req.method() {
        Method::POST => handle_post(req, gate, to_upstream, state).await,
        Method::GET => handle_get_sse(req, state).await,
        Method::DELETE => text(StatusCode::OK, "session terminated"),
        _ => text(StatusCode::METHOD_NOT_ALLOWED, "use POST / GET / DELETE"),
    }
}

async fn handle_post(
    req: Request<Incoming>,
    gate: Arc<dyn RequestGate>,
    to_upstream: mpsc::Sender<String>,
    state: Arc<HttpDownstream>,
) -> Response<RespBody> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("body read error: {}", e)),
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };
    if parsed.is_array() {
        return text(
            StatusCode::BAD_REQUEST,
            "JSON-RPC batching is not supported (removed in MCP 2025-06-18)",
        );
    }

    let frame = parsed.to_string();
    let is_initialize = parsed.get("method").and_then(|m| m.as_str()) == Some("initialize");
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let is_request = parsed.get("method").is_some() && !id.is_null();

    if !is_request {
        // Notification or client->server response: forward, 202.
        if to_upstream.send(frame).await.is_err() {
            return text(StatusCode::BAD_GATEWAY, "upstream gone");
        }
        return text(StatusCode::ACCEPTED, "");
    }

    // Run the Shield gate exactly like the stdio path.
    if let Some(decision_resp) = gate.intercept(&parsed).await {
        return json_response(decision_resp.to_string(), is_initialize);
    }

    // Register the waiter BEFORE forwarding so the response can't race us.
    let (tx, rx) = oneshot::channel::<String>();
    let key = canonical_id(&id);
    state.pending.lock().await.insert(key.clone(), tx);

    // v1.4 cloak: resolve `{{cloak:NAME}}` placeholders on the upstream copy
    // only (runs after the gate, so rules saw the placeholder).
    let outbound = gate.transform_outbound(&parsed).await.unwrap_or(frame);
    if to_upstream.send(outbound).await.is_err() {
        state.pending.lock().await.remove(&key);
        return text(StatusCode::BAD_GATEWAY, "upstream gone");
    }

    // Approvals can legitimately take a minute -- be generous.
    match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
        Ok(Ok(resp_frame)) => json_response(resp_frame, is_initialize),
        Ok(Err(_)) => text(
            StatusCode::BAD_GATEWAY,
            "upstream closed without responding",
        ),
        Err(_) => {
            state.pending.lock().await.remove(&key);
            text(StatusCode::GATEWAY_TIMEOUT, "upstream response timeout")
        }
    }
}

async fn handle_get_sse(req: Request<Incoming>, state: Arc<HttpDownstream>) -> Response<RespBody> {
    let wants_sse = req
        .headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/event-stream"))
        .unwrap_or(false);
    if !wants_sse {
        return text(
            StatusCode::OK,
            "aperion-shield Streamable HTTP MCP endpoint. POST JSON-RPC here; \
             GET with Accept: text/event-stream for the server-initiated stream.",
        );
    }

    let rx = state.broadcast.subscribe();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(frame) => {
                    let chunk = Bytes::from(format!("data: {}\n\n", frame));
                    return Some((Ok::<_, Infallible>(Frame::data(chunk)), rx));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("[shield] SSE subscriber lagged, skipped {} frames", n);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-store")
        .body(BoxBody::new(StreamBody::new(stream)))
        .unwrap()
}

fn json_response(frame: String, mint_session: bool) -> Response<RespBody> {
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");
    if mint_session {
        b = b.header("mcp-session-id", uuid::Uuid::new_v4().simple().to_string());
    }
    b.body(BoxBody::new(Full::new(Bytes::from(frame)))).unwrap()
}

fn text(status: StatusCode, msg: &str) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(BoxBody::new(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_id_distinguishes_number_and_string() {
        assert_eq!(canonical_id(&json!(1)), "1");
        assert_eq!(canonical_id(&json!("1")), "\"1\"");
        assert_ne!(canonical_id(&json!(1)), canonical_id(&json!("1")));
    }

    #[tokio::test]
    async fn route_completes_waiting_post() {
        let state = HttpDownstream::new();
        let (tx, rx) = oneshot::channel();
        state.pending.lock().await.insert("7".to_string(), tx);
        state
            .route_upstream_frame(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#.to_string())
            .await;
        let frame = rx.await.unwrap();
        assert!(frame.contains("\"id\":7"));
    }

    #[tokio::test]
    async fn route_broadcasts_unmatched_frames() {
        let state = HttpDownstream::new();
        let mut sub = state.broadcast.subscribe();
        state
            .route_upstream_frame(
                r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#.to_string(),
            )
            .await;
        let frame = sub.recv().await.unwrap();
        assert!(frame.contains("notifications/progress"));
    }

    #[tokio::test]
    async fn upstream_request_with_id_is_broadcast_not_routed() {
        // A frame with BOTH method and id is an upstream-initiated
        // request (e.g. sampling), not a response -- it must go to SSE.
        let state = HttpDownstream::new();
        let mut sub = state.broadcast.subscribe();
        state
            .route_upstream_frame(
                r#"{"jsonrpc":"2.0","id":9,"method":"sampling/createMessage"}"#.to_string(),
            )
            .await;
        assert!(sub.recv().await.unwrap().contains("sampling/createMessage"));
    }
}

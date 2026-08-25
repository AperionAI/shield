//! Integration coverage for the v0.9 transports, over real sockets:
//!
//! * downstream: `transport::http_server` -- Shield listening as a
//!   Streamable HTTP MCP server (JSON-RPC over POST, GET SSE stream).
//! * upstream: `transport::http_upstream` -- Shield relaying to a remote
//!   Streamable HTTP MCP server (JSON response bodies, SSE response
//!   bodies, session-id echo, transport-error surfacing).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

use aperion_shield::transport::http_server::{self, HttpDownstream, RequestGate};
use aperion_shield::transport::http_upstream::spawn_http_upstream;

// ─────────────────────────────────────────────────────────────────────
// Downstream server tests
// ─────────────────────────────────────────────────────────────────────

/// Gate that blocks `tools/call` for one specific tool and forwards
/// everything else -- a stand-in for the real Shield gate.
struct BlockOneTool(&'static str);

#[async_trait::async_trait]
impl RequestGate for BlockOneTool {
    async fn intercept(&self, req: &Value) -> Option<Value> {
        let method = req.get("method")?.as_str()?;
        if method != "tools/call" {
            return None;
        }
        let tool = req.pointer("/params/name")?.as_str()?;
        if tool == self.0 {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": req.get("id").cloned().unwrap_or(Value::Null),
                "error": {"code": -32099, "message": "shield_blocked", "data": {"tool": tool}}
            }));
        }
        None
    }
}

/// Start the downstream server plus a fake upstream that echoes every
/// request as `{"result": {"echo": <method>}}`. Returns the base URL.
async fn start_downstream(gate: Arc<dyn RequestGate>) -> (String, Arc<HttpDownstream>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = HttpDownstream::new();

    let (to_upstream_tx, mut to_upstream_rx) = mpsc::channel::<String>(16);

    // Fake upstream: respond to every request id with an echo result.
    let pump_state = state.clone();
    tokio::spawn(async move {
        while let Some(frame) = to_upstream_rx.recv().await {
            let parsed: Value = serde_json::from_str(&frame).unwrap();
            if let Some(id) = parsed.get("id") {
                if !id.is_null() {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"echo": parsed.get("method").cloned().unwrap_or(Value::Null)}
                    });
                    pump_state.route_upstream_frame(resp.to_string()).await;
                }
            }
        }
    });

    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = http_server::serve_on(listener, gate, to_upstream_tx, serve_state).await;
    });

    (format!("http://{}", addr), state)
}

#[tokio::test]
async fn http_downstream_round_trips_requests() {
    let (base, _state) = start_downstream(Arc::new(BlockOneTool("never"))).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(&base)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("mcp-session-id").is_some(),
        "initialize response must mint a session id"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body.pointer("/result/echo").unwrap(), "initialize");
}

#[tokio::test]
async fn http_downstream_enforces_gate() {
    let (base, _state) = start_downstream(Arc::new(BlockOneTool("drop_db"))).await;
    let client = reqwest::Client::new();

    // Blocked tool: Shield answers directly with the JSON-RPC error.
    let body: Value = client
        .post(&base)
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "drop_db", "arguments": {}}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.pointer("/error/message").unwrap(), "shield_blocked");

    // Other tools pass through to the upstream echo.
    let body: Value = client
        .post(&base)
        .json(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "fetch", "arguments": {}}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.pointer("/result/echo").unwrap(), "tools/call");
}

#[tokio::test]
async fn http_downstream_accepts_notifications_with_202() {
    let (base, _state) = start_downstream(Arc::new(BlockOneTool("never"))).await;
    let resp = reqwest::Client::new()
        .post(&base)
        .json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
}

#[tokio::test]
async fn http_downstream_rejects_batches() {
    let (base, _state) = start_downstream(Arc::new(BlockOneTool("never"))).await;
    let resp = reqwest::Client::new()
        .post(&base)
        .json(&json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn http_downstream_streams_server_initiated_frames_over_sse() {
    let (base, state) = start_downstream(Arc::new(BlockOneTool("never"))).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(&base)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));

    // Push a notification through the broadcast path (no waiting POST).
    state
        .route_upstream_frame(
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"p":1}}"#.into(),
        )
        .await;

    // Read the first SSE chunk off the live stream.
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("SSE frame within 5s")
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.starts_with("data: "), "SSE framing, got: {}", text);
    assert!(text.contains("notifications/progress"));
}

// ─────────────────────────────────────────────────────────────────────
// Upstream client tests
// ─────────────────────────────────────────────────────────────────────

/// What the fake remote MCP server saw, for assertions.
#[derive(Default)]
struct SeenRequests {
    session_headers: Vec<Option<String>>,
}

/// A minimal remote Streamable HTTP MCP server:
///   * `initialize` -> JSON body + `Mcp-Session-Id: sess-123` header
///   * `tools/list` -> SSE body carrying one event with the response
///   * `tools/call` -> plain JSON body
async fn start_fake_remote() -> (SocketAddr, Arc<Mutex<SeenRequests>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(SeenRequests::default()));

    let seen_task = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let seen = seen.clone();
                    async move { Ok::<_, Infallible>(fake_remote_handler(req, seen).await) }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, seen)
}

async fn fake_remote_handler(
    req: Request<Incoming>,
    seen: Arc<Mutex<SeenRequests>>,
) -> Response<Full<Bytes>> {
    let session = req
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    seen.lock().await.session_headers.push(session);

    if req.method() == hyper::Method::GET {
        // No server-initiated stream on this fake.
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }

    let body = req.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => {
            let resp = json!({"jsonrpc": "2.0", "id": id,
                              "result": {"capabilities": {}, "serverInfo": {"name": "fake"}}});
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("mcp-session-id", "sess-123")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap()
        }
        "tools/list" => {
            // Respond over SSE: one notification event, then the response.
            let note =
                json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"p": 1}});
            let resp = json!({"jsonrpc": "2.0", "id": id,
                              "result": {"tools": [{"name": "fetch", "description": "Fetch a URL"}]}});
            let sse = format!("data: {}\n\ndata: {}\n\n", note, resp);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Full::new(Bytes::from(sse)))
                .unwrap()
        }
        "" => {
            // Notification from the client: 202, no body.
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
        _ => {
            let resp =
                json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true, "method": method}});
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap()
        }
    }
}

#[tokio::test]
async fn http_upstream_relays_json_and_sse_responses() {
    let (addr, seen) = start_fake_remote().await;
    let mut up = spawn_http_upstream(&format!("http://{}/mcp", addr), vec![]).unwrap();

    // 1. initialize -> JSON body, captures session.
    up.tx
        .send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).to_string())
        .await
        .unwrap();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), up.rx.recv())
        .await
        .expect("initialize response")
        .unwrap();
    let parsed: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(parsed.pointer("/result/serverInfo/name").unwrap(), "fake");

    // 2. tools/list -> SSE body: the notification event arrives first,
    //    then the actual response. Both must surface as frames.
    up.tx
        .send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string())
        .await
        .unwrap();
    let f1 = tokio::time::timeout(std::time::Duration::from_secs(5), up.rx.recv())
        .await
        .expect("sse frame 1")
        .unwrap();
    let f2 = tokio::time::timeout(std::time::Duration::from_secs(5), up.rx.recv())
        .await
        .expect("sse frame 2")
        .unwrap();
    assert!(f1.contains("notifications/progress"));
    assert!(f2.contains("\"tools\""));

    // 3. The tools/list POST must have echoed the session id from init.
    let seen = seen.lock().await;
    assert!(seen.session_headers.len() >= 2);
    assert_eq!(
        seen.session_headers[0], None,
        "initialize has no session yet"
    );
    assert_eq!(
        seen.session_headers[1].as_deref(),
        Some("sess-123"),
        "subsequent requests echo the server-assigned session id"
    );
}

#[tokio::test]
async fn http_upstream_surfaces_transport_errors_as_jsonrpc() {
    // Point at a port nobody listens on -- requests must come back as
    // JSON-RPC transport errors instead of leaving the host hanging.
    let dead = {
        // Bind+drop to find a port that is closed right now.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let mut up = spawn_http_upstream(&format!("http://{}/mcp", dead), vec![]).unwrap();
    up.tx
        .send(json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).to_string())
        .await
        .unwrap();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(15), up.rx.recv())
        .await
        .expect("error frame")
        .unwrap();
    let parsed: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(parsed.get("id").unwrap(), 7);
    assert_eq!(
        parsed.pointer("/error/message").unwrap(),
        "shield_upstream_transport_error"
    );
}

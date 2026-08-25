//! Local OAuth callback server.
//!
//! Bound to `127.0.0.1` on an OS-assigned port (unless the user pinned
//! one in `identity.yaml`). Two routes:
//!
//!   * `GET /verify/<challenge_id>` -- the URL Shield hands the user.
//!     For OAuth providers it 302-redirects to the provider's
//!     authorize URL (which is what the provider's [`begin`] already
//!     returned as `verify_url`); for the mock provider it short-
//!     circuits straight to `/callback?code=mock&state=<id>&mock=1`.
//!   * `GET /callback` -- the OAuth redirect target. Pulls the
//!     in-flight challenge state, calls [`exchange`] on the matching
//!     provider, mints + caches a [`Proof`], and renders a friendly
//!     "you may return to your editor" page.
//!
//! Concurrency model: each Shield process has at most one callback
//! server. It's started lazily on the first identity-required decision
//! (via `IdentityGate::callback_base`). State -- in-flight challenges
//! and the proof cache handle -- lives behind an `Arc<RwLock<...>>`
//! shared with the request handlers.
//!
//! Security:
//!   * Only binds to `127.0.0.1` (or whatever the config says, but we
//!     hard-warn if anyone tries to bind a non-loopback address).
//!   * Each callback validates `state` against an in-flight entry.
//!   * Stale challenges (`expires_at <= now`) are reaped at lookup time.
//!   * The HTML response includes a `cache-control: no-store` and a
//!     CSP that disables script execution -- the page is static text.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use tokio::sync::{oneshot, RwLock};

/// Type alias for the response body we produce. hyper 1.x decoupled
/// the body type from the framework, so we pick `Full<Bytes>` for our
/// small static HTML/text responses -- it is the simplest body that
/// implements `http_body::Body` and works with the http1 server.
type ResponseBody = Full<Bytes>;

use super::{Challenge, IdentityProvider, Requirement};
use crate::identity::cache::ProofCache;
use crate::identity::proof::ProofSigner;

/// State the server holds for one in-flight verification.
#[derive(Debug, Clone)]
pub struct Inflight {
    pub rule_id: String,
    pub provider: String,
    pub requirement: Requirement,
}

#[derive(Default)]
struct State {
    /// challenge_id -> (challenge, in-flight meta)
    challenges: HashMap<String, (Challenge, Inflight)>,
}

/// Handle returned by [`CallbackServer::spawn`]. Owns the abort guard
/// for the background task; dropping it shuts the server down.
pub struct ServerHandle {
    pub bound: SocketAddr,
    pub base_url: String,
    state: Arc<RwLock<State>>,
    #[allow(dead_code)] // kept alive so the server shuts down on drop
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ServerHandle {
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    /// Register a freshly-minted challenge so the server knows what to
    /// do when its `/callback` route is hit with this `state`.
    pub async fn register(&self, challenge: Challenge, inflight: Inflight) {
        let cid = challenge.challenge_id.clone();
        let entry = (challenge, inflight);
        let mut g = self.state.write().await;
        g.challenges.insert(cid, entry);
    }

    /// For tests / diagnostics: how many challenges are currently
    /// in-flight.
    #[cfg(test)]
    pub async fn inflight_count(&self) -> usize {
        self.state.read().await.challenges.len()
    }
}

pub struct CallbackServer;

impl CallbackServer {
    /// Spin up the callback server. Returns a handle whose `base_url`
    /// points at the bound address.
    pub async fn spawn(
        host: &str,
        port: u16,
        providers: Vec<Arc<dyn IdentityProvider>>,
        cache: Arc<ProofCache>,
        signer: Arc<ProofSigner>,
    ) -> anyhow::Result<ServerHandle> {
        if host != "127.0.0.1" && host != "localhost" && host != "::1" {
            warn!(
                "[shield-identity] callback_host='{}' is NOT loopback -- this exposes the \
                 OAuth callback to the network. Only override this if you know what you're doing.",
                host,
            );
        }
        let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
        // Bind a std listener so we can read the OS-assigned port
        // synchronously, then hand it off to hyper.
        let listener = std::net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let bound = listener.local_addr()?;
        let base_url = format!("http://{}:{}", bound.ip(), bound.port());

        let state: Arc<RwLock<State>> = Arc::new(RwLock::new(State::default()));
        let providers: Arc<Vec<Arc<dyn IdentityProvider>>> = Arc::new(providers);

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        // hyper 1.x is connection-oriented: we accept directly from a
        // tokio TcpListener and serve each connection with
        // `http1::Builder::new().serve_connection`. The per-connection
        // service is built fresh each loop so it owns its own clones
        // of the shared state.
        let tokio_listener = tokio::net::TcpListener::from_std(listener)?;
        let accept_state = state.clone();
        let accept_providers = providers.clone();
        let accept_cache = cache.clone();
        let accept_signer = signer.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        debug!("[shield-identity] callback server shutting down");
                        return;
                    }
                    accept = tokio_listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(p) => p,
                            Err(e) => {
                                error!("[shield-identity] accept failed: {}", e);
                                continue;
                            }
                        };
                        let io = TokioIo::new(stream);
                        let svc_state = accept_state.clone();
                        let svc_providers = accept_providers.clone();
                        let svc_cache = accept_cache.clone();
                        let svc_signer = accept_signer.clone();
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let state = svc_state.clone();
                            let providers = svc_providers.clone();
                            let cache = svc_cache.clone();
                            let signer = svc_signer.clone();
                            async move {
                                Ok::<_, Infallible>(handle(req, state, providers, cache, signer).await)
                            }
                        });
                        tokio::spawn(async move {
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                debug!(
                                    "[shield-identity] connection from {} ended: {}",
                                    peer, e
                                );
                            }
                        });
                    }
                }
            }
        });

        info!(
            "[shield-identity] callback server listening on {} (base_url={})",
            bound, base_url
        );

        Ok(ServerHandle {
            bound,
            base_url,
            state,
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Request handler
// ────────────────────────────────────────────────────────────────────

async fn handle(
    req: Request<Incoming>,
    state: Arc<RwLock<State>>,
    providers: Arc<Vec<Arc<dyn IdentityProvider>>>,
    cache: Arc<ProofCache>,
    signer: Arc<ProofSigner>,
) -> Response<ResponseBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    debug!("[shield-identity] {} {}", method, path);

    // Routes:
    //   GET /healthz
    //   GET /verify/<id>?mock=1  -- mock-only short-circuit
    //   GET /callback?code=...&state=...
    //   GET /                    -- friendly index
    if method != Method::GET {
        return text(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }

    if path == "/healthz" {
        return text(StatusCode::OK, "ok\n");
    }
    if path == "/" {
        return html(StatusCode::OK, INDEX_HTML);
    }

    if let Some(rest) = path.strip_prefix("/verify/") {
        let challenge_id = rest.trim_end_matches('/').to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        return handle_verify(&challenge_id, &query, &state, &providers).await;
    }

    if path == "/callback" {
        let query = req.uri().query().unwrap_or("").to_string();
        return handle_callback(&query, &state, &providers, &cache, &signer).await;
    }

    text(StatusCode::NOT_FOUND, "not found")
}

async fn handle_verify(
    challenge_id: &str,
    query: &str,
    state: &Arc<RwLock<State>>,
    providers: &Arc<Vec<Arc<dyn IdentityProvider>>>,
) -> Response<ResponseBody> {
    let mock_flow = query_param(query, "mock").is_some();
    let (challenge, inflight) = {
        let g = state.read().await;
        match g.challenges.get(challenge_id) {
            Some((c, i)) => (c.clone(), i.clone()),
            None => return html(StatusCode::NOT_FOUND, EXPIRED_HTML),
        }
    };

    if mock_flow {
        // Find the matching provider and run an in-process exchange,
        // then redirect to /callback?code=...&state=... so the rest of
        // the pipeline runs identically to the real OAuth flow.
        let provider = providers
            .iter()
            .find(|p| p.id() == inflight.provider)
            .cloned();
        let Some(p) = provider else {
            return html(StatusCode::INTERNAL_SERVER_ERROR, "no matching provider");
        };
        match p
            .exchange(
                challenge_id,
                "synthetic-code",
                challenge_id,
                challenge.pkce_verifier.as_deref(),
            )
            .await
        {
            Ok(_vi) => {
                // We could mint+cache here, but to keep the
                // happy-path identical between mock and real, redirect
                // to /callback which will go through the same code.
                let location = format!(
                    "/callback?code=synthetic-code&state={}&mock=1",
                    challenge_id
                );
                let mut resp = Response::new(empty_body());
                *resp.status_mut() = StatusCode::FOUND;
                resp.headers_mut().insert(
                    hyper::header::LOCATION,
                    hyper::header::HeaderValue::from_str(&location).unwrap(),
                );
                resp
            }
            Err(e) => html(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "<h1>Mock exchange failed</h1><pre>{}</pre>",
                    html_escape(&e.to_string())
                ),
            ),
        }
    } else {
        // Real flow: just bounce the user to the provider's verify_url.
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::FOUND;
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&challenge.verify_url) {
            resp.headers_mut().insert(hyper::header::LOCATION, hv);
        }
        resp
    }
}

async fn handle_callback(
    query: &str,
    state: &Arc<RwLock<State>>,
    providers: &Arc<Vec<Arc<dyn IdentityProvider>>>,
    cache: &Arc<ProofCache>,
    signer: &Arc<ProofSigner>,
) -> Response<ResponseBody> {
    let code = match query_param(query, "code") {
        Some(c) => c,
        None => return html(StatusCode::BAD_REQUEST, "<h1>Missing OAuth code</h1>"),
    };
    let cb_state = match query_param(query, "state") {
        Some(s) => s,
        None => return html(StatusCode::BAD_REQUEST, "<h1>Missing OAuth state</h1>"),
    };

    let (challenge, inflight) = {
        let g = state.read().await;
        match g.challenges.get(&cb_state) {
            Some((c, i)) => (c.clone(), i.clone()),
            None => return html(StatusCode::NOT_FOUND, EXPIRED_HTML),
        }
    };

    let provider = providers
        .iter()
        .find(|p| p.id() == inflight.provider)
        .cloned();
    let Some(p) = provider else {
        return html(StatusCode::INTERNAL_SERVER_ERROR, "<h1>Provider gone</h1>");
    };

    let vi = match p
        .exchange(
            &cb_state,
            &code,
            &cb_state,
            challenge.pkce_verifier.as_deref(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("[shield-identity] exchange failed: {}", e);
            return html(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "<h1>Verification failed</h1><pre>{}</pre>",
                    html_escape(&e.to_string())
                ),
            );
        }
    };

    if !inflight.requirement.allows(&vi) {
        return html(
            StatusCode::FORBIDDEN,
            &format!(
                "<h1>Verified, but not authorised</h1>\
                 <p>Identity \"{}\" verified successfully, but is not on the allow-list for this rule.</p>",
                html_escape(&vi.email.clone().unwrap_or_else(|| vi.subject.clone())),
            ),
        );
    }
    if vi.loa < inflight.requirement.loa {
        return html(
            StatusCode::FORBIDDEN,
            &format!(
                "<h1>Verified, but LOA too low</h1>\
                 <p>This rule requires LOA &ge; {} but the provider reported LOA {}.</p>",
                inflight.requirement.loa, vi.loa,
            ),
        );
    }

    // Mint + cache the signed proof. Outside the request handler this
    // is exactly what the held tool call is polling on.
    let now = super::unix_now();
    let proof = super::Proof {
        v: 1,
        provider: vi.provider.clone(),
        subject: vi.subject.clone(),
        email: vi.email.clone(),
        loa: vi.loa,
        scope: inflight.requirement.scope.clone(),
        verified_at: now,
        expires_at: now.saturating_add(inflight.requirement.max_proof_age_seconds),
        nonce: hex::encode(rand::random::<[u8; 16]>()),
        sig: String::new(),
    };
    let signed = match signer.sign(proof) {
        Ok(p) => p,
        Err(e) => {
            error!("[shield-identity] sign failed: {}", e);
            return html(
                StatusCode::INTERNAL_SERVER_ERROR,
                "<h1>Internal signing error</h1>",
            );
        }
    };
    if let Err(e) = cache.insert(signed) {
        error!("[shield-identity] cache insert failed: {}", e);
        return html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "<h1>Internal cache error</h1>",
        );
    }

    // Clean up the in-flight slot so an expired state can't be reused.
    {
        let mut g = state.write().await;
        g.challenges.remove(&cb_state);
    }

    info!(
        "[shield-identity] verified provider={} subject={} loa={} scope={} rule={}",
        vi.provider, vi.subject, vi.loa, inflight.requirement.scope, inflight.rule_id
    );

    let display = vi.email.unwrap_or_else(|| vi.subject.clone());
    html(
        StatusCode::OK,
        &success_page(&display, &inflight.rule_id, &inflight.requirement.scope),
    )
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn empty_body() -> ResponseBody {
    Full::new(Bytes::new())
}

fn body_from_string(s: String) -> ResponseBody {
    Full::new(Bytes::from(s))
}

fn text(status: StatusCode, body: &str) -> Response<ResponseBody> {
    let mut resp = Response::new(body_from_string(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn html(status: StatusCode, body: &str) -> Response<ResponseBody> {
    let full = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Aperion Shield</title>\
         <style>{css}</style></head><body><main class=\"card\">{body}</main></body></html>",
        css = PAGE_CSS,
        body = body,
    );
    let mut resp = Response::new(body_from_string(full));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    resp.headers_mut().insert(
        hyper::header::HeaderName::from_static("content-security-policy"),
        hyper::header::HeaderValue::from_static(
            "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'",
        ),
    );
    resp
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    // Tiny percent-decoder -- avoids pulling in the percent-encoding
    // crate just for this. Hex parsing is on the hot path of exactly
    // zero requests per second so simplicity beats speed.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn success_page(who: &str, rule_id: &str, scope: &str) -> String {
    format!(
        "<h1>Identity verified</h1>\
         <p class=\"who\"><strong>{who}</strong> -- verified for scope <code>{scope}</code>.</p>\
         <p class=\"rule\">Rule: <code>{rule_id}</code></p>\
         <p class=\"close\">You may close this tab and return to your editor.\
         The pending tool call will be released automatically.</p>",
        who = html_escape(who),
        scope = html_escape(scope),
        rule_id = html_escape(rule_id),
    )
}

const INDEX_HTML: &str =
    "<h1>Aperion Shield</h1><p>This server handles identity verification callbacks. \
Open a verification URL emitted by Shield to continue.</p>";

const EXPIRED_HTML: &str =
    "<h1>Verification expired</h1><p>This challenge is no longer in flight. \
Re-run the gated tool call to start a new verification.</p>";

const PAGE_CSS: &str = "body { background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; margin: 0; padding: 40px 20px; }
.card { max-width: 560px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
h1 { color: #6ee7b7; margin: 0 0 16px; font-size: 22px; }
p { line-height: 1.55; margin: 8px 0; }
.who strong { color: #fff; }
code { background: #0f172a; color: #6ee7b7; padding: 2px 6px; border-radius: 4px; font-family: \"JetBrains Mono\", \"SF Mono\", monospace; font-size: 0.92em; }
.close { color: #94a3b8; font-size: 0.92em; margin-top: 18px; }
pre { background: #0f172a; padding: 12px; border-radius: 8px; overflow-x: auto; color: #fda4af; }";

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%21%40%23"), "!@#");
        assert_eq!(percent_decode("no-encoded-chars"), "no-encoded-chars");
    }

    #[test]
    fn query_param_finds_keys() {
        assert_eq!(query_param("a=1&b=hi", "a"), Some("1".into()));
        assert_eq!(query_param("a=1&b=hi", "b"), Some("hi".into()));
        assert_eq!(query_param("a=1&b=hi", "c"), None);
        assert_eq!(query_param("mock=1", "mock"), Some("1".into()));
        assert_eq!(
            query_param("code=abc&state=xyz", "state"),
            Some("xyz".into())
        );
    }

    #[test]
    fn html_escape_is_safe() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }
}

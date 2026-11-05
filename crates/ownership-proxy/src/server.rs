use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version,
        header::CONNECTION,
    },
    response::IntoResponse,
};
use hyper::{
    body::{Body as HttpBody, Frame, Incoming, SizeHint},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::graceful::GracefulShutdown,
};
use ownership_token::{OwnershipLayer, Rejection, RemoteJwks, TokenVerifier, VerifiedOwnership};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tower::{Layer as _, Service, ServiceExt as _};

use crate::config::Config;
use tracing::Instrument as _;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Clone)]
struct Forward {
    client: Client<HttpConnector, Body>,
    upstream: Uri,
    timeout: Duration,
}

impl Forward {
    fn new(config: &Config) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(config.upstream_connect_timeout));
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            upstream: config.upstream.uri().clone(),
            timeout: config.upstream_response_timeout,
        }
    }

    async fn call(&self, mut request: Request<Body>) -> Response<Body> {
        let verified = request.extensions().get::<VerifiedOwnership>().cloned();
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .expect("request ID is set")
            .0
            .clone();
        strip_hop_headers(request.headers_mut());
        // A client can name x-request-id in Connection, so insert it after stripping.
        request
            .headers_mut()
            .insert("x-request-id", request_id.clone());
        if let Some(verified) = verified {
            let subject = HeaderValue::from_str(verified.0.sub.as_str())
                .expect("subject is always a valid header value");
            let audience = HeaderValue::from_str(verified.0.aud.as_str())
                .expect("audience is always a valid header value");
            request.headers_mut().insert("x-world-id-subject", subject);
            request
                .headers_mut()
                .insert("x-world-id-audience", audience);
            metrics::counter!("ownership_proxy.requests.verified").increment(1);
        }
        let mut parts = self.upstream.clone().into_parts();
        parts.path_and_query = Some(
            request
                .uri()
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/")),
        );
        *request.uri_mut() =
            Uri::from_parts(parts).expect("configured origin and request path form a valid URI");
        *request.version_mut() = Version::HTTP_11;
        let request_id = request_id.to_str().expect("request ID is valid ASCII");
        let body_failed = request
            .extensions()
            .get::<ClientBodyState>()
            .expect("incoming body state")
            .clone();
        // The response deadline covers the whole exchange, including the upload.
        let result = tokio::time::timeout(self.timeout, self.client.request(request)).await;
        let timed_out = body_failed.timed_out.clone();
        let mut response = match result {
            Ok(Ok(response)) if response.status() != StatusCode::SWITCHING_PROTOCOLS => {
                response.map(Body::new)
            }
            Ok(Ok(_)) => {
                upstream_failure("other", "unsupported upstream protocol upgrade", request_id)
            }
            Ok(Err(_error)) if timed_out.load(Ordering::Relaxed) => {
                metrics::counter!("ownership_proxy.requests.client_timeout").increment(1);
                error_response(StatusCode::REQUEST_TIMEOUT, "client_timeout")
            }
            Ok(Err(_error)) if body_failed.failed.load(Ordering::Relaxed) => {
                metrics::counter!("ownership_proxy.requests.client_aborted").increment(1);
                error_response(StatusCode::BAD_GATEWAY, "upstream_unavailable")
            }
            Ok(Err(error)) => {
                let class = if error.is_connect() {
                    "connect"
                } else {
                    "other"
                };
                upstream_failure(class, &format!("{error:?}"), request_id)
            }
            Err(_) => upstream_failure("timeout", "upstream response deadline elapsed", request_id),
        };
        strip_hop_headers(response.headers_mut());
        response
    }
}

pub(crate) async fn serve(
    listener: TcpListener,
    config: Config,
    verifier: Arc<TokenVerifier>,
    jwks: RemoteJwks,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let forward = Forward::new(&config);
    let body_read_timeout = config.body_read_timeout;
    let service = tower::service_fn(move |request| {
        let forward = forward.clone();
        async move { Ok::<_, Infallible>(forward.call(request).await) }
    });
    let layer =
        OwnershipLayer::new(verifier, jwks).with_unprotected_paths(config.unprotected_paths);
    let grace = config.shutdown_grace;
    let protected = layer.clone().layer(service);
    let slots = Arc::new(Semaphore::new(config.max_connections.get()));
    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();
    loop {
        let permit = tokio::select! {
            permit = slots.clone().acquire_owned() => permit.expect("connection semaphore stays open"),
            _ = stop.changed() => break,
        };
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = stop.changed() => break,
        };
        let (stream, _) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                if !keep_accepting(&error, &mut stop).await {
                    break;
                }
                continue;
            }
        };
        let protected = protected.clone();
        let layer = layer.clone();
        let service = service_fn(move |request: Request<Incoming>| {
            let route_class = if layer.is_unprotected(request.uri().path()) {
                "unprotected"
            } else {
                "protected"
            };
            handle(protected.clone(), request, route_class, body_read_timeout)
        });
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let connection = graceful.watch(builder.serve_connection(TokioIo::new(stream), service));
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = connection.await {
                tracing::debug!(%error, "client connection closed");
            }
        });
        reap_connections(&mut connections);
    }
    drop(listener);
    drain(graceful, connections, grace).await;
    Ok(())
}

async fn handle<S>(
    protected: S,
    request: Request<Incoming>,
    route_class: &'static str,
    body_read_timeout: Duration,
) -> Result<Response<Body>, Infallible>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let request_id = request_id(request.headers());
    let span = tracing::info_span!(
        "ownership_proxy.request", request_id = %request_id.to_str().expect("validated request ID"), http.method = %request.method(),
        route_class, http.status_code = tracing::field::Empty, rejection_reason = tracing::field::Empty
    );
    async move {
        let started = Instant::now();
        let body_state = ClientBodyState {
            failed: Arc::new(AtomicBool::new(false)),
            timed_out: Arc::new(AtomicBool::new(false)),
        };
        let mut request = request.map(|body| {
            Body::new(TrackedBody {
                body,
                failed: body_state.failed.clone(),
                timed_out: body_state.timed_out.clone(),
                idle_timeout: body_read_timeout,
                idle_timer: None,
            })
        });
        request.extensions_mut().insert(body_state);
        request
            .extensions_mut()
            .insert(RequestId(request_id.clone()));
        let mut response = protected
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
        metrics::histogram!("ownership_proxy.http.duration", "histogram" => "distribution")
            .record(started.elapsed().as_secs_f64());
        record_rejection(&mut response);
        tracing::Span::current().record("http.status_code", response.status().as_u16());
        response.headers_mut().insert("x-request-id", request_id);
        Ok(response)
    }
    .instrument(span)
    .await
}

#[derive(Clone)]
struct RequestId(HeaderValue);

#[derive(Clone)]
struct ClientBodyState {
    failed: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
}

struct TrackedBody {
    body: Incoming,
    failed: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    idle_timeout: Duration,
    idle_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[derive(Debug, thiserror::Error)]
enum ClientBodyError {
    #[error("incoming body failed")]
    Incoming(#[source] hyper::Error),
    #[error("incoming body idle timeout")]
    Timeout,
}

impl HttpBody for TrackedBody {
    type Data = axum::body::Bytes;
    type Error = ClientBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(frame) => {
                self.idle_timer = None;
                Poll::Ready(frame.map(|result| {
                    result.map_err(|error| {
                        self.failed.store(true, Ordering::Relaxed);
                        ClientBodyError::Incoming(error)
                    })
                }))
            }
            Poll::Pending => {
                let timeout = self.idle_timeout;
                let timer = self
                    .idle_timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                if timer.as_mut().poll(cx).is_ready() {
                    self.timed_out.store(true, Ordering::Relaxed);
                    Poll::Ready(Some(Err(ClientBodyError::Timeout)))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

fn record_rejection(response: &mut Response<Body>) {
    if let Some(rejection) = response.extensions_mut().remove::<Rejection>() {
        let reason = rejection.reason();
        tracing::Span::current().record("rejection_reason", reason);
        metrics::counter!("ownership_proxy.requests.rejected", "reason" => reason).increment(1);
    }
}

fn reap_connections(connections: &mut JoinSet<()>) {
    while let Some(result) = connections.try_join_next() {
        if let Err(error) = result {
            tracing::warn!(%error, "client connection task failed");
        }
    }
}

async fn keep_accepting(error: &std::io::Error, stop: &mut watch::Receiver<bool>) -> bool {
    metrics::counter!("ownership_proxy.listener.accept_errors").increment(1);
    tracing::warn!(%error, "proxy accept failed");
    if !matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
    ) {
        tokio::select! {
            () = tokio::time::sleep(ACCEPT_BACKOFF) => {},
            _ = stop.changed() => return false,
        }
    }
    true
}

async fn drain(graceful: GracefulShutdown, mut connections: JoinSet<()>, grace: Duration) {
    if tokio::time::timeout(grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("proxy shutdown timed out; aborting connections");
        connections.abort_all();
    }
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            tracing::warn!(%error, "client connection task failed");
        }
    }
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn request_id(headers: &HeaderMap) -> HeaderValue {
    if let Some(value) = headers.get("x-request-id").and_then(|v| v.to_str().ok())
        && !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return HeaderValue::from_str(value).expect("validated request ID");
    }
    HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).expect("UUID is a valid header")
}

fn error_response(status: StatusCode, code: &'static str) -> Response<Body> {
    (
        status,
        axum::Json(serde_json::json!({"error": {"code": code, "message": "Request failed"}})),
    )
        .into_response()
}

fn upstream_failure(class: &'static str, cause: &str, request_id: &str) -> Response<Body> {
    metrics::counter!("ownership_proxy.upstream.errors", "class" => class).increment(1);
    tracing::warn!(class, cause, request_id, "upstream request failed");
    error_response(StatusCode::BAD_GATEWAY, "upstream_unavailable")
}

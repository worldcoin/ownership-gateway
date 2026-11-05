//! Request tracing, HTTP and dependency metrics, and log formatting.

use std::{error::Error, fmt};

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore as _, rngs::OsRng};
use tokio::time::Instant;
use tracing::Instrument as _;

/// A remote dependency, as named in the `dep` metric tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dependency {
    Redis,
    Root,
    Kms,
}

impl Dependency {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Redis => "redis",
            Self::Root => "root",
            Self::Kms => "kms",
        }
    }
}

/// How a dependency call failed, as named in the `class` metric tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Timeout,
    Server,
    Connect,
    Throttled,
    Other,
}

impl FailureClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Server => "5xx",
            Self::Connect => "connect",
            Self::Throttled => "throttled",
            Self::Other => "other",
        }
    }
}

/// Records the duration of a call that started at `started` and, if it failed, its failure class.
pub(crate) fn record_call(
    dependency: Dependency,
    started: Instant,
    outcome: Result<(), FailureClass>,
) {
    metrics::histogram!("ownership_gateway.dependency.duration", "dep" => dependency.as_str())
        .record(started.elapsed().as_secs_f64());
    if let Err(class) = outcome {
        metrics::counter!(
            "ownership_gateway.dependency.errors",
            "dep" => dependency.as_str(),
            "class" => class.as_str()
        )
        .increment(1);
    }
}

/// Sets the `ready{component}` gauge for a dependency.
pub(crate) fn set_ready(component: Dependency, ready: bool) {
    metrics::gauge!("ownership_gateway.ready", "component" => component.as_str()).set(if ready {
        1.0
    } else {
        0.0
    });
}

/// Formats an error followed by its sources, separated by `: `.
pub(crate) struct ErrorChain<'a>(pub(crate) &'a (dyn Error + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(error) = source {
            write!(f, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}

/// Runs a request in a span with a random request ID, then records
/// `http.requests{route,status_class}` and the `http.duration{route}` distribution. `route` is the
/// matched route template, or `unmatched`.
pub(crate) async fn observe_request(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let mut request_id = [0_u8; 16];
    OsRng.fill_bytes(&mut request_id);
    let span = tracing::info_span!(
        "request",
        request_id = %URL_SAFE_NO_PAD.encode(request_id),
        route = %route
    );
    let started = Instant::now();
    let response = next.run(request).instrument(span).await;
    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };
    metrics::counter!(
        "ownership_gateway.http.requests",
        "route" => route.clone(),
        "status_class" => status_class
    )
    .increment(1);
    // The `histogram` tag makes the DogStatsD exporter send a distribution.
    metrics::histogram!(
        "ownership_gateway.http.duration",
        "route" => route,
        "histogram" => "distribution"
    )
    .record(started.elapsed().as_secs_f64());
    response
}

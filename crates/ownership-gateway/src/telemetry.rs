//! Telemetry setup, request tracing, HTTP and dependency metrics, and log formatting.

use std::{error::Error, fmt};

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{WrapErr as _, eyre};
use metrics_exporter_statsd::{StatsdBuilder, StatsdError, StatsdRecorder};
use rand::{RngCore as _, rngs::OsRng};
use telemetry_batteries::{MetricsBackend, StatsdConfig, TelemetryConfig, TelemetryGuard};
use tokio::time::Instant;
use tracing::Instrument as _;

/// The tags every metric carries, each with the variable it comes from: Datadog's unified
/// service tags, and the pod UID, from which the Datadog agent adds the pod's own tags
/// (`kube_namespace`, `pod_name` and so on) to metrics that arrive over UDP.
const DEFAULT_TAGS: [(&str, &str); 4] = [
    ("service", "DD_SERVICE"),
    ("env", "DD_ENV"),
    ("version", "DD_VERSION"),
    ("dd.internal.entity_id", "DD_ENTITY_ID"),
];

/// A default tag variable whose value would break the `DogStatsD` line format.
#[derive(Debug, thiserror::Error)]
#[error("{0} must not contain whitespace, ',' or '|'")]
pub struct InvalidTagValue(&'static str);

/// Initializes logging, tracing and metrics from the `TELEMETRY_*` variables of
/// `telemetry-batteries`.
///
/// With `TELEMETRY_METRICS_BACKEND=statsd`, the gateway installs the `StatsD` recorder itself, so
/// that every metric carries `service`, `env` and `version` from `DD_SERVICE`, `DD_ENV` and
/// `DD_VERSION`, and `dd.internal.entity_id` from `DD_ENTITY_ID`. An unset or empty variable
/// adds no tag. The recorder sends to `TELEMETRY_STATSD_HOST`:`TELEMETRY_STATSD_PORT` with the
/// prefix `TELEMETRY_STATSD_PREFIX`, as the `telemetry-batteries` one would.
///
/// # Errors
///
/// Returns an error if a variable is invalid or a backend cannot start.
pub fn init() -> eyre::Result<TelemetryGuard> {
    let mut config = TelemetryConfig::from_env()?;
    let statsd = if config.metrics.backend == MetricsBackend::Statsd {
        config.metrics.backend = MetricsBackend::None;
        let tags = default_tags(|variable| std::env::var(variable).ok())?;
        Some(
            statsd_recorder(&config.metrics.statsd, tags)
                .wrap_err("building the StatsD recorder")?,
        )
    } else {
        None
    };
    let guard = telemetry_batteries::init_with_config(config)?;
    if let Some(recorder) = statsd {
        metrics::set_global_recorder(recorder)
            .map_err(|_| eyre!("a metrics recorder is already installed"))?;
    }
    Ok(guard)
}

/// Returns the [`DEFAULT_TAGS`] whose variable `env` holds a nonempty value for.
fn default_tags(
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(&'static str, String)>, InvalidTagValue> {
    let mut tags = Vec::new();
    for (tag, variable) in DEFAULT_TAGS {
        let Some(value) = env(variable).filter(|value| !value.is_empty()) else {
            continue;
        };
        if value.contains(|c: char| c.is_whitespace() || c.is_control() || matches!(c, ',' | '|')) {
            return Err(InvalidTagValue(variable));
        }
        tags.push((tag, value));
    }
    Ok(tags)
}

fn statsd_recorder(
    config: &StatsdConfig,
    tags: Vec<(&'static str, String)>,
) -> Result<StatsdRecorder, StatsdError> {
    tags.into_iter()
        .fold(
            StatsdBuilder::from(config.host.as_str(), config.port)
                .with_queue_size(config.queue_size)
                .with_buffer_size(config.buffer_size),
            |builder, (tag, value)| builder.with_default_tag(tag, value),
        )
        .build(config.prefix.as_deref())
}

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

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use super::*;

    #[test]
    fn statsd_metrics_carry_the_default_tags() {
        let agent = UdpSocket::bind("127.0.0.1:0").unwrap();
        agent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let env = |variable: &str| match variable {
            "DD_SERVICE" => Some("ownership-gateway".to_owned()),
            "DD_ENV" => Some("stage".to_owned()),
            "DD_VERSION" => Some(String::new()),
            "DD_ENTITY_ID" => Some("0b1e6a5c-pod-uid".to_owned()),
            _ => None,
        };
        let config = StatsdConfig {
            host: "127.0.0.1".to_owned(),
            port: agent.local_addr().unwrap().port(),
            prefix: None,
            queue_size: 16,
            // Sends each metric in its own datagram instead of buffering it.
            buffer_size: 1,
        };
        let recorder = statsd_recorder(&config, default_tags(env).unwrap()).unwrap();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("ownership_gateway.tokens.issued", "aud" => "service-a").increment(1);
        });
        let mut datagram = [0_u8; 512];
        let length = agent.recv(&mut datagram).unwrap();
        assert_eq!(
            std::str::from_utf8(&datagram[..length]).unwrap(),
            "ownership_gateway.tokens.issued:1|c|#service:ownership-gateway,env:stage,\
             dd.internal.entity_id:0b1e6a5c-pod-uid,aud:service-a"
        );
    }

    #[test]
    fn default_tags_reject_values_that_break_the_line_format() {
        assert!(default_tags(|_| None).unwrap().is_empty());
        for value in ["a,b", "a|b", "a b", "a\nb"] {
            assert!(
                default_tags(|variable| (variable == "DD_ENV").then(|| value.to_owned())).is_err(),
                "{value:?}"
            );
        }
    }
}

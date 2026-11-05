//! Sidecar settings from command-line arguments or environment variables.

use clap::Parser;
use http::Uri;
use ownership_token::{Audience, Issuer, JwksUrl, UnprotectedPath};
use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Configuration for the ownership verification sidecar.
#[derive(Debug, Clone, Parser)]
#[command(version)]
pub struct Config {
    /// Address for proxied traffic.
    #[arg(long, env = "OWNERSHIP_PROXY_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Address for health probes.
    #[arg(
        long,
        env = "OWNERSHIP_PROXY_ADMIN_LISTEN",
        default_value = "0.0.0.0:8081"
    )]
    pub admin_listen: SocketAddr,

    /// Application origin, as `http://host:port`.
    #[arg(long, env = "OWNERSHIP_PROXY_UPSTREAM")]
    pub upstream: UpstreamOrigin,

    /// Exact issuer URL expected in ownership tokens.
    #[arg(long, env = "OWNERSHIP_PROXY_ISSUER")]
    pub issuer: Issuer,

    /// Trusted JWKS endpoint.
    #[arg(long, env = "OWNERSHIP_PROXY_JWKS_URL")]
    pub jwks_url: JwksUrl,

    /// Accepted audiences, separated by commas; multiple values allow a migration without downtime.
    #[arg(
        long,
        env = "OWNERSHIP_PROXY_AUDIENCES",
        value_delimiter = ',',
        required = true
    )]
    pub audiences: Vec<Audience>,

    /// Exact paths forwarded without verification, separated by commas.
    /// Use for health checks, not application routes.
    #[arg(long, env = "OWNERSHIP_PROXY_UNPROTECTED_PATHS", value_delimiter = ',')]
    pub unprotected_paths: Vec<UnprotectedPath>,

    /// Upstream connection timeout in milliseconds.
    #[arg(
        long,
        env = "OWNERSHIP_PROXY_UPSTREAM_CONNECT_TIMEOUT_MS",
        default_value = "2000", value_parser = millis
    )]
    pub upstream_connect_timeout: Duration,

    /// Deadline for the whole upstream exchange through response headers, including the upload.
    /// Slow uploads exceeding this limit return a 502 timeout; raise it for large-upload routes.
    /// If this deadline expires first, it takes precedence; simultaneous timeouts may race.
    #[arg(
        long,
        env = "OWNERSHIP_PROXY_UPSTREAM_RESPONSE_TIMEOUT_SECS",
        default_value = "60", value_parser = seconds
    )]
    pub upstream_response_timeout: Duration,

    /// Maximum idle time waiting for incoming body data, in seconds.
    /// Buffered data is read before checking the idle timer after upstream backpressure.
    #[arg(long, env = "OWNERSHIP_PROXY_BODY_READ_TIMEOUT_SECS", default_value = "10", value_parser = seconds)]
    pub body_read_timeout: Duration,

    /// Grace period for draining in-flight connections in seconds.
    /// The pod terminationGracePeriodSeconds must exceed this value and any preStop delay.
    /// A preStop sleep is recommended to allow endpoint removal to propagate.
    #[arg(long, env = "OWNERSHIP_PROXY_SHUTDOWN_GRACE_SECS", default_value = "45", value_parser = seconds)]
    pub shutdown_grace: Duration,

    /// Maximum concurrent client connections.
    #[arg(long, env = "OWNERSHIP_PROXY_MAX_CONNECTIONS", default_value = "1024")]
    pub max_connections: NonZeroUsize,
}

fn millis(value: &str) -> Result<Duration, String> {
    nonzero_duration(value, Duration::from_millis, "milliseconds")
}

fn seconds(value: &str) -> Result<Duration, String> {
    nonzero_duration(value, Duration::from_secs, "seconds")
}

fn nonzero_duration(
    value: &str,
    unit: fn(u64) -> Duration,
    name: &str,
) -> Result<Duration, String> {
    let value: NonZeroU64 = value
        .parse()
        .map_err(|_| format!("expected nonzero {name}"))?;
    Ok(unit(value.get()))
}

/// An HTTP origin, without credentials or a path.
#[derive(Debug, Clone)]
pub struct UpstreamOrigin(Uri);
impl UpstreamOrigin {
    pub(crate) fn uri(&self) -> &Uri {
        &self.0
    }
}
/// An invalid upstream HTTP origin.
#[derive(Debug, thiserror::Error)]
#[error("expected an HTTP origin without a path or credentials")]
pub struct InvalidUpstream;

impl std::str::FromStr for UpstreamOrigin {
    type Err = InvalidUpstream;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uri: Uri = value.parse().map_err(|_| InvalidUpstream)?;
        let Some(authority) = uri.authority() else {
            return Err(InvalidUpstream);
        };
        if uri.scheme_str() != Some("http")
            || authority.as_str().contains('@')
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
        {
            return Err(InvalidUpstream);
        }
        Ok(Self(uri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_or_invalid_audience_entries() {
        for audiences in [
            "service,",
            ",service",
            "service, other",
            "service,,other",
            "é",
        ] {
            let args = [
                "proxy",
                "--upstream",
                "http://localhost:3000",
                "--issuer",
                "https://issuer.example",
                "--jwks-url",
                "https://issuer.example/keys",
                "--audiences",
                audiences,
            ];
            assert!(Config::try_parse_from(args).is_err(), "{audiences:?}");
        }
    }
}

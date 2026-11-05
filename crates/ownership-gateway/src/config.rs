//! Command-line and environment configuration.

use std::{
    ffi::OsStr, fmt, marker::PhantomData, net::SocketAddr, num::NonZeroU64, path::PathBuf,
    str::FromStr, time::Duration,
};

use clap::{Parser, Subcommand, builder::TypedValueParser, error::ErrorKind};
use ownership_token::Issuer;
use url::Url;

/// The longest challenge lifetime accepted.
const MAX_CHALLENGE_TTL: Duration = Duration::from_mins(10);

/// Gateway configuration, from command-line arguments or environment variables.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Config {
    /// The deployment role.
    #[command(subcommand)]
    pub command: Command,
}

/// A deployment role.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Issue challenges and tokens.
    Serve(Box<ServeConfig>),
}

/// The listener addresses.
#[derive(Debug, clap::Args)]
pub struct Listeners {
    /// Address for public requests.
    #[arg(
        long = "listen",
        env = "OWNERSHIP_GATEWAY_LISTEN",
        default_value = "0.0.0.0:8080"
    )]
    pub public: SocketAddr,
    /// Address for health probes.
    #[arg(
        long = "admin-listen",
        env = "OWNERSHIP_GATEWAY_ADMIN_LISTEN",
        default_value = "0.0.0.0:8081"
    )]
    pub admin: SocketAddr,
}

/// Configuration of the issuance server.
#[derive(Debug, clap::Args)]
pub struct ServeConfig {
    /// Where to listen.
    #[command(flatten)]
    pub listeners: Listeners,
    /// Environment-wide HTTPS issuer URL. The token endpoint is `/v1/tokens` under it.
    #[arg(long, env = "OWNERSHIP_GATEWAY_ISSUER")]
    pub issuer: Issuer,
    /// Redis URL, including its auth token. It must use `rediss://`. Neither `--help` nor a
    /// parse error prints it.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_REDIS_URL",
        hide_env_values = true,
        value_parser = secret::<RedisUrl>()
    )]
    pub redis_url: RedisUrl,
    /// Path to the JSON audience policy.
    #[arg(long, env = "OWNERSHIP_GATEWAY_AUDIENCE_POLICY_PATH")]
    pub audience_policy_path: PathBuf,
    /// Challenge lifetime in seconds, at most 600.
    #[arg(
        long = "challenge-ttl-secs",
        env = "OWNERSHIP_GATEWAY_CHALLENGE_TTL_SECS",
        default_value = "120",
        value_parser = challenge_ttl
    )]
    pub challenge_ttl: Duration,
    /// Whole-request deadline in milliseconds.
    #[arg(
        long = "request-deadline-ms",
        env = "OWNERSHIP_GATEWAY_REQUEST_DEADLINE_MS",
        default_value = "5000",
        value_parser = millis
    )]
    pub request_deadline: Duration,
}

impl ServeConfig {
    /// Returns the token exchange endpoint: `/v1/tokens` under the issuer's path, without a
    /// query.
    #[must_use]
    pub fn token_url(&self) -> Url {
        let mut url = Url::parse(self.issuer.as_str()).expect("an issuer is an absolute URL");
        let path = format!("{}/v1/tokens", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.set_query(None);
        url
    }
}

/// Parses an argument that can carry a credential. Clap's own parse errors repeat the value;
/// this one names the argument and the reason only.
#[derive(Clone)]
struct SecretParser<T>(PhantomData<fn() -> T>);

fn secret<T>() -> SecretParser<T> {
    SecretParser(PhantomData)
}

impl<T> TypedValueParser for SecretParser<T>
where
    T: FromStr + Clone + Send + Sync + 'static,
    T::Err: fmt::Display,
{
    type Value = T;

    fn parse_ref(
        &self,
        command: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<T, clap::Error> {
        let reason = match value.to_str().map(str::parse::<T>) {
            Some(Ok(value)) => return Ok(value),
            Some(Err(error)) => error.to_string(),
            None => "it is not UTF-8".to_owned(),
        };
        let argument = arg.map_or_else(|| "a value".to_owned(), ToString::to_string);
        Err(clap::Error::raw(
            ErrorKind::ValueValidation,
            format!("invalid value for {argument}: {reason}\n"),
        )
        .with_cmd(command))
    }
}

/// A `rediss://` URL with a host. Formatting redacts its password.
#[derive(Clone)]
pub struct RedisUrl(Url);

/// Why a string is not a `rediss://` URL with a host. The message never repeats the URL.
#[derive(Debug, thiserror::Error)]
pub enum InvalidRedisUrl {
    /// The string is not a URL.
    #[error("Redis URL is not a valid URL: {0}")]
    Malformed(url::ParseError),
    /// The URL does not use TLS.
    #[error("Redis URL must use rediss://")]
    NotTls,
    /// The URL names no host.
    #[error("Redis URL must name a host")]
    NoHost,
}

impl RedisUrl {
    /// Returns the URL to connect with, including any credentials.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for RedisUrl {
    type Err = InvalidRedisUrl;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(InvalidRedisUrl::Malformed)?;
        if url.scheme() != "rediss" {
            return Err(InvalidRedisUrl::NotTls);
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(InvalidRedisUrl::NoHost);
        }
        Ok(Self(url))
    }
}

impl fmt::Display for RedisUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut redacted = self.0.clone();
        if redacted.password().is_some() {
            redacted
                .set_password(Some("REDACTED"))
                .map_err(|()| fmt::Error)?;
        }
        redacted.fmt(f)
    }
}

impl fmt::Debug for RedisUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedisUrl({self})")
    }
}

fn challenge_ttl(value: &str) -> Result<Duration, String> {
    let ttl = seconds(value)?;
    if ttl > MAX_CHALLENGE_TTL {
        return Err(format!(
            "expected at most {} seconds",
            MAX_CHALLENGE_TTL.as_secs()
        ));
    }
    Ok(ttl)
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn serve_args<'a>(redis_url: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec![
            "ownership-gateway",
            "serve",
            "--issuer",
            "https://issuer.example",
            "--redis-url",
            redis_url,
            "--audience-policy-path",
            "policy.json",
        ];
        args.extend_from_slice(extra);
        args
    }

    fn parse_serve(args: &[&str]) -> Result<ServeConfig, clap::Error> {
        let Command::Serve(config) = Config::try_parse_from(args)?.command;
        Ok(*config)
    }

    #[test]
    fn redis_url_requires_tls_and_a_host() {
        for rejected in [
            "redis://cache:6379",
            "rediss://",
            "https://cache",
            "cache:6379",
        ] {
            assert!(rejected.parse::<RedisUrl>().is_err(), "{rejected}");
        }
        assert!("rediss://:token@cache:6379/0".parse::<RedisUrl>().is_ok());
    }

    #[test]
    fn redis_url_formatting_redacts_the_password() {
        let url: RedisUrl = "rediss://user:secret@cache:6379/0".parse().unwrap();
        assert_eq!(url.to_string(), "rediss://user:REDACTED@cache:6379/0");
        assert!(!format!("{url:?}").contains("secret"));
        assert!(url.as_str().contains("secret"));
    }

    #[test]
    fn redis_url_errors_and_help_never_print_the_url() {
        for (url, reason) in [
            ("redis://:s3cr3t@cache:6379", "must use rediss://"),
            ("rediss://:s3cr3t#token@cache:6379", "not a valid URL"),
        ] {
            let error = parse_serve(&serve_args(url, &[])).unwrap_err().to_string();
            assert!(!error.contains("s3cr3t"), "{error}");
            assert!(error.contains(reason), "{error}");
        }
        let command = Config::command();
        let serve = command.find_subcommand("serve").unwrap();
        let mut arguments = serve.get_arguments();
        let redis_url = arguments.find(|arg| arg.get_id() == "redis_url").unwrap();
        assert!(redis_url.is_hide_env_values_set());
    }

    #[test]
    fn defaults_follow_the_spec_and_out_of_range_values_are_rejected() {
        let config = parse_serve(&serve_args("rediss://cache", &[])).unwrap();
        assert_eq!(config.challenge_ttl, Duration::from_mins(2));
        assert_eq!(config.request_deadline, Duration::from_millis(5000));
        let config = parse_serve(&serve_args(
            "rediss://cache",
            &["--challenge-ttl-secs", "30", "--request-deadline-ms", "750"],
        ))
        .unwrap();
        assert_eq!(config.challenge_ttl, Duration::from_secs(30));
        assert_eq!(config.request_deadline, Duration::from_millis(750));
        for flag in ["--challenge-ttl-secs", "--request-deadline-ms"] {
            assert!(parse_serve(&serve_args("rediss://cache", &[flag, "0"])).is_err());
        }
        assert!(
            parse_serve(&serve_args(
                "rediss://cache",
                &["--challenge-ttl-secs", "601"]
            ))
            .is_err()
        );
    }

    #[test]
    fn token_url_is_under_the_issuer_path() {
        for (issuer, expected) in [
            ("https://issuer.example", "https://issuer.example/v1/tokens"),
            (
                "https://issuer.example/base/",
                "https://issuer.example/base/v1/tokens",
            ),
            (
                "https://issuer.example/base?x=1",
                "https://issuer.example/base/v1/tokens",
            ),
        ] {
            let mut config = parse_serve(&serve_args("rediss://cache", &[])).unwrap();
            config.issuer = issuer.parse().unwrap();
            assert_eq!(config.token_url().as_str(), expected);
        }
    }
}

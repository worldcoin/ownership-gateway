//! Command-line and environment configuration.

use std::{
    ffi::OsStr,
    fmt,
    marker::PhantomData,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use clap::{Parser, Subcommand, builder::TypedValueParser, error::ErrorKind};
use ownership_token::{Issuer, UseCase};
use url::Url;

use crate::{
    exchange::MIN_REQUEST_DEADLINE, root::RootSourceUrl, signing::DEFAULT_FAILURE_THRESHOLD,
};

/// The longest challenge lifetime accepted.
const MAX_CHALLENGE_TTL: Duration = Duration::from_mins(10);
/// The most proof verification workers: the async runtime's limit on blocking threads.
const MAX_VERIFY_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(512).unwrap();

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
    /// Serve the public keys that verify issued tokens.
    Jwks(JwksConfig),
}

/// The listener addresses and how they drain, shared by both deployment roles.
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
    /// How long requests in flight may finish after `SIGTERM`, in seconds. The pod's
    /// `terminationGracePeriodSeconds` must exceed this plus any `preStop` delay.
    #[arg(
        long = "shutdown-grace-secs",
        env = "OWNERSHIP_GATEWAY_SHUTDOWN_GRACE_SECS",
        default_value = "45",
        value_parser = seconds
    )]
    pub shutdown_grace: Duration,
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
    /// Whole-request deadline in milliseconds, at least 3500.
    #[arg(
        long = "request-deadline-ms",
        env = "OWNERSHIP_GATEWAY_REQUEST_DEADLINE_MS",
        default_value = "5000",
        value_parser = request_deadline
    )]
    pub request_deadline: Duration,
    /// Base URL of the root service, `world-id-gateway`. It may carry credentials, so neither
    /// `--help` nor a parse error prints it.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_ROOT_SOURCE_URL",
        hide_env_values = true,
        value_parser = secret::<RootSourceUrl>()
    )]
    pub root_source_url: RootSourceUrl,
    /// How long every root check must fail before readiness is lost, in seconds.
    #[arg(
        long = "root-failure-window-secs",
        env = "OWNERSHIP_GATEWAY_ROOT_FAILURE_WINDOW_SECS",
        default_value = "30",
        value_parser = seconds
    )]
    pub root_failure_window: Duration,
    /// KMS key that signs tokens.
    #[arg(long, env = "OWNERSHIP_GATEWAY_KMS_SIGNING_KEY_ID")]
    pub kms_signing_key_id: KmsKeyId,
    /// Consecutive failed signing attempts before readiness is lost.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_KMS_FAILURE_THRESHOLD",
        default_value_t = DEFAULT_FAILURE_THRESHOLD
    )]
    pub kms_failure_threshold: NonZeroU32,
    /// WIP-103 use case named in issued tokens.
    #[arg(long, env = "OWNERSHIP_GATEWAY_USE_CASE")]
    pub use_case: UseCase,
    /// Proof verification workers, at most 512. Defaults to the available CPUs, or one if they
    /// cannot be counted.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_VERIFY_CONCURRENCY",
        default_value_t = std::thread::available_parallelism()
            .unwrap_or(NonZeroUsize::MIN)
            .min(MAX_VERIFY_CONCURRENCY),
        value_parser = verify_concurrency
    )]
    pub verify_concurrency: NonZeroUsize,
    /// Verifications that may wait for a worker, at most 65535.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_VERIFY_QUEUE_DEPTH",
        value_parser = clap::value_parser!(u16).map(usize::from)
    )]
    pub verify_queue_depth: usize,
    /// Whether challenges and tokens may be issued: the global kill switch.
    #[arg(
        long,
        env = "OWNERSHIP_GATEWAY_TOKEN_ISSUANCE_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub token_issuance_enabled: bool,
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

/// Configuration of the JWKS deployment.
#[derive(Debug, clap::Args)]
pub struct JwksConfig {
    /// Where to listen.
    #[command(flatten)]
    pub listeners: Listeners,
    /// KMS key IDs whose public keys are published, separated by commas.
    #[arg(long, env = "OWNERSHIP_GATEWAY_KMS_PUBLISHED_KEY_IDS")]
    pub published_key_ids: PublishedKeyIds,
}

/// A KMS key ID, alias or ARN: nonempty, without whitespace or commas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KmsKeyId(String);

/// A KMS key ID that is empty or contains whitespace or a comma.
#[derive(Debug, thiserror::Error)]
#[error("KMS key IDs must be nonempty, without whitespace or commas")]
pub struct InvalidKmsKeyId;

impl KmsKeyId {
    /// Returns the key ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KmsKeyId {
    type Err = InvalidKmsKeyId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.contains(|c: char| c.is_whitespace() || c == ',') {
            return Err(InvalidKmsKeyId);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for KmsKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A nonempty, comma-separated list of KMS key IDs.
#[derive(Clone, Debug)]
pub struct PublishedKeyIds(Vec<KmsKeyId>);

impl PublishedKeyIds {
    /// Returns the key IDs in configured order.
    pub fn iter(&self) -> impl Iterator<Item = &KmsKeyId> {
        self.0.iter()
    }
}

impl FromStr for PublishedKeyIds {
    type Err = InvalidKmsKeyId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map(Self)
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

fn request_deadline(value: &str) -> Result<Duration, String> {
    let deadline = millis(value)?;
    if deadline < MIN_REQUEST_DEADLINE {
        return Err(format!(
            "expected at least {} milliseconds: the claim, a root check, the consume and a \
             signing attempt must fit",
            MIN_REQUEST_DEADLINE.as_millis()
        ));
    }
    Ok(deadline)
}

fn verify_concurrency(value: &str) -> Result<NonZeroUsize, String> {
    value
        .parse()
        .ok()
        .filter(|workers| *workers <= MAX_VERIFY_CONCURRENCY)
        .ok_or_else(|| format!("expected 1 to {MAX_VERIFY_CONCURRENCY} workers"))
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
            "--root-source-url",
            "https://root.example",
            "--kms-signing-key-id",
            "key",
            "--use-case",
            "stage-test",
            "--verify-queue-depth",
            "4",
        ];
        args.extend_from_slice(extra);
        args
    }

    fn parse_serve(args: &[&str]) -> Result<ServeConfig, clap::Error> {
        let Command::Serve(config) = Config::try_parse_from(args)?.command else {
            panic!("expected the serve command");
        };
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
        assert_eq!(config.root_failure_window, Duration::from_secs(30));
        assert_eq!(config.kms_failure_threshold, DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(config.listeners.shutdown_grace, Duration::from_secs(45));
        let config = parse_serve(&serve_args(
            "rediss://cache",
            &[
                "--challenge-ttl-secs",
                "30",
                "--request-deadline-ms",
                "3500",
            ],
        ))
        .unwrap();
        assert_eq!(config.challenge_ttl, Duration::from_secs(30));
        assert_eq!(config.request_deadline, Duration::from_millis(3500));
        for flag in [
            "--challenge-ttl-secs",
            "--request-deadline-ms",
            "--root-failure-window-secs",
            "--kms-failure-threshold",
            "--verify-concurrency",
        ] {
            assert!(parse_serve(&serve_args("rediss://cache", &[flag, "0"])).is_err());
        }
        for (flag, value) in [
            ("--challenge-ttl-secs", "601"),
            ("--request-deadline-ms", "3499"),
            ("--verify-concurrency", "513"),
        ] {
            let args = serve_args("rediss://cache", &[flag, value]);
            assert!(parse_serve(&args).is_err(), "{flag} {value}");
        }
    }

    #[test]
    fn the_issuance_switch_defaults_on_and_can_be_turned_off() {
        let config = parse_serve(&serve_args("rediss://cache", &[])).unwrap();
        assert!(config.token_issuance_enabled);
        let config = parse_serve(&serve_args(
            "rediss://cache",
            &["--token-issuance-enabled", "false"],
        ))
        .unwrap();
        assert!(!config.token_issuance_enabled);
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

    #[test]
    fn published_key_ids_are_a_nonempty_list_without_empty_entries() {
        let ids: PublishedKeyIds = "key-a,arn:aws:kms:us-east-1:1:key/b".parse().unwrap();
        assert_eq!(
            ids.iter().map(KmsKeyId::as_str).collect::<Vec<_>>(),
            ["key-a", "arn:aws:kms:us-east-1:1:key/b"]
        );
        for rejected in ["", "key-a,", ",key-a", "key-a,,key-b", "key a"] {
            assert!(rejected.parse::<PublishedKeyIds>().is_err(), "{rejected:?}");
        }
        let config = Config::try_parse_from([
            "ownership-gateway",
            "jwks",
            "--published-key-ids",
            "key-a,key-b",
        ])
        .unwrap();
        let Command::Jwks(config) = config.command else {
            panic!("expected the jwks command");
        };
        assert_eq!(config.published_key_ids.iter().count(), 2);
    }
}

//! Remote key caching coalesces fetches and bounds unknown-key refreshes.
//! This prevents a stream of unknown key IDs from overwhelming the issuer.

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use p256::ecdsa::VerifyingKey;
use tokio::{sync::Mutex, time::Instant};
use tracing::Instrument as _;

use crate::{JwkSet, KeySet, KeysUnavailable};

const MAX_JITTER: f64 = 0.1;
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const COOLDOWN: Duration = Duration::from_secs(30);
const MAX_STALENESS: Duration = Duration::from_hours(6);
const MAX_BYTES: usize = 64 * 1024;

/// A bounded classification of a failed JWKS fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwksFetchError {
    /// The HTTP request or response body timed out.
    #[error("JWKS request timed out")]
    Timeout,
    /// The HTTP request or response body failed.
    #[error("JWKS request failed")]
    Request,
    /// The endpoint returned a non-success status.
    #[error("JWKS endpoint returned an unsuccessful status")]
    Status(reqwest::StatusCode),
    /// The document exceeded the size limit.
    #[error("JWKS document too large")]
    TooLarge,
    /// The document was malformed or had no keys.
    #[error("invalid or empty JWKS document")]
    Invalid,
    /// The shared fetch task did not complete.
    #[error("JWKS fetch task failed")]
    Task,
}

impl JwksFetchError {
    /// Returns a low-cardinality label suitable for metrics.
    #[must_use]
    pub fn class(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Request => "request",
            Self::Status(_) => "status",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid",
            Self::Task => "task",
        }
    }
}

/// A trusted JWKS endpoint URL. HTTPS is required except for loopback HTTP.
/// Credentials and fragments are rejected.
#[derive(Debug, Clone)]
pub struct JwksUrl(url::Url);

/// An invalid JWKS endpoint URL.
#[derive(Debug, thiserror::Error)]
#[error("JWKS URL must be HTTPS (or loopback HTTP) without credentials or fragment")]
pub struct InvalidJwksUrl;

impl std::str::FromStr for JwksUrl {
    type Err = InvalidJwksUrl;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(value).map_err(|_| InvalidJwksUrl)?;
        let loopback = match url.host() {
            Some(url::Host::Domain(host)) => host == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(InvalidJwksUrl);
        }
        Ok(Self(url))
    }
}
impl std::fmt::Display for JwksUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A trusted remote JWKS and its shared local cache.
///
/// Call [`RemoteJwks::refresh`] at startup and spawn [`RemoteJwks::run_refresh`].
/// Cancelling the refresh future stops periodic refreshes. Usable caches refresh every five
/// minutes with up to 10% early jitter; unusable caches retry after 30 seconds
/// with up to 10% additional jitter. Unknown-key requests share a 30-second
/// cooldown. Keys become stale after six hours; fetches have a three-second
/// timeout, a 64 KiB limit, and reject redirects.
#[derive(Clone)]
pub struct RemoteJwks {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for RemoteJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteJwks")
            .field("host", &self.inner.url.host_str())
            .finish_non_exhaustive()
    }
}

struct Inner {
    url: url::Url,
    client: reqwest::Client,
    snapshot: RwLock<Option<Snapshot>>,
    last_attempt: Arc<Mutex<Option<Attempt>>>,
    failure_observer: Box<dyn Fn(JwksFetchError) + Send + Sync>,
}
struct Snapshot {
    keys: JwkSet,
    fetched_at: Instant,
}
impl Snapshot {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() <= MAX_STALENESS
    }
}

struct Attempt {
    finished_at: Instant,
    result: Result<(), JwksFetchError>,
}

/// An HTTP client configuration failure.
#[derive(Debug, thiserror::Error)]
#[error("could not create JWKS HTTP client")]
pub struct JwksConfigError(#[source] reqwest::Error);

impl RemoteJwks {
    /// Creates an initially empty cache for a trusted endpoint. Redirects are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(url: JwksUrl) -> Result<Self, JwksConfigError> {
        Self::with_failure_observer(url, |_| {})
    }

    /// Creates a cache that reports every failed fetch to the observer.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn with_failure_observer(
        url: JwksUrl,
        observer: impl Fn(JwksFetchError) + Send + Sync + 'static,
    ) -> Result<Self, JwksConfigError> {
        let url = url.0;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .user_agent(concat!("ownership-token/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(JwksConfigError)?;
        Ok(Self {
            inner: Arc::new(Inner {
                url,
                client,
                snapshot: RwLock::new(None),
                last_attempt: Arc::new(Mutex::new(None)),
                failure_observer: Box::new(observer),
            }),
        })
    }

    /// Fetches keys now, joining an in-flight refresh. A failure leaves cached keys intact.
    ///
    /// # Errors
    ///
    /// Returns the fetch failure class if a new set could not be loaded.
    pub async fn refresh(&self) -> Result<(), JwksFetchError> {
        self.refresh_shared(Duration::ZERO).await
    }

    /// Returns the age of the last successfully fetched set, or `None` before the first fetch.
    #[must_use]
    pub fn age(&self) -> Option<Duration> {
        self.inner
            .snapshot
            .read()
            .expect("JWKS snapshot lock poisoned")
            .as_ref()
            .map(|snapshot| snapshot.fetched_at.elapsed())
    }

    /// Returns whether a nonempty, non-stale key set is available.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.inner
            .snapshot
            .read()
            .expect("JWKS snapshot lock poisoned")
            .as_ref()
            .is_some_and(Snapshot::is_fresh)
    }

    /// Runs periodic refreshes until this future is cancelled.
    pub async fn run_refresh(self) {
        loop {
            let mut random = [0u8; 1];
            let early = match getrandom::fill(&mut random) {
                Ok(()) => MAX_JITTER * f64::from(random[0]) / f64::from(u8::MAX),
                Err(error) => {
                    tracing::warn!(%error, "JWKS refresh jitter unavailable");
                    0.0
                }
            };
            // Unusable caches recover on the shorter cooldown; usable ones refresh periodically.
            let age = self
                .inner
                .snapshot
                .read()
                .expect("JWKS snapshot lock poisoned")
                .as_ref()
                .filter(|snapshot| snapshot.is_fresh())
                .map(|snapshot| snapshot.fetched_at.elapsed());
            let delay = if let Some(age) = age {
                let until_stale = MAX_STALENESS.saturating_sub(age);
                let retry_after_stale = until_stale + COOLDOWN.mul_f64(1.0 + early);
                REFRESH_INTERVAL.mul_f64(1.0 - early).min(retry_after_stale)
            } else {
                COOLDOWN.mul_f64(1.0 + early)
            };
            tokio::time::sleep(delay).await;
            // Refresh failures are reported by the observer and logged.
            let _ = self.refresh().await;
        }
    }

    async fn refresh_shared(&self, cooldown: Duration) -> Result<(), JwksFetchError> {
        // Explicit refreshes join in-flight fetches; key lookups also reuse recent attempts.
        let started = Instant::now();
        let mut last = self.inner.last_attempt.clone().lock_owned().await;
        if let Some(attempt) = last.as_ref()
            && (attempt.finished_at >= started || attempt.finished_at.elapsed() < cooldown)
        {
            return attempt.result;
        }
        let jwks = self.clone();
        // Keep the shared fetch and its lock alive if the initiating caller is cancelled.
        tokio::spawn(
            async move {
                let result = jwks.fetch().await;
                if let Err(error) = result {
                    (jwks.inner.failure_observer)(error);
                    let status = match error {
                        JwksFetchError::Status(status) => Some(status.as_u16()),
                        _ => None,
                    };
                    tracing::warn!(
                        class = error.class(),
                        ?status,
                        host = jwks.inner.url.host_str().unwrap_or("unknown"),
                        "JWKS refresh failed"
                    );
                }
                *last = Some(Attempt {
                    finished_at: Instant::now(),
                    result,
                });
                result
            }
            .in_current_span(),
        )
        .await
        .map_err(|error| {
            (self.inner.failure_observer)(JwksFetchError::Task);
            tracing::error!(
                %error,
                host = self.inner.url.host_str().unwrap_or("unknown"),
                "JWKS refresh task failed"
            );
            JwksFetchError::Task
        })?
    }

    async fn fetch(&self) -> Result<(), JwksFetchError> {
        let mut response = self
            .inner
            .client
            .get(self.inner.url.clone())
            .send()
            .await
            .map_err(|error| request_error(&error))?;
        if !response.status().is_success() {
            return Err(JwksFetchError::Status(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return Err(JwksFetchError::TooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| request_error(&error))?
        {
            if chunk.len() > MAX_BYTES - bytes.len() {
                return Err(JwksFetchError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let keys: JwkSet = serde_json::from_slice(&bytes).map_err(|_| JwksFetchError::Invalid)?;
        if keys.keys().is_empty() {
            return Err(JwksFetchError::Invalid);
        }
        *self
            .inner
            .snapshot
            .write()
            .expect("JWKS snapshot lock poisoned") = Some(Snapshot {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    fn cached_key(&self, kid: &str) -> Result<Option<VerifyingKey>, KeysUnavailable> {
        let guard = self
            .inner
            .snapshot
            .read()
            .expect("JWKS snapshot lock poisoned");
        let snapshot = guard
            .as_ref()
            .filter(|snapshot| snapshot.is_fresh())
            .ok_or(KeysUnavailable)?;
        Ok(snapshot.keys.find(kid).map(|key| *key.public_key()))
    }
}

impl KeySet for RemoteJwks {
    async fn key(&self, kid: &str) -> Result<Option<VerifyingKey>, KeysUnavailable> {
        if let Ok(Some(key)) = self.cached_key(kid) {
            return Ok(Some(key));
        }
        // Fetch failures are reported by the observer and logged.
        let _ = self.refresh_shared(COOLDOWN).await;
        self.cached_key(kid)
    }
}

fn request_error(error: &reqwest::Error) -> JwksFetchError {
    if error.is_timeout() {
        JwksFetchError::Timeout
    } else {
        JwksFetchError::Request
    }
}

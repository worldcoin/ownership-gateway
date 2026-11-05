//! Registry root checks against the root service: the `is-valid-root` endpoint of
//! `world-id-gateway`.

use std::{fmt, str::FromStr, sync::Mutex, time::Duration};

use reqwest::{StatusCode, Url};
use tokio::time::Instant;
use url::Position;
use world_id_primitives::{FieldElement, api_types::IsValidRootResponse};

use crate::{
    retry::Deadline,
    telemetry::{self, Dependency, ErrorChain, FailureClass},
};

/// How long one root check attempt may take.
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_BODY_BYTES: usize = 4096;

/// The base URL of the root service; checks go to `{base}/is-valid-root`. Its `Debug` output
/// leaves out the userinfo, which can carry credentials.
#[derive(Clone)]
pub struct RootSourceUrl(Url);

/// A root source that is not an HTTP(S) base URL without a query or fragment.
#[derive(Debug, thiserror::Error)]
#[error("root source must be an HTTP(S) base URL without a query or fragment")]
pub struct InvalidRootSourceUrl;

impl FromStr for RootSourceUrl {
    type Err = InvalidRootSourceUrl;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(|_| InvalidRootSourceUrl)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.cannot_be_a_base()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(InvalidRootSourceUrl);
        }
        Ok(Self(url))
    }
}

impl fmt::Debug for RootSourceUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = &self.0;
        write!(
            f,
            "RootSourceUrl({}://{})",
            url.scheme(),
            &url[Position::BeforeHost..Position::AfterPath]
        )
    }
}

/// The root service's verdict on a root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootVerdict {
    /// The registry accepts the root.
    Valid,
    /// The registry does not accept the root.
    Invalid,
    /// No verdict could be obtained.
    Unavailable,
}

#[derive(Debug, thiserror::Error)]
enum CheckError {
    #[error("root service request failed")]
    Request(#[source] reqwest::Error),
    #[error("root service answered {0}")]
    Status(StatusCode),
    #[error("root service response exceeds 4 KiB")]
    BodyTooLarge,
    #[error("root service response is not a verdict")]
    Body(#[source] serde_json::Error),
}

impl CheckError {
    fn request(error: reqwest::Error) -> Self {
        // The URL carries the root, which must not reach logs.
        Self::Request(error.without_url())
    }

    fn class(&self) -> FailureClass {
        match self {
            Self::Request(error) if error.is_timeout() => FailureClass::Timeout,
            Self::Request(error) if error.is_connect() => FailureClass::Connect,
            Self::Status(status) if status.is_server_error() => FailureClass::Server,
            Self::Request(_) | Self::Status(_) | Self::BodyTooLarge | Self::Body(_) => {
                FailureClass::Other
            }
        }
    }
}

struct FailingSince {
    since: Instant,
    confirmed: bool,
}

/// Checks roots against the root service and tracks whether checks keep failing.
pub struct RootValidator {
    client: reqwest::Client,
    endpoint: Url,
    failure_window: Duration,
    failing: Mutex<Option<FailingSince>>,
}

/// Counts a check that is dropped before it finishes, for example at the request deadline,
/// as a failed check.
struct CheckGuard<'a> {
    validator: &'a RootValidator,
    started: Instant,
    finished: bool,
}

impl Drop for CheckGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.validator.record(RootVerdict::Unavailable);
            telemetry::record_call(Dependency::Root, self.started, Err(FailureClass::Timeout));
        }
    }
}

impl RootValidator {
    /// Creates a validator for `source`. It becomes unready once every check has failed for
    /// `failure_window`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(source: &RootSourceUrl, failure_window: Duration) -> Result<Self, reqwest::Error> {
        let mut endpoint = source.0.clone();
        let path = format!("{}/is-valid-root", endpoint.path().trim_end_matches('/'));
        endpoint.set_path(&path);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("ownership-gateway/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            client,
            endpoint,
            failure_window,
            failing: Mutex::new(None),
        })
    }

    /// Asks the root service whether the registry accepts `root`.
    ///
    /// Each attempt times out after one second or at the deadline, whichever is sooner. A failed
    /// attempt is retried once after a jittered pause, if the deadline leaves time for a full
    /// attempt. Never returns [`RootVerdict::Valid`] without a verdict from the service.
    pub async fn check(&self, root: FieldElement, deadline: Deadline) -> RootVerdict {
        let mut guard = CheckGuard {
            validator: self,
            started: Instant::now(),
            finished: false,
        };
        let outcome = deadline
            .retry_once(
                ATTEMPT_TIMEOUT,
                |_| true,
                |timeout| self.attempt(root, timeout),
            )
            .await;
        guard.finished = true;
        let Some((result, attempts)) = outcome else {
            return RootVerdict::Unavailable;
        };
        let verdict = match result {
            Ok(verdict) => verdict,
            Err(error) => {
                tracing::warn!(
                    dependency = Dependency::Root.as_str(),
                    operation = "validate_root",
                    attempts,
                    class = error.class().as_str(),
                    error = %ErrorChain(&error),
                    "root check failed"
                );
                RootVerdict::Unavailable
            }
        };
        self.record(verdict);
        verdict
    }

    /// Whether root checks can currently succeed: false once every check for the failure window
    /// has failed, and true again after the next check that gets a verdict.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.failing
            .lock()
            .expect("root readiness lock is not poisoned")
            .as_ref()
            .is_none_or(|failing| !failing.confirmed)
    }

    fn record(&self, verdict: RootVerdict) {
        let mut failing = self
            .failing
            .lock()
            .expect("root readiness lock is not poisoned");
        if verdict != RootVerdict::Unavailable {
            *failing = None;
        } else if let Some(failing) = failing.as_mut() {
            // A failure only confirms the outage once the window has passed since the first one,
            // so a single failure on a quiet pod does not make it unready.
            failing.confirmed |= failing.since.elapsed() >= self.failure_window;
        } else {
            *failing = Some(FailingSince {
                since: Instant::now(),
                confirmed: false,
            });
        }
    }

    async fn attempt(
        &self,
        root: FieldElement,
        timeout: Duration,
    ) -> Result<RootVerdict, CheckError> {
        let started = Instant::now();
        let result = self.request(root, timeout).await;
        telemetry::record_call(
            Dependency::Root,
            started,
            result.as_ref().map(|_| ()).map_err(CheckError::class),
        );
        result
    }

    async fn request(
        &self,
        root: FieldElement,
        timeout: Duration,
    ) -> Result<RootVerdict, CheckError> {
        let mut response = self
            .client
            .get(self.endpoint.clone())
            .query(&[("root", root.to_string())])
            .timeout(timeout)
            .send()
            .await
            .map_err(CheckError::request)?;
        if !response.status().is_success() {
            return Err(CheckError::Status(response.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(CheckError::request)? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(CheckError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let verdict: IsValidRootResponse =
            serde_json::from_slice(&body).map_err(CheckError::Body)?;
        Ok(if verdict.valid {
            RootVerdict::Valid
        } else {
            RootVerdict::Invalid
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(30);

    fn validator(failure_window: Duration) -> RootValidator {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("no other provider is installed");
        });
        RootValidator::new(&"http://127.0.0.1:1".parse().unwrap(), failure_window).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_is_lost_only_when_failures_span_the_window() {
        let validator = validator(WINDOW);
        validator.record(RootVerdict::Unavailable);
        tokio::time::advance(WINDOW).await;
        assert!(validator.is_ready());
        validator.record(RootVerdict::Unavailable);
        assert!(!validator.is_ready());
        validator.record(RootVerdict::Invalid);
        assert!(validator.is_ready());
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_check_counts_as_a_failure() {
        let validator = validator(WINDOW);
        validator.record(RootVerdict::Unavailable);
        tokio::time::advance(WINDOW).await;
        drop(CheckGuard {
            validator: &validator,
            started: Instant::now(),
            finished: false,
        });
        assert!(!validator.is_ready());
    }

    #[test]
    fn root_source_must_be_an_http_base_url() {
        for rejected in [
            "ftp://root.example",
            "mailto:root@example.com",
            "https://root.example/?x=1",
            "https://root.example/#x",
        ] {
            assert!(rejected.parse::<RootSourceUrl>().is_err(), "{rejected}");
        }
        assert!("https://root.example/base".parse::<RootSourceUrl>().is_ok());
    }

    #[test]
    fn root_source_debug_leaves_out_credentials() {
        let url: RootSourceUrl = "https://user:s3cr3t@root.example:8443/base"
            .parse()
            .unwrap();
        assert_eq!(
            format!("{url:?}"),
            "RootSourceUrl(https://root.example:8443/base)"
        );
    }
}

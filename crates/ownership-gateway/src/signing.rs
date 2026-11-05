//! ES256 signing with a KMS key, and loading the public keys that verify its signatures.

use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use aws_sdk_kms::{
    config::retry::RetryConfig,
    error::{ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ownership_token::{Claims, Jwk, TOKEN_TYPE};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier as _},
    pkcs8::DecodePublicKey as _,
};
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

use crate::{
    retry::Deadline,
    telemetry::{self, Dependency, ErrorChain, FailureClass},
};

/// How long one KMS request may take.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// The default number of consecutive failed signing attempts that makes a signer unready.
pub const DEFAULT_FAILURE_THRESHOLD: NonZeroU32 = NonZeroU32::new(3).unwrap();

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Why a KMS request failed.
#[derive(Debug, thiserror::Error)]
pub enum KmsFailure {
    /// The request did not finish in time.
    #[error("KMS request timed out")]
    Timeout,
    /// KMS could not be reached.
    #[error("connecting to KMS failed")]
    Connect(#[source] BoxError),
    /// KMS answered with a server error.
    #[error("KMS failed")]
    Server(#[source] BoxError),
    /// KMS throttled the request: the account's request quota is used up for now. It is not
    /// retried, because a retry within the same second would only add to that quota's load.
    #[error("KMS throttled the request")]
    Throttled(#[source] BoxError),
    /// KMS asked the caller to retry.
    #[error("KMS asked for a retry")]
    Retryable(#[source] BoxError),
    /// KMS rejected the request, for example for a missing key or permission.
    #[error("KMS rejected the request")]
    Permanent(#[source] BoxError),
    /// KMS returned a signature or key that is malformed or does not match the loaded key.
    #[error("KMS returned an invalid signature or public key")]
    InvalidResponse,
}

impl KmsFailure {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Connect(_) | Self::Server(_) | Self::Retryable(_)
        )
    }

    fn class(&self) -> FailureClass {
        match self {
            Self::Timeout => FailureClass::Timeout,
            Self::Connect(_) => FailureClass::Connect,
            Self::Server(_) => FailureClass::Server,
            Self::Throttled(_) => FailureClass::Throttled,
            Self::Retryable(_) | Self::Permanent(_) | Self::InvalidResponse => FailureClass::Other,
        }
    }
}

/// The network boundary to KMS.
#[async_trait]
pub trait KmsClient: Send + Sync {
    /// Signs a SHA-256 digest with the P-256 key `key_id`, returning a DER signature.
    async fn sign_digest(&self, key_id: &str, digest: [u8; 32]) -> Result<Vec<u8>, KmsFailure>;

    /// Returns the public half of the P-256 key `key_id` as SPKI DER.
    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, KmsFailure>;
}

/// AWS KMS, without the SDK's own retries: the signer bounds its retries itself.
pub struct AwsKms(aws_sdk_kms::Client);

impl AwsKms {
    /// Creates a client for the region and credentials in `config`, with SDK retries disabled.
    #[must_use]
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        let config = aws_sdk_kms::config::Builder::from(config)
            .retry_config(RetryConfig::disabled())
            .build();
        Self(aws_sdk_kms::Client::from_conf(config))
    }
}

#[async_trait]
impl KmsClient for AwsKms {
    async fn sign_digest(&self, key_id: &str, digest: [u8; 32]) -> Result<Vec<u8>, KmsFailure> {
        let response = self
            .0
            .sign()
            .key_id(key_id)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(classify_aws_error)?;
        let signature = response.signature().ok_or(KmsFailure::InvalidResponse)?;
        Ok(signature.as_ref().to_vec())
    }

    async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, KmsFailure> {
        let response = self
            .0
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(classify_aws_error)?;
        let key = response.public_key().ok_or(KmsFailure::InvalidResponse)?;
        Ok(key.as_ref().to_vec())
    }
}

fn classify_aws_error<E>(error: SdkError<E>) -> KmsFailure
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    let server_error = error
        .raw_response()
        .is_some_and(|response| response.status().is_server_error());
    let code = error
        .as_service_error()
        .and_then(ProvideErrorMetadata::code);
    match (&error, code) {
        (SdkError::TimeoutError(_), _) => KmsFailure::Timeout,
        (SdkError::DispatchFailure(_), _) => KmsFailure::Connect(Box::new(error)),
        _ if server_error => KmsFailure::Server(Box::new(error)),
        (_, Some("ThrottlingException")) => KmsFailure::Throttled(Box::new(error)),
        (_, Some("DependencyTimeoutException" | "KMSInternalException")) => {
            KmsFailure::Retryable(Box::new(error))
        }
        _ => KmsFailure::Permanent(Box::new(error)),
    }
}

/// Loads the public half of the KMS key `key_id` as a JWK, within [`ATTEMPT_TIMEOUT`].
///
/// # Errors
///
/// Returns the KMS failure, or [`KmsFailure::InvalidResponse`] if the key is not a P-256 key.
pub async fn load_jwk(client: &dyn KmsClient, key_id: &str) -> Result<Jwk, KmsFailure> {
    let started = Instant::now();
    let result = match tokio::time::timeout(ATTEMPT_TIMEOUT, client.public_key(key_id)).await {
        Err(_) => Err(KmsFailure::Timeout),
        Ok(Err(failure)) => Err(failure),
        Ok(Ok(der)) => VerifyingKey::from_public_key_der(&der)
            .map(|key| Jwk::from_public_key(&key))
            .map_err(|_| KmsFailure::InvalidResponse),
    };
    telemetry::record_call(
        Dependency::Kms,
        started,
        result.as_ref().map(|_| ()).map_err(KmsFailure::class),
    );
    result
}

/// A signing request that did not produce a signature.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// The deadline passed before KMS was asked.
    #[error("request deadline passed before signing")]
    DeadlineExceeded,
    /// KMS did not sign.
    #[error("KMS signing failed after {attempts} attempt(s)")]
    Kms {
        /// The number of KMS requests made.
        attempts: u32,
        /// The failure of the last request.
        #[source]
        failure: KmsFailure,
    },
}

/// Signs ownership tokens with a KMS key, and tracks whether signing works.
pub struct KmsSigner {
    client: Arc<dyn KmsClient>,
    key_id: String,
    kid: String,
    public_key: VerifyingKey,
    failure_threshold: NonZeroU32,
    consecutive_failures: AtomicU32,
}

/// Counts a signing attempt that is dropped before it finishes, for example at the request
/// deadline, as a failed attempt.
struct AttemptGuard<'a> {
    signer: &'a KmsSigner,
    started: Instant,
    finished: bool,
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.signer
                .consecutive_failures
                .fetch_add(1, Ordering::AcqRel);
            telemetry::record_call(Dependency::Kms, self.started, Err(FailureClass::Timeout));
        }
    }
}

impl KmsSigner {
    /// Loads the public half of the signing key `key_id`. The signer becomes unready after
    /// `failure_threshold` consecutive failed attempts and ready again after one success.
    /// Throttling is an account-wide quota rather than a fault of this signer, so a throttled
    /// attempt neither counts as a failure nor as a success.
    ///
    /// # Errors
    ///
    /// Returns the failure if the public key cannot be loaded.
    pub async fn load(
        client: Arc<dyn KmsClient>,
        key_id: String,
        failure_threshold: NonZeroU32,
    ) -> Result<Self, KmsFailure> {
        let jwk = load_jwk(client.as_ref(), &key_id).await?;
        Ok(Self {
            client,
            key_id,
            kid: jwk.kid().to_owned(),
            public_key: *jwk.public_key(),
            failure_threshold,
            consecutive_failures: AtomicU32::new(0),
        })
    }

    /// Returns the key identifier that verifiers find the signing key under.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Whether signing works: false after the threshold of consecutive failed attempts.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.consecutive_failures.load(Ordering::Acquire) < self.failure_threshold.get()
    }

    /// Signs `claims` as a compact ES256 JWS with the header `{alg, typ, kid}`.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`KmsSigner::sign`].
    pub async fn sign_token(
        &self,
        claims: &Claims,
        deadline: Deadline,
    ) -> Result<String, SigningError> {
        let header = serde_json::json!({"alg": "ES256", "typ": TOKEN_TYPE, "kid": self.kid});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("the header serializes")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"))
        );
        let signature = self.sign(input.as_bytes(), deadline).await?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Signs the SHA-256 digest of `input` and returns the raw `r || s` signature.
    ///
    /// Each attempt times out after two seconds or at the deadline, whichever is sooner. A
    /// retryable failure is retried once after a jittered pause, if the deadline leaves time for
    /// a full attempt. A signature is returned only after it verifies against the loaded key.
    /// Failures are logged here.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::DeadlineExceeded`] without contacting KMS once the deadline has
    /// passed, and [`SigningError::Kms`] when KMS does not sign.
    pub async fn sign(&self, input: &[u8], deadline: Deadline) -> Result<[u8; 64], SigningError> {
        let digest: [u8; 32] = Sha256::digest(input).into();
        let (result, attempts) = deadline
            .retry_once(ATTEMPT_TIMEOUT, KmsFailure::is_retryable, |timeout| {
                self.attempt(digest, timeout)
            })
            .await
            .ok_or(SigningError::DeadlineExceeded)?;
        result
            .map(|signature| signature.to_bytes().into())
            .map_err(|failure| {
                tracing::warn!(
                    dependency = Dependency::Kms.as_str(),
                    operation = "sign",
                    key_id = %self.key_id,
                    attempts,
                    class = failure.class().as_str(),
                    error = %ErrorChain(&failure),
                    "signing failed"
                );
                SigningError::Kms { attempts, failure }
            })
    }

    async fn attempt(&self, digest: [u8; 32], timeout: Duration) -> Result<Signature, KmsFailure> {
        let mut guard = AttemptGuard {
            signer: self,
            started: Instant::now(),
            finished: false,
        };
        let result = match tokio::time::timeout(
            timeout,
            self.client.sign_digest(&self.key_id, digest),
        )
        .await
        {
            Err(_) => Err(KmsFailure::Timeout),
            Ok(Err(failure)) => Err(failure),
            Ok(Ok(der)) => Signature::from_der(&der)
                .ok()
                .filter(|signature| self.public_key.verify_prehash(&digest, signature).is_ok())
                .ok_or(KmsFailure::InvalidResponse),
        };
        guard.finished = true;
        telemetry::record_call(
            Dependency::Kms,
            guard.started,
            result.as_ref().map(|_| ()).map_err(KmsFailure::class),
        );
        match &result {
            Ok(_) => self.consecutive_failures.store(0, Ordering::Release),
            Err(KmsFailure::Throttled(_)) => {}
            Err(_) => {
                self.consecutive_failures.fetch_add(1, Ordering::AcqRel);
            }
        }
        result
    }
}

use crate::{Audience, Claims, Issuer, JwkSet, TOKEN_TYPE};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The maximum accepted token lifetime.
pub const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);
/// The maximum accepted clock skew.
pub const MAX_LEEWAY: Duration = Duration::from_secs(60);

/// A key source could not provide a usable set of keys.
#[derive(Debug, thiserror::Error)]
#[error("verification keys unavailable")]
pub struct KeysUnavailable;

/// Supplies a key from a trusted source. Unknown IDs return `Ok(None)`.
pub trait KeySet: Send + Sync {
    /// Looks up a key by ID, or reports that the key source is unavailable.
    fn key(
        &self,
        kid: &str,
    ) -> impl Future<Output = Result<Option<VerifyingKey>, KeysUnavailable>> + Send;
}
impl KeySet for JwkSet {
    fn key(
        &self,
        kid: &str,
    ) -> impl Future<Output = Result<Option<VerifyingKey>, KeysUnavailable>> + Send {
        std::future::ready(Ok(self.find(kid).map(|key| *key.public_key())))
    }
}

/// A bounded reason for rejecting a token, suitable for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The compact token or its contents are malformed.
    Malformed,
    /// A protected header is unsupported.
    UnsupportedHeader,
    /// No trusted key matches the key ID.
    UnknownKey,
    /// Signature verification failed.
    BadSignature,
    /// Issuer does not match.
    WrongIssuer,
    /// Audience does not match.
    WrongAudience,
    /// The token has expired.
    Expired,
    /// The token is not yet valid.
    NotYetValid,
    /// The lifetime or issue time is invalid.
    InvalidLifetime,
    /// A required claim is absent.
    MissingClaim,
    /// Sender-constrained tokens are unsupported.
    SenderConstrained,
}
impl RejectionReason {
    /// Returns the stable, bounded telemetry label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedHeader => "unsupported_header",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::MissingClaim => "missing_claim",
            Self::SenderConstrained => "sender_constrained",
        }
    }
}

/// The result of rejecting an ownership token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The token is invalid or untrusted.
    #[error("invalid ownership token")]
    BadToken(RejectionReason),
    /// Verification keys are unavailable; the caller may retry later.
    #[error("verification keys unavailable")]
    KeysUnavailable,
    /// The supplied clock is before the Unix epoch.
    #[error("verification clock is before the Unix epoch")]
    InvalidClock,
}
impl VerifyError {
    /// Returns a bounded, non-sensitive reason for telemetry.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::BadToken(reason) => reason.as_str(),
            Self::KeysUnavailable => "keys_unavailable",
            Self::InvalidClock => "invalid_clock",
        }
    }
}

/// Invalid verifier configuration.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifierConfigError {
    /// At least one audience is required.
    #[error("at least one audience is required")]
    EmptyAudiences,
    /// Clock skew exceeds the permitted maximum.
    #[error("leeway exceeds the permitted maximum")]
    ExcessiveLeeway,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

const REQUIRED_CLAIMS: &[&str] = &["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "uc"];

// `crit` and `b64` change JWS interpretation; this verifier implements neither extension.
const FORBIDDEN_HEADER_PARAMETERS: &[&str] = &["jku", "x5u", "jwk", "x5c", "crit", "b64"];

struct CompactJws<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}
impl<'a> CompactJws<'a> {
    fn parse(token: &'a str) -> Result<Self, VerifyError> {
        let mut parts = token.split('.');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(header), Some(payload), Some(signature), None) => Ok(Self {
                header,
                payload,
                signature,
            }),
            _ => Err(VerifyError::BadToken(RejectionReason::Malformed)),
        }
    }
}
fn decode_json<T: DeserializeOwned>(part: &str) -> Result<T, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| VerifyError::BadToken(RejectionReason::Malformed))?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadToken(RejectionReason::Malformed))
}

/// Verifies the ownership token profile against a trusted key source.
#[derive(Debug)]
pub struct TokenVerifier {
    issuer: Issuer,
    audiences: HashSet<Audience>,
    leeway: Duration,
}
impl TokenVerifier {
    /// Creates a verifier for an exact issuer and at least one accepted audience.
    ///
    /// # Errors
    /// Returns an error when no audiences are supplied or leeway exceeds [`MAX_LEEWAY`].
    pub fn new(
        issuer: Issuer,
        audiences: impl IntoIterator<Item = Audience>,
        leeway: Duration,
    ) -> Result<Self, VerifierConfigError> {
        let audiences: HashSet<_> = audiences.into_iter().collect();
        if audiences.is_empty() {
            return Err(VerifierConfigError::EmptyAudiences);
        }
        if leeway > MAX_LEEWAY {
            return Err(VerifierConfigError::ExcessiveLeeway);
        }
        Ok(Self {
            issuer,
            audiences,
            leeway,
        })
    }

    /// Verifies a compact JWS using `keys` and the supplied clock time.
    ///
    /// # Errors
    /// Returns [`VerifyError::BadToken`] for rejected tokens and
    /// [`VerifyError::KeysUnavailable`] if the trusted key source is unavailable, or
    /// [`VerifyError::InvalidClock`] if the supplied time is before the Unix epoch.
    pub async fn verify(
        &self,
        token: &str,
        keys: &impl KeySet,
        now: SystemTime,
    ) -> Result<Claims, VerifyError> {
        use RejectionReason as R;
        let jws = CompactJws::parse(token)?;
        let header: Header = decode_json(jws.header)?;
        if header.alg != "ES256"
            || header.typ != TOKEN_TYPE
            || header.kid.is_empty()
            || FORBIDDEN_HEADER_PARAMETERS
                .iter()
                .any(|name| header.extra.contains_key(*name))
        {
            return Err(VerifyError::BadToken(R::UnsupportedHeader));
        }
        let key = keys
            .key(&header.kid)
            .await
            .map_err(|_| VerifyError::KeysUnavailable)?
            .ok_or(VerifyError::BadToken(R::UnknownKey))?;
        let sig = URL_SAFE_NO_PAD
            .decode(jws.signature)
            .map_err(|_| VerifyError::BadToken(R::Malformed))?;
        let sig = Signature::from_slice(&sig).map_err(|_| VerifyError::BadToken(R::Malformed))?;
        key.verify(format!("{}.{}", jws.header, jws.payload).as_bytes(), &sig)
            .map_err(|_| VerifyError::BadToken(R::BadSignature))?;
        let value: serde_json::Value = decode_json(jws.payload)?;
        let object = value
            .as_object()
            .ok_or(VerifyError::BadToken(R::Malformed))?;
        if object.contains_key("cnf") {
            return Err(VerifyError::BadToken(R::SenderConstrained));
        }
        if REQUIRED_CLAIMS
            .iter()
            .any(|name| !object.contains_key(*name))
        {
            return Err(VerifyError::BadToken(R::MissingClaim));
        }
        // Deserialize the original payload so duplicate claims are rejected by serde.
        let claims: Claims = decode_json(jws.payload)?;
        self.check_claims(&claims, now)?;
        Ok(claims)
    }
    fn check_claims(&self, claims: &Claims, now: SystemTime) -> Result<(), VerifyError> {
        use RejectionReason as R;
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::InvalidClock)?
            .as_secs();
        let leeway = self.leeway.as_secs();
        let reason = if claims.iss != self.issuer {
            Some(R::WrongIssuer)
        } else if !self.audiences.contains(&claims.aud) {
            Some(R::WrongAudience)
        } else if claims.exp <= claims.iat
            || claims.nbf < claims.iat
            || claims.exp - claims.iat > MAX_TOKEN_LIFETIME.as_secs()
            || claims.iat > now.saturating_add(leeway)
        {
            Some(R::InvalidLifetime)
        } else if now >= claims.exp.saturating_add(leeway) {
            Some(R::Expired)
        } else if now.saturating_add(leeway) < claims.nbf {
            Some(R::NotYetValid)
        } else {
            None
        };
        match reason {
            Some(reason) => Err(VerifyError::BadToken(reason)),
            None => Ok(()),
        }
    }
}

//! Error responses of the public API.

use axum::{
    Json,
    extract::{FromRequest, Request},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};

/// A failed public API request, rendered as `{"error": {"code": ..., "message": ...}}`.
///
/// A rejected exchange is [`ApiError::ChallengeUnusable`] or [`ApiError::ProofRejected`], and
/// neither says which check failed. A 503 says whether the client may retry the same request
/// (`retry_later`) or must request a new challenge (`request_new_challenge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// The body is not the expected JSON (400).
    MalformedRequest,
    /// The body is larger than the limit (413).
    BodyTooLarge,
    /// The audience is unknown or disabled (403).
    AudienceNotAllowed,
    /// The browser origin is not allowed for the audience (403).
    OriginNotAllowed,
    /// The proof, or the root it was made against, was rejected (401).
    ProofRejected,
    /// The challenge is unknown, expired, spent or already attempted (401).
    ChallengeUnusable,
    /// A dependency failed or the request ran out of time before anything was spent, or issuance
    /// is disabled (503). The client may retry the request.
    Unavailable,
    /// Verification capacity is exhausted; the client may retry after one second (503).
    Overloaded,
    /// The challenge may be spent: claiming it or a later step failed, or the token request ran
    /// past the request deadline (503). The client must request a new challenge.
    NeedsNewChallenge,
    /// KMS throttled signing after the challenge was consumed (503). The client may request a
    /// new challenge after one second.
    Throttled,
}

impl ApiError {
    fn parts(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::MalformedRequest => (
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "Malformed request",
            ),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body too large",
            ),
            Self::AudienceNotAllowed => (
                StatusCode::FORBIDDEN,
                "audience_not_allowed",
                "Audience not allowed",
            ),
            Self::OriginNotAllowed => (
                StatusCode::FORBIDDEN,
                "origin_not_allowed",
                "Origin not allowed",
            ),
            Self::ProofRejected => (StatusCode::UNAUTHORIZED, "proof_rejected", "Proof rejected"),
            Self::ChallengeUnusable => (
                StatusCode::UNAUTHORIZED,
                "challenge_unusable",
                "Challenge unusable",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "retry_later",
                "Service unavailable",
            ),
            Self::Overloaded => (
                StatusCode::SERVICE_UNAVAILABLE,
                "retry_later",
                "Service overloaded",
            ),
            Self::NeedsNewChallenge => (
                StatusCode::SERVICE_UNAVAILABLE,
                "request_new_challenge",
                "Service unavailable",
            ),
            Self::Throttled => (
                StatusCode::SERVICE_UNAVAILABLE,
                "request_new_challenge",
                "Signing throttled",
            ),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let mut response = (
            status,
            Json(ErrorBody {
                error: ErrorDetail { code, message },
            }),
        )
            .into_response();
        if matches!(self, Self::Overloaded | Self::Throttled) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

/// A JSON request body that rejects with [`ApiError::BodyTooLarge`] or
/// [`ApiError::MalformedRequest`].
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(ApiError::BodyTooLarge)
            }
            Err(_) => Err(ApiError::MalformedRequest),
        }
    }
}

//! Error responses of the public API.

use axum::{
    Json,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};

/// A failed public API request, rendered as `{"error": {"code": ..., "message": ...}}`.
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
    /// A dependency failed before anything was spent (503). The client may retry the request.
    Unavailable,
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
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "retry_later",
                "Service unavailable",
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
        (
            status,
            Json(ErrorBody {
                error: ErrorDetail { code, message },
            }),
        )
            .into_response()
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

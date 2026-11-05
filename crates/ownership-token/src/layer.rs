use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::SystemTime,
};

use axum::{
    body::Body,
    extract::FromRequestParts,
    http::{Request, Response, StatusCode, header::AUTHORIZATION, request::Parts},
    response::IntoResponse,
};
use tower::{Layer, Service};

use crate::{Claims, KeySet, TokenVerifier, VerifyError};

/// Verified ownership claims, available as an Axum extractor after [`OwnershipLayer`].
///
/// Without the layer, the extractor rejects with a 401 response.
#[derive(Debug, Clone)]
pub struct VerifiedOwnership(pub Claims);

impl<S: Send + Sync> FromRequestParts<S> for VerifiedOwnership {
    type Rejection = Rejection;
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Self>()
                .cloned()
                .ok_or(Rejection::MissingToken),
        )
    }
}

/// An exact request path that bypasses verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprotectedPath(String);

impl UnprotectedPath {
    /// Returns the exact path matched by the layer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid unprotected path.
#[derive(Debug, thiserror::Error)]
#[error("unprotected path must be an absolute path without query or fragment")]
pub struct InvalidUnprotectedPath;
impl std::str::FromStr for UnprotectedPath {
    type Err = InvalidUnprotectedPath;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed: axum::http::uri::PathAndQuery =
            value.parse().map_err(|_| InvalidUnprotectedPath)?;
        if !value.starts_with('/') || parsed.query().is_some() || value.contains('#') {
            return Err(InvalidUnprotectedPath);
        }
        Ok(Self(value.to_owned()))
    }
}

/// A Tower layer that verifies bearer tokens and removes client identity headers.
///
/// Paths configured with [`OwnershipLayer::with_unprotected_paths`] bypass authentication but
/// still have all `x-world-id-*` headers removed.
#[derive(Debug, Clone)]
pub struct OwnershipLayer<K> {
    verifier: Arc<TokenVerifier>,
    keys: K,
    unprotected_paths: Arc<Vec<UnprotectedPath>>,
    clock: fn() -> SystemTime,
}

impl<K> OwnershipLayer<K> {
    /// Creates a layer with the trusted verifier and key source.
    pub fn new(verifier: Arc<TokenVerifier>, keys: K) -> Self {
        Self {
            verifier,
            keys,
            unprotected_paths: Arc::new(Vec::new()),
            clock: SystemTime::now,
        }
    }
    /// Sets the clock used when verifying tokens.
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.clock = clock;
        self
    }
    /// Sets exact paths that bypass token verification.
    #[must_use]
    pub fn with_unprotected_paths(
        mut self,
        paths: impl IntoIterator<Item = UnprotectedPath>,
    ) -> Self {
        self.unprotected_paths = Arc::new(paths.into_iter().collect());
        self
    }
    /// Returns whether a path bypasses token verification.
    #[must_use]
    pub fn is_unprotected(&self, path: &str) -> bool {
        self.unprotected_paths
            .iter()
            .any(|entry| entry.as_str() == path)
    }
}

impl<S, K: Clone> Layer<S> for OwnershipLayer<K> {
    type Service = OwnershipService<S, K>;
    fn layer(&self, inner: S) -> Self::Service {
        OwnershipService {
            inner,
            layer: self.clone(),
        }
    }
}

/// The service created by [`OwnershipLayer`].
#[derive(Debug, Clone)]
pub struct OwnershipService<S, K> {
    inner: S,
    layer: OwnershipLayer<K>,
}

impl<S, K> Service<Request<Body>> for OwnershipService<S, K>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    K: KeySet + Clone + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        let layer = self.layer.clone();
        Box::pin(async move {
            let names: Vec<_> = request
                .headers()
                .keys()
                .filter(|name| is_identity_header(name.as_str()))
                .cloned()
                .collect();
            for name in names {
                request.headers_mut().remove(name);
            }
            request.extensions_mut().remove::<VerifiedOwnership>();
            if layer.is_unprotected(request.uri().path()) {
                return inner.call(request).await;
            }
            let Some(token) = bearer_token(request.headers()) else {
                return Ok(Rejection::MissingToken.into_response());
            };
            let claims = match layer
                .verifier
                .verify(token, &layer.keys, (layer.clock)())
                .await
            {
                Ok(claims) => claims,
                Err(error) => return Ok(Rejection::from(error).into_response()),
            };
            request.headers_mut().remove(AUTHORIZATION);
            request.extensions_mut().insert(VerifiedOwnership(claims));
            inner.call(request).await
        })
    }
}

fn is_identity_header(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    normalized.starts_with("x-world-id-")
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// An authentication rejection. The layer inserts it into response extensions.
#[derive(Debug, Clone, Copy)]
pub enum Rejection {
    /// No bearer token was supplied.
    MissingToken,
    /// The verifier rejected the request.
    Verify(VerifyError),
}

impl From<VerifyError> for Rejection {
    fn from(error: VerifyError) -> Self {
        Self::Verify(error)
    }
}

impl Rejection {
    /// Returns the non-sensitive rejection reason.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::Verify(error) => error.reason(),
        }
    }
}
impl IntoResponse for Rejection {
    fn into_response(self) -> Response<Body> {
        let (status, code, message) = match &self {
            Self::Verify(VerifyError::InvalidClock) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Verification clock unavailable",
            ),
            Self::Verify(VerifyError::KeysUnavailable) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "jwks_unavailable",
                "Verification keys unavailable",
            ),
            Self::MissingToken | Self::Verify(VerifyError::BadToken(_)) => (
                StatusCode::UNAUTHORIZED,
                "token_rejected",
                "Ownership token rejected",
            ),
        };
        let mut response = (
            status,
            axum::Json(serde_json::json!({"error": {"code": code, "message": message}})),
        )
            .into_response();
        response.extensions_mut().insert(self);
        response
    }
}

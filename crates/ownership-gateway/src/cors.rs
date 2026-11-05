//! Cross-origin access for browsers on origins that the audience policy allows.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};

use crate::{
    error::ApiError,
    policy::{AudiencePolicy, Policies},
};

/// How long a browser may cache a preflight answer, in seconds.
const PREFLIGHT_MAX_AGE_SECS: HeaderValue = HeaderValue::from_static("600");

fn allowed_origin<'a>(policies: &Policies, headers: &'a HeaderMap) -> Option<&'a HeaderValue> {
    headers.get(header::ORIGIN).filter(|origin| {
        origin
            .to_str()
            .is_ok_and(|origin| policies.allows_origin(origin))
    })
}

/// Adds the CORS headers to every response for an origin that an enabled audience allows:
/// the echoed origin and `Vary: Origin`.
pub(crate) async fn add_headers(
    State(policies): State<Arc<Policies>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = allowed_origin(&policies, request.headers()).cloned();
    let mut response = next.run(request).await;
    if let Some(origin) = origin {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    response
}

/// Answers a preflight for a `POST` that sends at most a `content-type` header from an origin
/// that an enabled audience allows. [`add_headers`] adds the origin headers.
pub(crate) async fn preflight(
    State(policies): State<Arc<Policies>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let post = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .is_some_and(|method| method == Method::POST.as_str());
    let content_type_only = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .is_none_or(|requested| {
            requested.to_str().is_ok_and(|names| {
                names
                    .split(',')
                    .all(|name| name.trim().eq_ignore_ascii_case("content-type"))
            })
        });
    if allowed_origin(&policies, &headers).is_none() || !post || !content_type_only {
        return Err(ApiError::OriginNotAllowed);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE_SECS);
    Ok(response)
}

/// Rejects a browser request whose origin `policy` does not allow. A request without an
/// `Origin` header does not come from a browser page and passes.
pub(crate) fn check_origin(policy: &AudiencePolicy, headers: &HeaderMap) -> Result<(), ApiError> {
    match headers.get(header::ORIGIN) {
        None => Ok(()),
        Some(origin)
            if origin
                .to_str()
                .is_ok_and(|origin| policy.allows_origin(origin)) =>
        {
            Ok(())
        }
        Some(_) => Err(ApiError::OriginNotAllowed),
    }
}

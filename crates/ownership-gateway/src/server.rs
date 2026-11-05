//! The public router and its middleware.

use std::time::Duration;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::post,
};

use crate::{
    challenge, cors, error::ApiError, exchange, retry::Deadline, state::AppState, telemetry,
};

const MAX_CHALLENGE_BODY_BYTES: usize = 4 * 1024;
const MAX_TOKEN_BODY_BYTES: usize = 1024 * 1024;

/// What a request that runs past the request deadline gets.
#[derive(Clone, Copy)]
struct RequestDeadline {
    budget: Duration,
    exceeded: ApiError,
}

/// Returns the public router, which issues challenges and exchanges proofs for tokens.
///
/// Each request runs in a span with a request ID and counts toward the HTTP metrics. It must
/// finish within the request deadline, including reading its body, or it gets a 503:
/// `retry_later` for a challenge request, which has spent nothing, and `request_new_challenge`
/// for a token request, which may have spent its challenge. Challenge request bodies are
/// limited to 4 KiB and token request bodies to 1 MiB. A token request beyond the verification
/// pool's capacity is shed before its body is read, which bounds the memory that buffered proofs
/// use. Every response, including a deadline 503, carries CORS headers for origins the audience
/// policy allows.
pub fn router(state: AppState) -> Router {
    let deadline = |exceeded| {
        middleware::from_fn_with_state(
            RequestDeadline {
                budget: state.request_deadline,
                exceeded,
            },
            enforce_deadline,
        )
    };
    Router::new()
        .route(
            "/v1/challenges",
            post(challenge::post_challenge)
                .layer(DefaultBodyLimit::max(MAX_CHALLENGE_BODY_BYTES))
                .options(cors::preflight)
                .layer(deadline(ApiError::Unavailable)),
        )
        .route(
            "/v1/tokens",
            post(exchange::post_token)
                .layer(DefaultBodyLimit::max(MAX_TOKEN_BODY_BYTES))
                .options(cors::preflight)
                .layer(deadline(ApiError::NeedsNewChallenge)),
        )
        .layer(middleware::from_fn_with_state(
            state.policies.clone(),
            cors::add_headers,
        ))
        .layer(middleware::from_fn(telemetry::observe_request))
        .with_state(state)
}

async fn enforce_deadline(
    State(RequestDeadline { budget, exceeded }): State<RequestDeadline>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(Deadline::after(budget));
    if let Ok(response) = tokio::time::timeout(budget, next.run(request)).await {
        response
    } else {
        tracing::warn!(
            deadline_ms = budget.as_millis(),
            "request deadline exceeded"
        );
        exceeded.into_response()
    }
}

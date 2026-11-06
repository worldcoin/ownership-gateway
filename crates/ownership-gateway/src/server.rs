//! The public and admin routers.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{get, post},
};

use crate::{challenge, cors, exchange, readiness, state::AppState};

const MAX_CHALLENGE_BODY_BYTES: usize = 4 * 1024;
const MAX_TOKEN_BODY_BYTES: usize = 1024 * 1024;

/// Returns the public router, which issues challenges and exchanges proofs for tokens.
///
/// Challenge request bodies are limited to 4 KiB and token request bodies to 1 MiB. A token
/// request beyond the verification pool's capacity is shed before its body is read, which
/// bounds the memory that buffered proofs use. Every response carries CORS headers for origins
/// the audience policy allows.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/challenges",
            post(challenge::post_challenge)
                .layer(DefaultBodyLimit::max(MAX_CHALLENGE_BODY_BYTES))
                .options(cors::preflight),
        )
        .route(
            "/v1/tokens",
            post(exchange::post_token)
                .layer(DefaultBodyLimit::max(MAX_TOKEN_BODY_BYTES))
                .options(cors::preflight),
        )
        .layer(middleware::from_fn_with_state(
            state.policies.clone(),
            cors::add_headers,
        ))
        .with_state(state)
}

/// Returns the probe router: `/health` for liveness, which makes no remote calls, and `/ready`
/// for readiness.
pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(readiness::ready))
        .with_state(state)
}

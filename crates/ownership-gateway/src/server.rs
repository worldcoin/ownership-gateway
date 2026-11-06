//! The public and admin routers.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{get, post},
};

use crate::{challenge, cors, readiness, state::AppState};

const MAX_CHALLENGE_BODY_BYTES: usize = 4 * 1024;

/// Returns the public router, which issues challenges. Challenge request bodies are limited to
/// 4 KiB, and every response carries CORS headers for origins the audience policy allows.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/challenges",
            post(challenge::post_challenge)
                .layer(DefaultBodyLimit::max(MAX_CHALLENGE_BODY_BYTES))
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

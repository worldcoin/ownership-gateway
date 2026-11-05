//! The JWKS deployment: public signing keys and its probes.

use std::sync::{Arc, RwLock};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use ownership_token::JwkSet;

use crate::{error::ApiError, shutdown::Shutdown, telemetry};

/// The key set to publish was empty.
#[derive(Debug, thiserror::Error)]
#[error("a published key set must contain at least one key")]
pub struct EmptyKeySet;

/// The public keys the JWKS deployment serves, once they have loaded.
#[derive(Clone, Default)]
pub struct JwksState(Arc<RwLock<Option<JwkSet>>>);

impl JwksState {
    /// Publishes `keys`, replacing any keys published before.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyKeySet`] and publishes nothing if `keys` is empty.
    pub fn publish(&self, keys: JwkSet) -> Result<(), EmptyKeySet> {
        if keys.keys().is_empty() {
            return Err(EmptyKeySet);
        }
        metrics::gauge!("ownership_gateway.jwks.keys").set(f64::from(
            u32::try_from(keys.keys().len()).unwrap_or(u32::MAX),
        ));
        *self.0.write().expect("the JWKS lock is not poisoned") = Some(keys);
        Ok(())
    }

    fn keys(&self) -> Option<JwkSet> {
        self.0
            .read()
            .expect("the JWKS lock is not poisoned")
            .clone()
    }
}

/// Returns the public router: `/.well-known/jwks.json`, which answers 503 until keys are
/// published and then serves them with `Cache-Control: public, max-age=300`. Requests count
/// toward the HTTP metrics.
pub fn router(state: JwksState) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .layer(axum::middleware::from_fn(telemetry::observe_request))
        .with_state(state)
}

async fn jwks(State(state): State<JwksState>) -> Response {
    let Some(keys) = state.keys() else {
        return ApiError::Unavailable.into_response();
    };
    metrics::counter!("ownership_gateway.jwks.served").increment(1);
    ([(header::CACHE_CONTROL, "public, max-age=300")], Json(keys)).into_response()
}

/// Returns the probe router: `/health` for liveness, and `/ready`, which answers 200 once keys
/// are published and until shutdown starts.
pub fn admin_router(state: JwksState, shutdown: Shutdown) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(ready))
        .with_state((state, shutdown))
}

async fn ready(State((state, shutdown)): State<(JwksState, Shutdown)>) -> StatusCode {
    if state.keys().is_some() && !shutdown.has_started() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

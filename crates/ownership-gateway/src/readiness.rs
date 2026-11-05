//! Readiness of the issuance server.

use axum::{extract::State, http::StatusCode};

use crate::{
    state::AppState,
    telemetry::{self, Dependency},
};

/// Answers `/ready`: 200 when Redis accepts a write and 503 otherwise, so a pod connected to a
/// replica after a failover is taken out of service until its store reconnects.
pub(crate) async fn ready(State(state): State<AppState>) -> StatusCode {
    let redis = state.store.check_writable().await.is_ok();
    telemetry::set_ready(Dependency::Redis, redis);
    if redis {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

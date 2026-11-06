//! Readiness of the issuance server.

use axum::{extract::State, http::StatusCode};

use crate::{
    state::AppState,
    telemetry::{self, Dependency},
};

/// Answers `/ready`: 200 when Redis accepts a write, the signer is ready and root checks are
/// not failing, and 503 otherwise. Requiring a write takes a pod connected to a replica after a
/// failover out of service until its store reconnects.
pub(crate) async fn ready(State(state): State<AppState>) -> StatusCode {
    let redis = state.store.check_writable().await.is_ok();
    let kms = state.exchange.signer.is_ready();
    let root = state.exchange.roots.is_ready();
    telemetry::set_ready(Dependency::Redis, redis);
    telemetry::set_ready(Dependency::Kms, kms);
    telemetry::set_ready(Dependency::Root, root);
    if redis && kms && root {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

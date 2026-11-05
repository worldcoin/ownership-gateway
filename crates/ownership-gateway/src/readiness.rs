//! Readiness of the issuance server, from startup to shutdown, and the background checks that
//! let it recover without traffic.

use std::{
    net::SocketAddr,
    ops::RangeInclusive,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use eyre::WrapErr as _;
use tokio::{net::TcpSocket, task::JoinHandle};
use world_id_primitives::FieldElement;

use crate::{
    exchange::Exchange,
    retry::{Deadline, jittered},
    shutdown::Shutdown,
    state::AppState,
    telemetry::{self, Dependency},
};

const RECOVERY_INTERVAL: RangeInclusive<Duration> =
    Duration::from_secs(20)..=Duration::from_secs(40);
const PROBE_BUDGET: Duration = Duration::from_secs(5);
/// The connection backlog of the admin listener, as `TcpListener::bind` uses.
const LISTEN_BACKLOG: u32 = 1024;

/// What the admin probes report about an issuance server that may still be starting.
///
/// The verifier artifacts load before the admin server starts (see [`serve_admin_after`]), so
/// until [`AdminState::serve`] is called the server is loading its signing key.
#[derive(Clone)]
pub struct AdminState {
    serving: Arc<OnceLock<AppState>>,
    shutdown: Shutdown,
}

impl AdminState {
    /// Returns the state of a server that is loading its signing key.
    #[must_use]
    pub fn new(shutdown: Shutdown) -> Self {
        Self {
            serving: Arc::new(OnceLock::new()),
            shutdown,
        }
    }

    /// Marks the server as serving with `state`. Later calls have no effect.
    pub fn serve(&self, state: AppState) {
        let _ = self.serving.set(state);
    }
}

/// Returns the probe router.
///
/// `/health` answers 200 and makes no remote calls. `/ready` answers 503 while the signing key
/// loads and once shutdown has started. Otherwise it answers 200 when Redis accepts a write, the
/// signer is ready and root checks are not failing, and 503 if any of them is not. Requiring a
/// write takes a pod connected to a replica after a failover out of service until its store
/// reconnects.
pub fn admin_router(admin: AdminState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(ready))
        .with_state(admin)
}

async fn ready(State(admin): State<AdminState>) -> StatusCode {
    if admin.shutdown.has_started() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let Some(state) = admin.serving.get() else {
        telemetry::set_ready(Dependency::Kms, false);
        return StatusCode::SERVICE_UNAVAILABLE;
    };
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

/// A running admin server.
pub struct AdminServer {
    /// The address it listens on.
    pub address: SocketAddr,
    /// The server task, which finishes only if the server fails.
    pub task: JoinHandle<std::io::Result<()>>,
}

/// Binds a socket for the admin server without listening on it, so the port is reserved while
/// connections to it are still refused.
///
/// # Errors
///
/// Returns an error if `address` cannot be bound.
pub fn bind_admin(address: SocketAddr) -> std::io::Result<TcpSocket> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    Ok(socket)
}

/// Awaits `load_verifier`, and only then listens on `socket` (see [`bind_admin`]) and serves the
/// admin probes, so a startup probe on `/health` fails until the verifier artifacts are loaded.
///
/// # Errors
///
/// Returns the error of `load_verifier`, or an error if the socket cannot listen.
pub async fn serve_admin_after<T>(
    load_verifier: impl Future<Output = eyre::Result<T>>,
    socket: TcpSocket,
    admin: AdminState,
) -> eyre::Result<(T, AdminServer)> {
    let verifier = load_verifier.await?;
    let listener = socket
        .listen(LISTEN_BACKLOG)
        .wrap_err("listening on the admin address")?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(axum::serve(listener, admin_router(admin)).into_future());
    Ok((verifier, AdminServer { address, task }))
}

/// Every 20 to 40 seconds, probes the root service and the signer if they are unready, so
/// readiness recovers on a pod that gets no traffic while it is unready. Never returns.
pub async fn recover_dependencies(exchange: Arc<Exchange>) {
    loop {
        tokio::time::sleep(jittered(RECOVERY_INTERVAL)).await;
        if !exchange.roots.is_ready() {
            // The zero root is never registered; the root service answers `{"valid": false}`,
            // which is a verdict and so restores readiness.
            exchange
                .roots
                .check(FieldElement::ZERO, Deadline::after(PROBE_BUDGET))
                .await;
        }
        if !exchange.signer.is_ready() {
            // The signer logs and counts its own failures.
            let _ = exchange
                .signer
                .sign(
                    b"ownership-gateway/readiness-probe",
                    Deadline::after(PROBE_BUDGET),
                )
                .await;
        }
    }
}

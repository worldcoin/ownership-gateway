//! Graceful shutdown on `SIGTERM` or `SIGINT`.

use std::{io, time::Duration};

use axum::Router;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::watch,
};

/// Starts the shutdown that every [`Shutdown`] from the same channel observes.
pub struct ShutdownTrigger(watch::Sender<bool>);

/// Observes whether the process is shutting down.
#[derive(Clone)]
pub struct Shutdown(watch::Receiver<bool>);

/// Returns a trigger and the shutdown it starts.
#[must_use]
pub fn channel() -> (ShutdownTrigger, Shutdown) {
    let (trigger, shutdown) = watch::channel(false);
    (ShutdownTrigger(trigger), Shutdown(shutdown))
}

impl ShutdownTrigger {
    /// Starts the shutdown. Starting it again has no effect.
    pub fn start(&self) {
        self.0.send_replace(true);
    }
}

impl Shutdown {
    /// Whether the shutdown has started.
    #[must_use]
    pub fn has_started(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once the shutdown has started, or once its trigger is dropped.
    pub async fn started(mut self) {
        let _ = self.0.wait_for(|started| *started).await;
    }
}

/// Installs `SIGTERM` and `SIGINT` handlers and returns a future that resolves on either
/// signal.
///
/// # Errors
///
/// Returns an error if the handlers cannot be installed.
pub fn signals() -> io::Result<impl Future<Output = ()>> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

/// Serves `router` on `listener` until `shutdown` starts, then stops accepting connections and
/// waits up to `grace` for requests in flight to finish.
///
/// Returns once every request has finished or `grace` has passed. Requests still running then
/// keep running until the process exits, so the caller should exit soon after.
///
/// # Errors
///
/// Returns an error if the server fails.
pub async fn serve_until_drained(
    listener: TcpListener,
    router: Router,
    shutdown: Shutdown,
    grace: Duration,
) -> io::Result<()> {
    let server = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown.clone().started())
        .into_future();
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result,
        () = shutdown.started() => {}
    }
    if let Ok(result) = tokio::time::timeout(grace, server).await {
        result
    } else {
        tracing::warn!(
            grace_secs = grace.as_secs(),
            "requests were still running when the shutdown grace period ended"
        );
        Ok(())
    }
}

//! A sidecar that verifies ownership tokens before forwarding to a local application.

pub mod config;
mod server;

use anyhow::Context as _;
use axum::{Router, extract::State, http::StatusCode, routing::get};
use ownership_token::{RemoteJwks, TokenVerifier};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

const GAUGE_INTERVAL: Duration = Duration::from_secs(15);

/// Runs the configured proxy until SIGINT or SIGTERM.
///
/// # Errors
///
/// Returns an error on invalid configuration, listener failure, or server failure.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let jwks = RemoteJwks::with_failure_observer(config.jwks_url.clone(), |error| {
        metrics::counter!("ownership_proxy.jwks.fetch_failures", "class" => error.class())
            .increment(1);
    })?;
    let proxy = TcpListener::bind(config.listen)
        .await
        .context("binding proxy listener")?;
    let admin = TcpListener::bind(config.admin_listen)
        .await
        .context("binding admin listener")?;
    serve(config, jwks, proxy, admin, shutdown_signal()).await
}

/// Serves proxy and admin listeners until `shutdown` completes, then drains active requests.
///
/// `jwks` must refer to the configured trusted key source; it is refreshed in the background.
///
/// # Errors
///
/// Returns an error for invalid configuration or if either server stops unexpectedly.
pub async fn serve(
    config: config::Config,
    jwks: RemoteJwks,
    proxy: TcpListener,
    admin: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let verifier = Arc::new(TokenVerifier::new(
        config.issuer.clone(),
        config.audiences.clone(),
        ownership_token::MAX_LEEWAY,
    )?);
    // Fetch failures are reported to the failure observer and logged.
    let _ = jwks.refresh().await;
    let (stop, stop_rx) = watch::channel(false);
    let mut tasks = start_tasks(config, jwks, proxy, admin, verifier, stop_rx);
    tokio::pin!(shutdown);
    let result = tokio::select! {
        () = &mut shutdown => Ok(()),
        stopped = tasks.proxy.join_next() => Err(task_stopped("proxy", stopped)),
        stopped = tasks.helpers.join_next() => Err(task_stopped("helper", stopped)),
    };
    // The admin server stays alive while readiness is false and the proxy drains.
    stop.send_replace(true);
    let drained = drain_tasks(&mut tasks.proxy, &mut tasks.helpers).await;
    result.and(drained)
}

struct Tasks {
    proxy: JoinSet<anyhow::Result<()>>,
    helpers: JoinSet<anyhow::Result<()>>,
}

fn start_tasks(
    config: config::Config,
    jwks: RemoteJwks,
    proxy: TcpListener,
    admin: TcpListener,
    verifier: Arc<TokenVerifier>,
    stop: watch::Receiver<bool>,
) -> Tasks {
    let mut helpers = JoinSet::new();
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(readiness))
        .with_state(AdminState {
            jwks: jwks.clone(),
            stop: stop.clone(),
        });
    helpers.spawn(async move { axum::serve(admin, app).await.map_err(anyhow::Error::from) });
    let keys_for_proxy = jwks.clone();
    let refresh = jwks.clone();
    helpers.spawn(async move {
        refresh.run_refresh().await;
        Ok(())
    });
    helpers.spawn(async move { report_jwks_gauges(jwks).await });
    // JoinSet can be polled again during drain after the select is cancelled.
    let mut proxy_task = JoinSet::new();
    proxy_task.spawn(async move {
        server::serve(proxy, config, verifier, keys_for_proxy, stop)
            .await
            .map_err(anyhow::Error::from)
    });
    Tasks {
        proxy: proxy_task,
        helpers,
    }
}

fn task_stopped(
    name: &str,
    result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(Ok(()))) | None => anyhow::anyhow!("{name} exited unexpectedly"),
        Some(Ok(Err(error))) => error.context(format!("{name} failed")),
        Some(Err(error)) => anyhow::Error::new(error).context(format!("{name} task failed")),
    }
}

async fn drain_tasks(
    proxy: &mut JoinSet<anyhow::Result<()>>,
    helpers: &mut JoinSet<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let mut result = Ok(());
    while !proxy.is_empty() {
        tokio::select! {
            stopped = proxy.join_next() => {
                match stopped {
                    Some(Ok(Ok(()))) | None => {},
                    other => if result.is_ok() { result = Err(task_stopped("proxy during drain", other)); },
                }
            }
            stopped = helpers.join_next(), if !helpers.is_empty() => {
                if result.is_ok() { result = Err(task_stopped("helper during drain", stopped)); }
            }
        }
    }
    helpers.abort_all();
    while helpers.join_next().await.is_some() {}
    result
}

#[derive(Clone)]
struct AdminState {
    jwks: RemoteJwks,
    stop: watch::Receiver<bool>,
}
async fn readiness(State(state): State<AdminState>) -> StatusCode {
    if !*state.stop.borrow() && state.jwks.is_usable() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn report_jwks_gauges(jwks: RemoteJwks) -> anyhow::Result<()> {
    loop {
        metrics::gauge!("ownership_proxy.jwks.usable").set(if jwks.is_usable() {
            1.0
        } else {
            0.0
        });
        if let Some(age) = jwks.age() {
            metrics::gauge!("ownership_proxy.jwks.age_seconds").set(age.as_secs_f64());
        }
        tokio::time::sleep(GAUGE_INTERVAL).await;
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

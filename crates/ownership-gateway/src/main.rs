//! The ownership gateway binary.

use std::{ops::RangeInclusive, sync::Arc, time::Duration};

use clap::Parser as _;
use eyre::{WrapErr as _, eyre};
use ownership_gateway::{
    config::{Command, Config, JwksConfig, PublishedKeyIds, ServeConfig},
    exchange::Exchange,
    jwks::{self, JwksState},
    policy::Policies,
    readiness::{AdminState, bind_admin, recover_dependencies, serve_admin_after},
    retry::jittered,
    root::RootValidator,
    server::router,
    shutdown::{self, Shutdown, serve_until_drained},
    signing::{AwsKms, KmsClient, KmsSigner, load_jwk},
    state::AppState,
    store::RedisStore,
    verification::{EmbeddedVerifier, VerificationPool},
};
use ownership_token::JwkSet;
use tokio::net::TcpListener;

/// The pause between attempts of a startup step that waits for a dependency.
const STARTUP_RETRY: RangeInclusive<Duration> = Duration::from_secs(20)..=Duration::from_secs(40);

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("installing the TLS crypto provider"))?;
    let _telemetry = ownership_gateway::telemetry::init().wrap_err("initializing telemetry")?;
    match Config::parse().command {
        Command::Serve(config) => serve(*config).await,
        Command::Jwks(config) => serve_jwks(config).await,
    }
}

async fn serve(config: ServeConfig) -> eyre::Result<()> {
    let shutdown = listen_for_shutdown()?;
    let policies = Policies::load(&config.audience_policy_path)?;
    let admin = AdminState::new(shutdown.clone());
    let admin_socket = bind_admin(config.listeners.admin).wrap_err("binding the admin address")?;
    let (verifier, admin_server) =
        serve_admin_after(load_verifier(), admin_socket, admin.clone()).await?;
    let kms: Arc<dyn KmsClient> = Arc::new(load_kms().await);
    let signer = tokio::select! {
        signer = retry_forever("kms", "load_signing_key", async || {
            KmsSigner::load(
                kms.clone(),
                config.kms_signing_key_id.to_string(),
                config.kms_failure_threshold,
            )
            .await
            .wrap_err_with(|| format!("loading signing key {}", config.kms_signing_key_id))
        }) => signer,
        () = shutdown.clone().started() => return Ok(()),
    };
    let state = build_state(&config, policies, verifier, signer)?;
    admin.serve(state.clone());
    let public = TcpListener::bind(config.listeners.public)
        .await
        .wrap_err("binding the public listener")?;
    let recovery = tokio::spawn(recover_dependencies(state.exchange.clone()));
    let public = serve_until_drained(
        public,
        router(state),
        shutdown,
        config.listeners.shutdown_grace,
    );
    let result = tokio::select! {
        result = public => {
            result.wrap_err("public server failed")
        }
        stopped = admin_server.task => Err(eyre!("admin server stopped: {stopped:?}")),
    };
    recovery.abort();
    result
}

/// Starts the shutdown on `SIGTERM` or `SIGINT`.
fn listen_for_shutdown() -> eyre::Result<Shutdown> {
    let signals = shutdown::signals().wrap_err("installing signal handlers")?;
    let (trigger, shutdown) = shutdown::channel();
    tokio::spawn(async move {
        signals.await;
        trigger.start();
    });
    Ok(shutdown)
}

async fn load_verifier() -> eyre::Result<EmbeddedVerifier> {
    tokio::task::spawn_blocking(EmbeddedVerifier::load)
        .await?
        .wrap_err("loading the verifier artifacts")
}

fn build_state(
    config: &ServeConfig,
    policies: Policies,
    verifier: EmbeddedVerifier,
    signer: KmsSigner,
) -> eyre::Result<AppState> {
    let exchange = Exchange {
        issuer: config.issuer.clone(),
        use_case: config.use_case.clone(),
        verification: VerificationPool::new(
            Arc::new(verifier),
            config.verify_concurrency,
            config.verify_queue_depth,
        ),
        roots: Arc::new(
            RootValidator::new(&config.root_source_url, config.root_failure_window)
                .wrap_err("building the root client")?,
        ),
        signer: Arc::new(signer),
    };
    Ok(AppState {
        store: Arc::new(RedisStore::new(&config.redis_url).wrap_err("configuring Redis")?),
        policies: Arc::new(policies),
        token_url: config.token_url(),
        challenge_ttl: config.challenge_ttl,
        request_deadline: config.request_deadline,
        exchange: Arc::new(exchange),
        issuance_enabled: config.token_issuance_enabled,
    })
}

async fn serve_jwks(config: JwksConfig) -> eyre::Result<()> {
    let shutdown = listen_for_shutdown()?;
    let state = JwksState::default();
    let public = TcpListener::bind(config.listeners.public)
        .await
        .wrap_err("binding the public listener")?;
    let admin = TcpListener::bind(config.listeners.admin)
        .await
        .wrap_err("binding the admin listener")?;
    let admin_server = tokio::spawn(
        axum::serve(admin, jwks::admin_router(state.clone(), shutdown.clone())).into_future(),
    );
    let load_keys = async {
        let kms = load_kms().await;
        let keys = retry_forever("kms", "load_public_keys", async || {
            load_published_keys(&kms, &config.published_key_ids).await
        })
        .await;
        state.publish(keys).wrap_err("publishing public keys")?;
        std::future::pending().await
    };
    let public = serve_until_drained(
        public,
        jwks::router(state.clone()),
        shutdown,
        config.listeners.shutdown_grace,
    );
    tokio::select! {
        result = public => {
            result.wrap_err("public server failed")
        }
        stopped = admin_server => Err(eyre!("admin server stopped: {stopped:?}")),
        result = load_keys => result,
    }
}

async fn load_kms() -> AwsKms {
    AwsKms::new(
        &aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await,
    )
}

/// Loads every published key, failing if any one fails.
async fn load_published_keys(kms: &AwsKms, ids: &PublishedKeyIds) -> eyre::Result<JwkSet> {
    let mut keys = Vec::new();
    for id in ids.iter() {
        let key = load_jwk(kms, id.as_str())
            .await
            .wrap_err_with(|| format!("loading public key {id}"))?;
        keys.push(key);
    }
    Ok(JwkSet::new(keys))
}

/// Runs a startup step until it succeeds, logging each failure and pausing 20 to 40 seconds
/// between attempts.
async fn retry_forever<T>(
    dependency: &'static str,
    operation: &'static str,
    mut step: impl AsyncFnMut() -> eyre::Result<T>,
) -> T {
    loop {
        match step().await {
            Ok(value) => return value,
            Err(error) => tracing::warn!(
                dependency,
                operation,
                error = format!("{error:#}"),
                "startup step failed; retrying"
            ),
        }
        tokio::time::sleep(jittered(STARTUP_RETRY)).await;
    }
}

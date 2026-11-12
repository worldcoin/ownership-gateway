//! The ownership gateway binary.

use std::{ops::RangeInclusive, sync::Arc, time::Duration};

use clap::Parser as _;
use eyre::{WrapErr as _, eyre};
use ownership_gateway::{
    config::{Command, Config, JwksConfig, PublishedKeyIds, ServeConfig},
    exchange::Exchange,
    jwks::{self, JwksState},
    policy::Policies,
    retry::jittered,
    root::RootValidator,
    server::{admin_router, router},
    signing::{AwsKms, KmsSigner, load_jwk},
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
    let _telemetry = telemetry_batteries::init().wrap_err("initializing telemetry")?;
    match Config::parse().command {
        Command::Serve(config) => serve(*config).await,
        Command::Jwks(config) => serve_jwks(config).await,
    }
}

async fn serve(config: ServeConfig) -> eyre::Result<()> {
    let state = build_state(&config).await?;
    let public = TcpListener::bind(config.listeners.public)
        .await
        .wrap_err("binding the public listener")?;
    let admin = TcpListener::bind(config.listeners.admin)
        .await
        .wrap_err("binding the admin listener")?;
    let public_router = router(state.clone());
    tokio::try_join!(
        async {
            axum::serve(public, public_router)
                .await
                .wrap_err("public server failed")
        },
        async {
            axum::serve(admin, admin_router(state))
                .await
                .wrap_err("admin server failed")
        },
    )?;
    Ok(())
}

/// Loads the verifier artifacts and the signing key and connects the dependencies.
async fn build_state(config: &ServeConfig) -> eyre::Result<AppState> {
    let policies = Policies::load(&config.audience_policy_path)?;
    let verifier = tokio::task::spawn_blocking(EmbeddedVerifier::load)
        .await
        .wrap_err("loading the verifier artifacts")?
        .wrap_err("loading the verifier artifacts")?;
    let signer = KmsSigner::load(
        Arc::new(load_kms().await),
        config.kms_signing_key_id.to_string(),
        config.kms_failure_threshold,
    )
    .await
    .wrap_err_with(|| format!("loading signing key {}", config.kms_signing_key_id))?;
    let exchange = Exchange {
        issuer: config.issuer.clone(),
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
    })
}

async fn serve_jwks(config: JwksConfig) -> eyre::Result<()> {
    let state = JwksState::default();
    let public = TcpListener::bind(config.listeners.public)
        .await
        .wrap_err("binding the public listener")?;
    let admin = TcpListener::bind(config.listeners.admin)
        .await
        .wrap_err("binding the admin listener")?;
    let load_keys = async {
        let kms = load_kms().await;
        let keys = retry_forever("kms", "load_public_keys", async || {
            load_published_keys(&kms, &config.published_key_ids).await
        })
        .await;
        state.publish(keys).wrap_err("publishing public keys")
    };
    tokio::try_join!(
        async {
            axum::serve(public, jwks::router(state.clone()))
                .await
                .wrap_err("public server failed")
        },
        async {
            axum::serve(admin, jwks::admin_router(state.clone()))
                .await
                .wrap_err("admin server failed")
        },
        load_keys,
    )?;
    Ok(())
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

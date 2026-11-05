//! The ownership gateway binary.

use std::sync::Arc;

use clap::Parser as _;
use eyre::{WrapErr as _, eyre};
use ownership_gateway::{
    config::{Command, Config, ServeConfig},
    policy::Policies,
    server::{admin_router, router},
    state::AppState,
    store::RedisStore,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("installing the TLS crypto provider"))?;
    let _telemetry = telemetry_batteries::init().wrap_err("initializing telemetry")?;
    match Config::parse().command {
        Command::Serve(config) => serve(*config).await,
    }
}

async fn serve(config: ServeConfig) -> eyre::Result<()> {
    let state = AppState {
        store: Arc::new(RedisStore::new(&config.redis_url).wrap_err("configuring Redis")?),
        policies: Arc::new(Policies::load(&config.audience_policy_path)?),
        token_url: config.token_url(),
        challenge_ttl: config.challenge_ttl,
        request_deadline: config.request_deadline,
    };
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

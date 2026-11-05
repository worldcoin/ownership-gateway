//! The ownership-proxy sidecar.
use clap::Parser as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("initializing telemetry: {error:?}"))?;
    ownership_proxy::run(ownership_proxy::config::Config::parse()).await
}

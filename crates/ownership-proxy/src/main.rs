//! The ownership-proxy sidecar.
use clap::Parser as _;

mod telemetry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = telemetry::init()?;
    ownership_proxy::run(ownership_proxy::config::Config::parse()).await
}

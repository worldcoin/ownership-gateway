//! Shared setup for the gateway's integration tests.
// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use ownership_gateway::store::RedisStore;
use testcontainers::{ContainerAsync, ContainerRequest, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::redis::Redis;

/// Installs the process-wide TLS crypto provider, as the gateway's `main` does.
pub(crate) fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("no other provider is installed");
    });
}

/// Docker Hub's official Redis image, from its ECR Public mirror, which does not rate-limit CI.
pub(crate) const REDIS_IMAGE: &str = "public.ecr.aws/docker/library/redis";
pub(crate) const REDIS_TAG: &str = "7.2";

/// A request for a [`REDIS_IMAGE`] container.
pub(crate) fn redis_image() -> ContainerRequest<Redis> {
    Redis::default().with_name(REDIS_IMAGE).with_tag(REDIS_TAG)
}

/// A Redis container and a plaintext store connected to it.
pub(crate) struct TestRedis {
    pub(crate) container: ContainerAsync<Redis>,
    pub(crate) store: RedisStore,
    pub(crate) url: String,
}

impl TestRedis {
    pub(crate) async fn start() -> Self {
        install_crypto_provider();
        let container = redis_image().start().await.unwrap();
        let port = container.get_host_port_ipv4(6379).await.unwrap();
        let url = format!("redis://127.0.0.1:{port}");
        let store = plaintext_store(&url);
        Self {
            container,
            store,
            url,
        }
    }

    /// Opens a separate connection for inspecting and changing stored keys directly.
    pub(crate) async fn connection(&self) -> redis::aio::MultiplexedConnection {
        redis::Client::open(self.url.as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap()
    }
}

/// A store for a plaintext Redis URL, which production configuration rejects.
pub(crate) fn plaintext_store(url: &str) -> RedisStore {
    RedisStore::from_client(redis::Client::open(url).unwrap()).unwrap()
}

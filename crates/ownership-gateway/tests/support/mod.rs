//! Shared setup for the gateway's integration tests.
// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use axum::Router;
use ownership_gateway::{
    policy::Policies,
    server::{admin_router, router},
    state::AppState,
    store::{ChallengeStore, RedisStore},
};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use testcontainers::{ContainerAsync, ContainerRequest, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::redis::Redis;
use tokio::{net::TcpListener, task::JoinHandle};

pub(crate) const ISSUER: &str = "https://issuer.example/base";

/// `service-a` allows one browser origin and issues 15-minute tokens; `service-b` allows no
/// browser origins; `disabled` is listed but disabled.
pub(crate) const POLICIES: &str = r#"[
    {"aud":"service-a","enabled":true,"token_ttl_secs":900,"allowed_origins":["https://app.example"]},
    {"aud":"service-b","enabled":true,"token_ttl_secs":600,"allowed_origins":[]},
    {"aud":"disabled","enabled":false,"token_ttl_secs":600,"allowed_origins":["https://disabled.example"]}
]"#;

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

/// An unreachable Redis: connections to port 1 are refused.
pub(crate) fn unreachable_store() -> RedisStore {
    plaintext_store("redis://127.0.0.1:1")
}

/// Gateway state with [`POLICIES`], issuer [`ISSUER`] and the spec's default lifetimes.
pub(crate) fn app_state(store: Arc<dyn ChallengeStore>) -> AppState {
    AppState {
        store,
        policies: Arc::new(Policies::parse(POLICIES.as_bytes()).unwrap()),
        token_url: format!("{ISSUER}/v1/tokens").parse().unwrap(),
        challenge_ttl: Duration::from_mins(2),
        request_deadline: Duration::from_secs(5),
    }
}

/// A server on a local port, stopped when dropped.
pub(crate) struct TestServer {
    pub(crate) url: String,
    task: JoinHandle<()>,
}

impl TestServer {
    pub(crate) async fn start(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, task }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The gateway's public and admin routers, served on local ports.
pub(crate) struct TestGateway {
    pub(crate) public: TestServer,
    pub(crate) admin: TestServer,
    pub(crate) client: reqwest::Client,
}

impl TestGateway {
    pub(crate) async fn start(state: AppState) -> Self {
        Self {
            public: TestServer::start(router(state.clone())).await,
            admin: TestServer::start(admin_router(state)).await,
            client: reqwest::Client::new(),
        }
    }

    /// Sends a JSON `POST` to a public path, optionally from a browser `origin`.
    pub(crate) async fn post(
        &self,
        path: &str,
        body: &Value,
        origin: Option<&str>,
    ) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("{}{path}", self.public.url))
            .json(body);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request.send().await.unwrap()
    }

    /// Sends a raw body with a JSON content type to a public path.
    pub(crate) async fn post_raw(
        &self,
        path: &str,
        body: impl Into<reqwest::Body>,
    ) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.public.url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    /// Sends a CORS preflight for a public path.
    pub(crate) async fn preflight(
        &self,
        path: &str,
        origin: &str,
        method: &str,
        headers: &str,
    ) -> reqwest::Response {
        self.client
            .request(Method::OPTIONS, format!("{}{path}", self.public.url))
            .header("origin", origin)
            .header("access-control-request-method", method)
            .header("access-control-request-headers", headers)
            .send()
            .await
            .unwrap()
    }

    /// Returns the status of an admin probe.
    pub(crate) async fn probe(&self, path: &str) -> StatusCode {
        self.client
            .get(format!("{}{path}", self.admin.url))
            .send()
            .await
            .unwrap()
            .status()
    }

    /// Issues a challenge and returns the response body.
    pub(crate) async fn challenge(&self, aud: &str) -> Value {
        let response = self
            .post("/v1/challenges", &serde_json::json!({ "aud": aud }), None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }
}

/// Returns the `error.code` of an error response.
pub(crate) async fn error_code(response: reqwest::Response) -> String {
    let body: Value = response.json().await.unwrap();
    body["error"]["code"].as_str().unwrap().to_owned()
}

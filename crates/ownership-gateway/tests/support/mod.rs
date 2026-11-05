//! Shared setup for the gateway's integration tests.
// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::Router;
use eddsa_babyjubjub::EdDSAPrivateKey;
use ownership_gateway::{
    policy::Policies,
    server::{admin_router, router},
    state::AppState,
    store::{ChallengeStore, RedisStore},
    verification::{ProofVerifier, V1Proof},
};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use testcontainers::{ContainerAsync, ContainerRequest, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::redis::Redis;
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    proof::OwnershipProof,
};
use world_id_proof::{
    artifacts::embedded::EmbeddedZkArtifacts, circuit_inputs::OwnershipProofCircuitInput,
    ownership_proof::generate_ownership_proof,
};

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

/// The leaf of the fixture account in its synthetic Merkle tree.
const LEAF_INDEX: u64 = 1;

/// A real ownership proof and the commitment it proves.
///
/// Adapted from `world-id-proof` 0.20.0's crate-private `ownership_proof_fixture`
/// (`src/fixtures.rs`). The account sits in a synthetic tree whose root no registry holds, so
/// tests that exchange the proof must mock the root check.
pub(crate) struct ProofFixture {
    pub(crate) proof: OwnershipProof,
    pub(crate) commitment: FieldElement,
}

impl ProofFixture {
    /// Proves ownership for a challenge's `nonce` and `context`. Takes seconds of CPU time.
    pub(crate) fn generate(nonce: FieldElement, context: FieldElement) -> Self {
        let key = EdDSAPrivateKey::from_bytes([42_u8; 32]);
        let key_set = AuthenticatorPublicKeySet::new(vec![key.public()]).unwrap();
        let (siblings, root) = first_leaf_merkle_path(key_set.leaf_hash().into());
        let blinder = FieldElement::from(999_u64);
        let commitment = Credential::compute_sub(LEAF_INDEX, blinder);
        let message = poseidon::hash(ds::OWNERSHIP_PROOF, [commitment, nonce, context]);
        let input = OwnershipProofCircuitInput {
            key_index: 0,
            key_set,
            inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
            nonce,
            expected_commitment: commitment,
            context,
            signature: key.sign(*message),
            commitment_blinder: blinder,
        };
        Self {
            proof: generate_ownership_proof(input, &EmbeddedZkArtifacts).unwrap(),
            commitment,
        }
    }

    /// Proves ownership for the challenge in a `POST /v1/challenges` response body.
    pub(crate) async fn for_challenge(challenge: &Value) -> Self {
        let nonce = challenge["nonce"].as_str().unwrap().parse().unwrap();
        let context = challenge["context"].as_str().unwrap().parse().unwrap();
        tokio::task::spawn_blocking(move || Self::generate(nonce, context))
            .await
            .unwrap()
    }
}

/// Returns the siblings and root of a tree whose only nonzero leaf is `leaf`, at
/// [`LEAF_INDEX`]: the leaf is the right child of a zero leaf, and each higher sibling is the
/// root of an all-zero subtree.
fn first_leaf_merkle_path(leaf: FieldElement) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero_subtree = FieldElement::ZERO;
    for sibling in &mut siblings {
        *sibling = zero_subtree;
        zero_subtree = poseidon::compress(zero_subtree, zero_subtree);
    }
    let mut root = poseidon::compress(siblings[0], leaf);
    for sibling in &siblings[1..] {
        root = poseidon::compress(root, *sibling);
    }
    (siblings, root)
}

/// A mock root service.
pub(crate) struct TestRootService {
    pub(crate) server: MockServer,
}

impl TestRootService {
    /// Starts a root service that answers nothing until the test mounts an answer.
    pub(crate) async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    pub(crate) fn url(&self) -> ownership_gateway::root::RootSourceUrl {
        self.server.uri().parse().unwrap()
    }

    /// Answers every following check with `{"valid": valid}`.
    pub(crate) async fn answer_valid(&self, valid: bool) {
        self.answer(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "valid": valid })),
        )
        .await;
    }

    /// Answers every following check with `response`.
    pub(crate) async fn answer(&self, response: ResponseTemplate) {
        self.server.reset().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/is-valid-root"))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    /// Returns the number of checks received.
    pub(crate) async fn checks(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/is-valid-root")
            .count()
    }
}

/// Blocks each verification until the test releases it, then accepts the proof.
pub(crate) struct GatedVerifier {
    started: mpsc::UnboundedSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    finished: mpsc::UnboundedSender<()>,
}

/// The test's side of a [`GatedVerifier`].
pub(crate) struct Gate {
    /// Receives a message as each verification starts.
    pub(crate) started: mpsc::UnboundedReceiver<()>,
    /// Lets one verification finish per message.
    pub(crate) release: std::sync::mpsc::Sender<()>,
    /// Receives a message as each verification finishes.
    pub(crate) finished: mpsc::UnboundedReceiver<()>,
}

impl GatedVerifier {
    pub(crate) fn new() -> (Self, Gate) {
        let (started_tx, started) = mpsc::unbounded_channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished) = mpsc::unbounded_channel();
        let verifier = Self {
            started: started_tx,
            release: Mutex::new(release_rx),
            finished: finished_tx,
        };
        let gate = Gate {
            started,
            release,
            finished,
        };
        (verifier, gate)
    }
}

impl ProofVerifier for GatedVerifier {
    fn verify(&self, _: &V1Proof) -> Result<(), world_id_proof::ProofError> {
        // The test may no longer listen; only the release matters.
        let _ = self.started.send(());
        self.release.lock().unwrap().recv().unwrap();
        let _ = self.finished.send(());
        Ok(())
    }
}

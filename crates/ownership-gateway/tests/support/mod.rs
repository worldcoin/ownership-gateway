//! Shared setup for the gateway's integration tests.
// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::Router;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use eddsa_babyjubjub::EdDSAPrivateKey;
use metrics::{SharedString, Unit};
use metrics_util::{CompositeKey, MetricKind, debugging::DebugValue};
use ownership_gateway::{
    challenge::{Challenge, ChallengeId},
    exchange::Exchange,
    policy::Policies,
    readiness::{AdminState, admin_router},
    retry::Deadline,
    root::RootValidator,
    server::router,
    shutdown::{self, ShutdownTrigger},
    signing::{DEFAULT_FAILURE_THRESHOLD, KmsClient, KmsFailure, KmsSigner},
    state::AppState,
    store::{Attempt, ChallengeStore, Insertion, RedisStore, StoreError},
    verification::{ProofVerifier, V1Proof, VerificationPool},
};
use ownership_token::{Jwk, JwkSet};
use p256::{
    ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner as _},
    pkcs8::EncodePublicKey as _,
};
use rand::rngs::OsRng;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
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
pub(crate) fn app_state(store: Arc<dyn ChallengeStore>, exchange: Exchange) -> AppState {
    AppState {
        store,
        policies: Arc::new(Policies::parse(POLICIES.as_bytes()).unwrap()),
        token_url: format!("{ISSUER}/v1/tokens").parse().unwrap(),
        challenge_ttl: Duration::from_mins(2),
        request_deadline: Duration::from_secs(5),
        exchange: Arc::new(exchange),
        issuance_enabled: true,
    }
}

/// Accepts every proof, for tests that check what happens around verification.
pub(crate) struct AcceptingVerifier;

impl ProofVerifier for AcceptingVerifier {
    fn verify(&self, _: &V1Proof) -> Result<(), world_id_proof::ProofError> {
        Ok(())
    }
}

/// The exchange's network dependencies, faked: a root service that accepts every root, and KMS.
pub(crate) struct TestIssuance {
    pub(crate) roots: TestRootService,
    pub(crate) kms: Arc<TestKms>,
}

impl TestIssuance {
    pub(crate) async fn start() -> Self {
        install_crypto_provider();
        let roots = TestRootService::start().await;
        roots.answer_valid(true).await;
        Self {
            roots,
            kms: TestKms::new(),
        }
    }

    /// Returns an exchange that verifies with `verifier` on `workers` workers, with as many
    /// queue places.
    pub(crate) async fn build_exchange(
        &self,
        verifier: Arc<dyn ProofVerifier>,
        workers: usize,
    ) -> Exchange {
        Exchange {
            issuer: ISSUER.parse().unwrap(),
            verification: VerificationPool::new(
                verifier,
                std::num::NonZeroUsize::new(workers).unwrap(),
                workers,
            ),
            roots: Arc::new(
                RootValidator::new(&self.roots.url(), Duration::from_secs(30)).unwrap(),
            ),
            signer: Arc::new(self.kms.signer().await),
        }
    }
}

/// A gateway on a real Redis, with its other dependencies faked.
pub(crate) struct TestStack {
    pub(crate) redis: TestRedis,
    pub(crate) issuance: TestIssuance,
    pub(crate) state: AppState,
    pub(crate) gateway: TestGateway,
}

impl TestStack {
    pub(crate) async fn start(verifier: Arc<dyn ProofVerifier>, workers: usize) -> Self {
        Self::start_with(verifier, workers, |redis, _, exchange| {
            app_state(Arc::new(redis.store.clone()), exchange)
        })
        .await
    }

    /// Starts a stack whose gateway serves the state that `state` builds from the stack's Redis,
    /// its fakes, and an exchange that verifies with `verifier` on `workers` workers.
    pub(crate) async fn start_with(
        verifier: Arc<dyn ProofVerifier>,
        workers: usize,
        state: impl FnOnce(&TestRedis, &TestIssuance, Exchange) -> AppState,
    ) -> Self {
        let redis = TestRedis::start().await;
        let issuance = TestIssuance::start().await;
        let exchange = issuance.build_exchange(verifier, workers).await;
        let state = state(&redis, &issuance, exchange);
        let gateway = TestGateway::start(state.clone()).await;
        Self {
            redis,
            issuance,
            state,
            gateway,
        }
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
    pub(crate) shutdown: ShutdownTrigger,
}

impl TestGateway {
    pub(crate) async fn start(state: AppState) -> Self {
        let (trigger, shutdown) = shutdown::channel();
        let admin = AdminState::new(shutdown);
        admin.serve(state.clone());
        Self {
            public: TestServer::start(router(state)).await,
            admin: TestServer::start(admin_router(admin)).await,
            client: reqwest::Client::new(),
            shutdown: trigger,
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

    /// Sends a token request.
    pub(crate) async fn exchange(&self, request: &Value) -> reqwest::Response {
        self.post("/v1/tokens", request, None).await
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

/// How [`TestKms`] answers signing requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KmsMode {
    /// Signs with the key it publishes.
    Healthy,
    /// Fails as if KMS were unreachable, which is retryable.
    Unreachable,
    /// Rejects the request, which is not retryable.
    Denied,
    /// Throttles the request, which is not retried.
    Throttled,
    /// Never answers.
    Hanging,
    /// Signs with a key other than the one it publishes.
    WrongKey,
}

/// A fake KMS holding one P-256 key.
pub(crate) struct TestKms {
    key: SigningKey,
    wrong_key: SigningKey,
    mode: Mutex<KmsMode>,
    public_key_available: AtomicBool,
    sign_requests: AtomicUsize,
}

impl TestKms {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            key: SigningKey::random(&mut OsRng),
            wrong_key: SigningKey::random(&mut OsRng),
            mode: Mutex::new(KmsMode::Healthy),
            public_key_available: AtomicBool::new(true),
            sign_requests: AtomicUsize::new(0),
        })
    }

    pub(crate) fn set_mode(&self, mode: KmsMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub(crate) fn set_public_key_available(&self, available: bool) {
        self.public_key_available.store(available, Ordering::SeqCst);
    }

    pub(crate) fn sign_requests(&self) -> usize {
        self.sign_requests.load(Ordering::SeqCst)
    }

    pub(crate) fn jwks(&self) -> JwkSet {
        JwkSet::new(vec![Jwk::from_public_key(self.key.verifying_key())])
    }

    /// Loads a signer for this KMS with the default failure threshold.
    pub(crate) async fn signer(self: &Arc<Self>) -> KmsSigner {
        KmsSigner::load(self.clone(), "test-key".into(), DEFAULT_FAILURE_THRESHOLD)
            .await
            .unwrap()
    }
}

#[async_trait]
impl KmsClient for TestKms {
    async fn sign_digest(&self, _: &str, digest: [u8; 32]) -> Result<Vec<u8>, KmsFailure> {
        self.sign_requests.fetch_add(1, Ordering::SeqCst);
        let mode = *self.mode.lock().unwrap();
        let key = match mode {
            KmsMode::Healthy => &self.key,
            KmsMode::WrongKey => &self.wrong_key,
            KmsMode::Unreachable => return Err(KmsFailure::Connect("connection refused".into())),
            KmsMode::Denied => return Err(KmsFailure::Permanent("access denied".into())),
            KmsMode::Throttled => return Err(KmsFailure::Throttled("rate exceeded".into())),
            KmsMode::Hanging => std::future::pending().await,
        };
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        Ok(signature.to_der().as_bytes().to_vec())
    }

    async fn public_key(&self, _: &str) -> Result<Vec<u8>, KmsFailure> {
        if !self.public_key_available.load(Ordering::SeqCst) {
            return Err(KmsFailure::Connect("connection refused".into()));
        }
        Ok(self
            .key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec())
    }
}

/// Encodes a proof as the API expects it: standard base64 of its CBOR.
pub(crate) fn encode(proof: &OwnershipProof) -> String {
    let mut cbor = Vec::new();
    ciborium::into_writer(proof, &mut cbor).unwrap();
    STANDARD.encode(cbor)
}

/// A request answering `challenge` with `proof` for `commitment`.
pub(crate) fn token_request(challenge: &Value, commitment: FieldElement, proof: &str) -> Value {
    json!({
        "challenge_id": challenge["challenge_id"],
        "commitment": commitment.to_string(),
        "proof": proof,
    })
}

/// A request answering a fresh challenge for `aud` with a real proof.
pub(crate) async fn proven_request(gateway: &TestGateway, aud: &str) -> Value {
    let challenge = gateway.challenge(aud).await;
    let fixture = ProofFixture::for_challenge(&challenge).await;
    token_request(&challenge, fixture.commitment, &encode(&fixture.proof))
}

/// A request for a fresh challenge with a well-formed proof that only [`AcceptingVerifier`]
/// accepts. One proof is generated per test binary.
pub(crate) async fn accepted_request(gateway: &TestGateway) -> Value {
    static FIXTURE: OnceLock<(String, FieldElement)> = OnceLock::new();
    let (proof, commitment) = tokio::task::spawn_blocking(|| {
        FIXTURE.get_or_init(|| {
            let fixture = ProofFixture::generate(FieldElement::ONE, FieldElement::ONE);
            (encode(&fixture.proof), fixture.commitment)
        })
    })
    .await
    .unwrap();
    token_request(&gateway.challenge("service-a").await, *commitment, proof)
}

fn challenge_id(request: &Value) -> ChallengeId {
    request["challenge_id"].as_str().unwrap().parse().unwrap()
}

/// Returns the stored record of the request's challenge, if Redis still holds it.
pub(crate) async fn stored_challenge(stack: &TestStack, request: &Value) -> Option<String> {
    redis::cmd("GET")
        .arg(challenge_id(request).redis_key())
        .query_async(&mut stack.redis.connection().await)
        .await
        .unwrap()
}

/// Deletes the request's challenge from Redis, as its expiry does.
pub(crate) async fn delete_challenge(stack: &TestStack, request: &Value) {
    let _: u64 = redis::cmd("DEL")
        .arg(challenge_id(request).redis_key())
        .query_async(&mut stack.redis.connection().await)
        .await
        .unwrap();
}

/// How a [`FaultyStore`] fails.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Fault {
    /// Consumes challenges but reports every consume as timed out, as when the reply is lost.
    LoseConsumeReply,
    /// Never answers a claim, so a token request runs until the request deadline ends it.
    HangClaims,
    /// Never answers an insert, so a challenge request runs until the request deadline ends it.
    HangInserts,
}

/// A Redis store that fails in one way.
pub(crate) struct FaultyStore {
    pub(crate) inner: RedisStore,
    pub(crate) fault: Fault,
}

#[async_trait]
impl ChallengeStore for FaultyStore {
    async fn insert(
        &self,
        id: &ChallengeId,
        challenge: &Challenge,
        ttl: Duration,
        deadline: Deadline,
    ) -> Result<Insertion, StoreError> {
        match self.fault {
            Fault::HangInserts => std::future::pending().await,
            Fault::LoseConsumeReply | Fault::HangClaims => {
                self.inner.insert(id, challenge, ttl, deadline).await
            }
        }
    }

    async fn claim_attempt(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Attempt, StoreError> {
        match self.fault {
            Fault::HangClaims => std::future::pending().await,
            Fault::LoseConsumeReply | Fault::HangInserts => {
                self.inner.claim_attempt(id, deadline).await
            }
        }
    }

    async fn consume(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Option<Challenge>, StoreError> {
        let consumed = self.inner.consume(id, deadline).await;
        match self.fault {
            Fault::LoseConsumeReply => consumed.and(Err(StoreError::Timeout)),
            Fault::HangClaims | Fault::HangInserts => consumed,
        }
    }

    async fn discard(&self, id: &ChallengeId, deadline: Deadline) -> Result<(), StoreError> {
        self.inner.discard(id, deadline).await
    }

    async fn check_writable(&self) -> Result<(), StoreError> {
        self.inner.check_writable().await
    }
}

/// Returns a metric's tags, sorted.
pub(crate) fn labels(key: &CompositeKey) -> Vec<(String, String)> {
    let mut labels: Vec<_> = key
        .key()
        .labels()
        .map(|label| (label.key().to_owned(), label.value().to_owned()))
        .collect();
    labels.sort();
    labels
}

/// Returns `expected` as sorted tags, to compare with [`labels`].
pub(crate) fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = expected
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    pairs.sort();
    pairs
}

/// A metrics snapshot, from [`metrics_util::debugging::Snapshot::into_vec`].
pub(crate) type Snapshot = [(CompositeKey, Option<Unit>, Option<SharedString>, DebugValue)];

/// Returns the count of the counter `name` with exactly the tags `expected`, or 0 if it was
/// never incremented.
pub(crate) fn counter(snapshot: &Snapshot, name: &str, expected: &[(&str, &str)]) -> u64 {
    snapshot
        .iter()
        .find_map(|(key, _, _, value)| {
            (key.kind() == MetricKind::Counter
                && key.key().name() == name
                && labels(key) == pairs(expected))
            .then_some(value)
        })
        .and_then(|value| match value {
            DebugValue::Counter(count) => Some(*count),
            _ => None,
        })
        .unwrap_or(0)
}

//! Startup, shutdown, the kill switch, the request deadline and dependency recovery.

mod support;

use std::{sync::Arc, time::Duration};

use axum::{Router, routing::get};
use ownership_gateway::{
    readiness::{AdminState, bind_admin, recover_dependencies, serve_admin_after},
    retry::Deadline,
    root::RootValidator,
    shutdown::{self, serve_until_drained},
    state::AppState,
};
use reqwest::StatusCode;
use serde_json::json;
use support::{
    AcceptingVerifier, Fault, FaultyStore, KmsMode, TestGateway, TestIssuance, TestRedis,
    TestStack, accepted_request, app_state, error_code,
};
use tokio::{
    net::TcpListener,
    sync::{Notify, oneshot},
};
use wiremock::{Mock, ResponseTemplate, matchers};
use world_id_primitives::FieldElement;

async fn status(url: String) -> StatusCode {
    reqwest::get(url).await.unwrap().status()
}

#[tokio::test]
async fn probes_answer_only_after_the_verifier_loads_and_ready_follows_startup_and_shutdown() {
    let (trigger, shutdown) = shutdown::channel();
    let admin = AdminState::new(shutdown);
    let socket = bind_admin("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = socket.local_addr().unwrap();
    let (loaded, loading) = oneshot::channel::<()>();
    let startup = tokio::spawn(serve_admin_after(
        async move { Ok(loading.await?) },
        socket,
        admin.clone(),
    ));
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "nothing listens while the verifier loads"
    );
    loaded.send(()).unwrap();
    let ((), server) = startup.await.unwrap().unwrap();
    let url = |path: &str| format!("http://{}{path}", server.address);
    assert_eq!(status(url("/health")).await, StatusCode::OK);
    assert_eq!(
        status(url("/ready")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "the signing key is still loading"
    );

    let redis = TestRedis::start().await;
    let issuance = TestIssuance::start().await;
    let exchange = issuance
        .build_exchange(Arc::new(AcceptingVerifier), 1)
        .await;
    admin.serve(app_state(Arc::new(redis.store.clone()), exchange));
    assert_eq!(status(url("/ready")).await, StatusCode::OK);

    trigger.start();
    assert_eq!(status(url("/ready")).await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(status(url("/health")).await, StatusCode::OK);
}

/// A router whose one route signals `entered` and then waits until the test notifies `release`.
fn held_router() -> (Router, Arc<Notify>, Arc<Notify>) {
    let (entered, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let router = Router::new().route(
        "/held",
        get({
            let (entered, release) = (entered.clone(), release.clone());
            async move || {
                entered.notify_one();
                release.notified().await;
                "done"
            }
        }),
    );
    (router, entered, release)
}

#[tokio::test]
async fn shutdown_stops_accepting_and_lets_requests_in_flight_finish() {
    let (router, entered, release) = held_router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (trigger, shutdown) = shutdown::channel();
    let server = tokio::spawn(serve_until_drained(
        listener,
        router,
        shutdown,
        Duration::from_secs(30),
    ));
    let in_flight = tokio::spawn(reqwest::get(format!("http://{address}/held")));
    entered.notified().await;
    trigger.start();
    while tokio::net::TcpStream::connect(address).await.is_ok() {
        tokio::task::yield_now().await;
    }
    release.notify_one();
    let response = in_flight.await.unwrap().unwrap();
    assert_eq!(response.text().await.unwrap(), "done");
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn draining_ends_after_the_grace_period_even_if_requests_are_still_running() {
    let (router, entered, _release) = held_router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (trigger, shutdown) = shutdown::channel();
    let server = tokio::spawn(serve_until_drained(
        listener,
        router,
        shutdown,
        Duration::from_millis(200),
    ));
    let _in_flight = tokio::spawn(reqwest::get(format!("http://{address}/held")));
    entered.notified().await;
    let started = std::time::Instant::now();
    trigger.start();
    server.await.unwrap().unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn the_kill_switch_answers_503_on_both_endpoints() {
    let redis = TestRedis::start().await;
    let issuance = TestIssuance::start().await;
    let enabled = TestGateway::start(app_state(
        Arc::new(redis.store.clone()),
        issuance
            .build_exchange(Arc::new(AcceptingVerifier), 1)
            .await,
    ))
    .await;
    let request = accepted_request(&enabled).await;
    let mut state = app_state(
        Arc::new(redis.store.clone()),
        issuance
            .build_exchange(Arc::new(AcceptingVerifier), 1)
            .await,
    );
    state.issuance_enabled = false;
    let disabled = TestGateway::start(state).await;
    for response in [
        disabled
            .post("/v1/challenges", &json!({"aud": "service-a"}), None)
            .await,
        disabled.exchange(&request).await,
    ] {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(response).await, "retry_later");
    }
    assert_eq!(
        enabled.exchange(&request).await.status(),
        StatusCode::OK,
        "the disabled gateway left the challenge untouched"
    );
}

#[tokio::test]
async fn the_request_deadline_answers_503_with_cors_headers() {
    let redis = TestRedis::start().await;
    let issuance = TestIssuance::start().await;
    let mut state = app_state(
        Arc::new(FaultyStore {
            inner: redis.store.clone(),
            fault: Fault::HangClaims,
        }),
        issuance
            .build_exchange(Arc::new(AcceptingVerifier), 1)
            .await,
    );
    state.request_deadline = Duration::from_millis(300);
    let gateway = TestGateway::start(state).await;
    let request = accepted_request(&gateway).await;
    let started = std::time::Instant::now();
    let response = gateway
        .post("/v1/tokens", &request, Some("https://app.example"))
        .await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(error_code(response).await, "request_new_challenge");
}

#[tokio::test]
async fn a_challenge_request_past_the_deadline_may_be_retried() {
    let stack = TestStack::start_with(Arc::new(AcceptingVerifier), 1, |redis, _, exchange| {
        let store = FaultyStore {
            inner: redis.store.clone(),
            fault: Fault::HangInserts,
        };
        AppState {
            request_deadline: Duration::from_millis(300),
            ..app_state(Arc::new(store), exchange)
        }
    })
    .await;
    let response = stack
        .gateway
        .post(
            "/v1/challenges",
            &json!({"aud": "service-a"}),
            Some("https://app.example"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(error_code(response).await, "retry_later");
}

#[tokio::test]
async fn recovery_probes_restore_the_signer_and_root_checks_without_traffic() {
    let issuance = TestIssuance::start().await;
    let mut exchange = issuance
        .build_exchange(Arc::new(AcceptingVerifier), 1)
        .await;
    exchange.roots = Arc::new(RootValidator::new(&issuance.roots.url(), Duration::ZERO).unwrap());
    let exchange = Arc::new(exchange);
    let deadline = || Deadline::after(Duration::from_secs(5));
    issuance.kms.set_mode(KmsMode::Denied);
    issuance.roots.answer(ResponseTemplate::new(503)).await;
    for _ in 0..3 {
        let _ = exchange.signer.sign(b"input", deadline()).await;
    }
    for _ in 0..2 {
        exchange.roots.check(FieldElement::ONE, deadline()).await;
    }
    assert!(!exchange.signer.is_ready() && !exchange.roots.is_ready());
    issuance.kms.set_mode(KmsMode::Healthy);
    // Only the probe's zero root gets a verdict; every other root still fails.
    issuance.roots.server.reset().await;
    Mock::given(matchers::path("/is-valid-root"))
        .and(matchers::query_param(
            "root",
            FieldElement::ZERO.to_string(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"valid": false})))
        .mount(&issuance.roots.server)
        .await;
    // Skip the 20 to 40 second pause before the probes, then let them talk to the mocks.
    tokio::time::pause();
    let recovery = tokio::spawn(recover_dependencies(exchange.clone()));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(40)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !(exchange.signer.is_ready() && exchange.roots.is_ready()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one round of probes restores both");
    recovery.abort();
}

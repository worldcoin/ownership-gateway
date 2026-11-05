//! Token exchange when the challenge, proof or origin is rejected, dependencies fail, the
//! deadline runs short or capacity runs out.

mod support;

use std::{sync::Arc, time::Duration};

use ownership_gateway::{
    challenge::ChallengeId, retry::Deadline, root::RootValidator, state::AppState,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use support::{
    AcceptingVerifier, Fault, FaultyStore, GatedVerifier, KmsMode, TestStack, accepted_request,
    app_state, delete_challenge, error_code, stored_challenge, token_request,
};
use wiremock::ResponseTemplate;
use world_id_primitives::FieldElement;

#[tokio::test]
async fn an_invalid_root_rejects_and_discards_the_challenge() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    stack.issuance.roots.answer_valid(false).await;
    let request = accepted_request(&stack.gateway).await;
    let response = stack.gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(response).await, "proof_rejected");
    assert_eq!(stored_challenge(&stack, &request).await, None);
}

#[tokio::test]
async fn unknown_and_expired_challenges_and_malformed_proofs_are_rejected() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let gateway = &stack.gateway;
    let unknown = json!({
        "challenge_id": ChallengeId::generate().as_str(),
        "commitment": FieldElement::ONE.to_string(),
        "proof": "AA==",
    });
    let expired = token_request(
        &gateway.challenge("service-a").await,
        FieldElement::ONE,
        "AA==",
    );
    delete_challenge(&stack, &expired).await;
    let malformed = token_request(
        &gateway.challenge("service-a").await,
        FieldElement::ONE,
        "not base64",
    );
    for (request, code) in [
        (&unknown, "challenge_unusable"),
        (&expired, "challenge_unusable"),
        (&malformed, "proof_rejected"),
    ] {
        let response = gateway.exchange(request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{request}");
        assert_eq!(error_code(response).await, code);
    }
    assert_eq!(
        stored_challenge(&stack, &malformed).await,
        None,
        "a malformed proof uses up the challenge"
    );
    assert_eq!(
        gateway.exchange(&malformed).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_root_outage_returns_503_and_leaves_the_challenge_unusable() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let request = accepted_request(&stack.gateway).await;
    stack
        .issuance
        .roots
        .answer(ResponseTemplate::new(503))
        .await;
    let response = stack.gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(response).await, "request_new_challenge");
    stack.issuance.roots.answer_valid(true).await;
    let retry = stack.gateway.exchange(&request).await;
    assert_eq!(retry.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(retry).await, "challenge_unusable");
}

#[tokio::test]
async fn a_signing_failure_after_consumption_returns_503_and_no_token() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let request = accepted_request(&stack.gateway).await;
    stack.issuance.kms.set_mode(KmsMode::Denied);
    assert_eq!(
        stack.gateway.exchange(&request).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        stored_challenge(&stack, &request).await,
        None,
        "the challenge was consumed"
    );
    stack.issuance.kms.set_mode(KmsMode::Healthy);
    assert_eq!(
        stack.gateway.exchange(&request).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn throttled_signing_returns_503_with_retry_after() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let request = accepted_request(&stack.gateway).await;
    stack.issuance.kms.set_mode(KmsMode::Throttled);
    let response = stack.gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    assert_eq!(error_code(response).await, "request_new_challenge");
    assert_eq!(
        stack.issuance.kms.sign_requests(),
        1,
        "a throttled attempt is not retried"
    );
}

#[tokio::test]
async fn an_uncertain_consume_returns_503_and_no_token() {
    let stack = TestStack::start_with(Arc::new(AcceptingVerifier), 1, |redis, _, exchange| {
        let store = FaultyStore {
            inner: redis.store.clone(),
            fault: Fault::LoseConsumeReply,
        };
        app_state(Arc::new(store), exchange)
    })
    .await;
    let gateway = &stack.gateway;
    let request = accepted_request(gateway).await;
    let response = gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(stack.issuance.kms.sign_requests(), 0);
    assert_eq!(
        gateway.exchange(&request).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(stack.issuance.kms.sign_requests(), 0);
}

#[tokio::test]
async fn too_little_time_to_sign_returns_503_without_consuming() {
    let stack = TestStack::start_with(Arc::new(AcceptingVerifier), 1, |redis, _, exchange| {
        AppState {
            request_deadline: Duration::from_millis(2500),
            ..app_state(Arc::new(redis.store.clone()), exchange)
        }
    })
    .await;
    let gateway = &stack.gateway;
    stack
        .issuance
        .roots
        .answer(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(800))
                .set_body_json(json!({"valid": true})),
        )
        .await;
    let request = accepted_request(gateway).await;
    let response = gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        stored_challenge(&stack, &request).await.is_some(),
        "the challenge was not consumed"
    );
    assert_eq!(stack.issuance.kms.sign_requests(), 0);
    assert_eq!(
        gateway.exchange(&request).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn requests_beyond_verification_capacity_are_shed_with_retry_after() {
    let (verifier, mut gate) = GatedVerifier::new();
    let stack = TestStack::start(Arc::new(verifier), 1).await;
    let gateway = &stack.gateway;
    let first = accepted_request(gateway).await;
    let second = accepted_request(gateway).await;
    let third = accepted_request(gateway).await;
    let post = |request: Value| {
        let client = gateway.client.clone();
        let url = format!("{}/v1/tokens", gateway.public.url);
        tokio::spawn(async move {
            client
                .post(url)
                .header("origin", "https://app.example")
                .json(&request)
                .send()
                .await
                .unwrap()
        })
    };
    let running = post(first);
    gate.started.recv().await.unwrap();
    let (mut second, mut third) = (post(second), post(third));
    let (shed, queued) = tokio::select! {
        response = &mut second => (response.unwrap(), third),
        response = &mut third => (response.unwrap(), second),
    };
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shed.headers()["retry-after"], "1");
    assert_eq!(
        shed.headers()["access-control-expose-headers"],
        "Retry-After"
    );
    assert_eq!(error_code(shed).await, "retry_later");
    gate.release.send(()).unwrap();
    gate.release.send(()).unwrap();
    assert_eq!(running.await.unwrap().status(), StatusCode::OK);
    assert_eq!(queued.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn readiness_follows_the_signer_and_root_checks() {
    let stack = TestStack::start_with(
        Arc::new(AcceptingVerifier),
        1,
        |redis, issuance, mut exchange| {
            exchange.roots =
                Arc::new(RootValidator::new(&issuance.roots.url(), Duration::ZERO).unwrap());
            app_state(Arc::new(redis.store.clone()), exchange)
        },
    )
    .await;
    let (state, gateway) = (&stack.state, &stack.gateway);
    let deadline = || Deadline::after(Duration::from_secs(5));
    assert_eq!(gateway.probe("/ready").await, StatusCode::OK);

    stack.issuance.kms.set_mode(KmsMode::Unreachable);
    for _ in 0..2 {
        assert!(
            state
                .exchange
                .signer
                .sign(b"input", deadline())
                .await
                .is_err()
        );
    }
    assert_eq!(
        gateway.probe("/ready").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(gateway.probe("/health").await, StatusCode::OK);
    stack.issuance.kms.set_mode(KmsMode::Healthy);
    state
        .exchange
        .signer
        .sign(b"input", deadline())
        .await
        .unwrap();
    assert_eq!(gateway.probe("/ready").await, StatusCode::OK);

    stack
        .issuance
        .roots
        .answer(ResponseTemplate::new(503))
        .await;
    for _ in 0..2 {
        state
            .exchange
            .roots
            .check(FieldElement::ONE, deadline())
            .await;
    }
    assert_eq!(
        gateway.probe("/ready").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    stack.issuance.roots.answer_valid(false).await;
    state
        .exchange
        .roots
        .check(FieldElement::ONE, deadline())
        .await;
    assert_eq!(gateway.probe("/ready").await, StatusCode::OK);
}

#[tokio::test]
async fn disallowed_origins_are_rejected_before_and_after_the_claim() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let gateway = &stack.gateway;
    let request = token_request(
        &gateway.challenge("service-b").await,
        FieldElement::ONE,
        "AA==",
    );
    let response = gateway
        .post("/v1/tokens", &request, Some("https://evil.example"))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, "origin_not_allowed");
    assert!(stored_challenge(&stack, &request).await.is_some());
    // service-a allows this origin, but the challenge is for service-b.
    let response = gateway
        .post("/v1/tokens", &request, Some("https://app.example"))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, "origin_not_allowed");
    assert_eq!(stored_challenge(&stack, &request).await, None);
}

//! End-to-end proof exchange: challenge, real proof, token.

mod support;

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use ownership_gateway::{
    challenge::{Challenge, ChallengeId},
    jwks::{self, JwksState},
    policy::audience_context,
    verification::{EmbeddedVerifier, ProofVerifier, V1Proof},
};
use ownership_token::{JwkSet, TokenVerifier};
use reqwest::StatusCode;
use serde_json::{Value, json};
use support::{
    AcceptingVerifier, ISSUER, TestServer, TestStack, error_code, proven_request, stored_challenge,
    token_request,
};
use world_id_primitives::FieldElement;
use world_id_proof::ProofError;

/// Verifies with the embedded verifier and counts the proofs it verified.
#[derive(Default)]
struct CountingVerifier {
    inner: OnceLock<EmbeddedVerifier>,
    verifications: AtomicUsize,
}

impl ProofVerifier for CountingVerifier {
    fn verify(&self, input: &V1Proof) -> Result<(), ProofError> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        self.inner
            .get_or_init(|| EmbeddedVerifier::load().unwrap())
            .verify(input)
    }
}

async fn verifying_stack() -> (TestStack, Arc<CountingVerifier>) {
    let verifier = Arc::new(CountingVerifier::default());
    (TestStack::start(verifier.clone(), 8).await, verifier)
}

#[tokio::test]
async fn a_valid_proof_gets_one_token_for_its_audience() {
    let (stack, _) = verifying_stack().await;
    let request = proven_request(&stack.gateway, "service-a").await;
    let response = stack.gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();

    let state = JwksState::default();
    state.publish(stack.issuance.kms.jwks()).unwrap();
    let jwks_server = TestServer::start(jwks::router(state)).await;
    let keys: JwkSet = reqwest::get(format!("{}/.well-known/jwks.json", jwks_server.url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let verifier = TokenVerifier::new(
        ISSUER.parse().unwrap(),
        ["service-a".parse().unwrap()],
        Duration::ZERO,
    )
    .unwrap();
    let claims = verifier
        .verify(body["token"].as_str().unwrap(), &keys, SystemTime::now())
        .await
        .unwrap();
    assert_eq!(claims.iss.as_str(), ISSUER);
    assert_eq!(claims.aud.as_str(), "service-a");
    assert_eq!(claims.sub.as_str(), request["commitment"]);
    assert_eq!(
        claims.exp - claims.iat,
        900,
        "the TTL comes from the policy"
    );
    let expires_at: DateTime<Utc> = body["expires_at"].as_str().unwrap().parse().unwrap();
    assert_eq!(u64::try_from(expires_at.timestamp()).unwrap(), claims.exp);

    let replay = stack.gateway.exchange(&request).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(replay).await, "challenge_unusable");
}

#[tokio::test]
async fn concurrent_exchanges_of_one_challenge_verify_once_and_issue_one_token() {
    let (stack, verifier) = verifying_stack().await;
    let request = proven_request(&stack.gateway, "service-a").await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (client, url, request) = (
            stack.gateway.client.clone(),
            format!("{}/v1/tokens", stack.gateway.public.url),
            request.clone(),
        );
        tasks.spawn(async move {
            client
                .post(url)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status()
        });
    }
    let statuses = tasks.join_all().await;
    let issued = statuses
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    let rejected = statuses
        .iter()
        .filter(|status| **status == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!((issued, rejected), (1, 7), "{statuses:?}");
    assert_eq!(verifier.verifications.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_proof_for_another_audience_context_is_rejected() {
    let (stack, verifier) = verifying_stack().await;
    let request = proven_request(&stack.gateway, "service-a").await;
    let id: ChallengeId = request["challenge_id"].as_str().unwrap().parse().unwrap();
    let mut challenge: Challenge =
        serde_json::from_str(&stored_challenge(&stack, &request).await.unwrap()).unwrap();
    challenge.context = audience_context(&"service-b".parse().unwrap());
    let () = redis::cmd("SET")
        .arg(id.redis_key())
        .arg(serde_json::to_string(&challenge).unwrap())
        .arg("KEEPTTL")
        .query_async(&mut stack.redis.connection().await)
        .await
        .unwrap();
    let response = stack.gateway.exchange(&request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(verifier.verifications.load(Ordering::SeqCst), 1);
    assert_eq!(stored_challenge(&stack, &request).await, None);
}

#[tokio::test]
async fn malformed_and_oversized_requests_are_rejected_before_any_challenge_is_touched() {
    let stack = TestStack::start(Arc::new(AcceptingVerifier), 1).await;
    let gateway = &stack.gateway;
    let challenge = gateway.challenge("service-a").await;
    let valid = token_request(&challenge, FieldElement::ONE, "AA==");
    let mut bad_id = valid.clone();
    bad_id["challenge_id"] = json!("too-short");
    let mut bad_commitment = valid.clone();
    bad_commitment["commitment"] = json!("0x01");
    let mut extra = valid.clone();
    extra["extra"] = json!(1);
    for request in [&bad_id, &bad_commitment, &extra] {
        let response = gateway.exchange(request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{request}");
        assert_eq!(error_code(response).await, "malformed_request");
    }
    let response = gateway
        .post_raw("/v1/tokens", " ".repeat(1024 * 1024 + 1))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(stored_challenge(&stack, &valid).await.is_some());
}

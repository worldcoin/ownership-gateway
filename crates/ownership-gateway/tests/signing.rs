//! KMS signing and the JWKS deployment, with a fake KMS.

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ownership_gateway::{
    jwks::{self, JwksState},
    retry::Deadline,
    signing::{KmsSigner, SigningError, load_jwk},
};
use ownership_token::{JwkSet, TokenVerifier, test_util};
use p256::ecdsa::{Signature, signature::Verifier as _};
use reqwest::StatusCode;
use support::{KmsMode, TestKms, TestServer, error_code};

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(5))
}

#[tokio::test]
async fn signatures_verify_with_the_published_key() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    let signature = signer.sign(b"header.payload", deadline()).await.unwrap();
    let key = load_jwk(kms.as_ref(), "test-key").await.unwrap();
    key.public_key()
        .verify(
            b"header.payload",
            &Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    assert_eq!(signer.kid(), key.kid());
}

#[tokio::test]
async fn signed_tokens_pass_the_ownership_verifier() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = test_util::claims(now);
    let token = signer.sign_token(&claims, deadline()).await.unwrap();
    let verifier =
        TokenVerifier::new(claims.iss.clone(), [claims.aud.clone()], Duration::ZERO).unwrap();
    let verified_claims = verifier
        .verify(&token, &kms.jwks(), SystemTime::now())
        .await
        .unwrap();
    assert_eq!(verified_claims, claims);
}

#[tokio::test]
async fn only_retryable_failures_are_retried_once() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    for (mode, requests) in [
        (KmsMode::Unreachable, 2),
        (KmsMode::Throttled, 1),
        (KmsMode::Denied, 1),
        (KmsMode::WrongKey, 1),
    ] {
        kms.set_mode(mode);
        let before = kms.sign_requests();
        let error = signer.sign(b"input", deadline()).await.unwrap_err();
        assert!(
            matches!(error, SigningError::Kms { attempts, .. } if attempts == requests),
            "{mode:?}"
        );
        assert_eq!(
            kms.sign_requests() - before,
            usize::try_from(requests).unwrap(),
            "{mode:?}"
        );
    }
}

#[tokio::test]
async fn readiness_is_lost_after_three_failed_attempts_and_returns_after_a_success() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    kms.set_mode(KmsMode::Unreachable);
    assert!(signer.sign(b"input", deadline()).await.is_err());
    assert!(
        signer.is_ready(),
        "two failed attempts are below the threshold"
    );
    kms.set_mode(KmsMode::Denied);
    assert!(signer.sign(b"input", deadline()).await.is_err());
    assert!(!signer.is_ready());
    kms.set_mode(KmsMode::Healthy);
    signer.sign(b"input", deadline()).await.unwrap();
    assert!(signer.is_ready());
}

#[tokio::test]
async fn throttling_does_not_count_toward_readiness() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    kms.set_mode(KmsMode::Throttled);
    for _ in 0..3 {
        let error = signer.sign(b"input", deadline()).await.unwrap_err();
        assert!(matches!(error, SigningError::Kms { attempts: 1, .. }));
    }
    assert!(signer.is_ready());
}

#[tokio::test(start_paused = true)]
async fn each_attempt_times_out_after_two_seconds() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    kms.set_mode(KmsMode::Hanging);
    let started = tokio::time::Instant::now();
    let error = signer
        .sign(b"input", Deadline::after(Duration::from_secs(10)))
        .await
        .unwrap_err();
    assert!(matches!(error, SigningError::Kms { attempts: 2, .. }));
    assert!(started.elapsed() >= Duration::from_secs(4));
}

#[tokio::test(start_paused = true)]
async fn the_deadline_caps_attempts_and_skips_a_retry_that_cannot_finish() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    kms.set_mode(KmsMode::Hanging);
    let started = tokio::time::Instant::now();
    let error = signer
        .sign(b"input", Deadline::after(Duration::from_secs(3)))
        .await
        .unwrap_err();
    assert!(matches!(error, SigningError::Kms { attempts: 1, .. }));
    assert_eq!(started.elapsed(), Duration::from_secs(2));

    let started = tokio::time::Instant::now();
    assert!(
        signer
            .sign(b"input", Deadline::after(Duration::from_millis(500)))
            .await
            .is_err()
    );
    assert_eq!(started.elapsed(), Duration::from_millis(500));

    let requests = kms.sign_requests();
    let error = signer
        .sign(b"input", Deadline::after(Duration::ZERO))
        .await
        .unwrap_err();
    assert!(matches!(error, SigningError::DeadlineExceeded));
    assert_eq!(kms.sign_requests(), requests);
}

#[tokio::test(start_paused = true)]
async fn cancelled_attempts_count_as_failures() {
    let kms = TestKms::new();
    let signer = kms.signer().await;
    kms.set_mode(KmsMode::Hanging);
    for _ in 0..3 {
        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            signer.sign(b"input", deadline()),
        )
        .await;
        assert!(cancelled.is_err());
    }
    assert!(!signer.is_ready());
}

#[tokio::test]
async fn loading_a_signer_needs_its_public_key() {
    let kms = TestKms::new();
    kms.set_public_key_available(false);
    assert!(
        KmsSigner::load(
            kms.clone(),
            "test-key".into(),
            ownership_gateway::signing::DEFAULT_FAILURE_THRESHOLD
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn jwks_is_served_only_once_keys_are_published() {
    let state = JwksState::default();
    let public = TestServer::start(jwks::router(state.clone())).await;
    let admin = TestServer::start(jwks::admin_router(state.clone())).await;
    let get = |url: String| async move { reqwest::get(url).await.unwrap() };
    assert_eq!(
        get(format!("{}/health", admin.url)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(format!("{}/ready", admin.url)).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let response = get(format!("{}/.well-known/jwks.json", public.url)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(response).await, "retry_later");

    assert!(state.publish(JwkSet::new(Vec::new())).is_err());
    let keys = test_util::TestIssuer::new().jwks();
    state.publish(keys.clone()).unwrap();
    assert_eq!(
        get(format!("{}/ready", admin.url)).await.status(),
        StatusCode::OK
    );
    let response = get(format!("{}/.well-known/jwks.json", public.url)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "public, max-age=300");
    let served: JwkSet = response.json().await.unwrap();
    assert_eq!(served.keys()[0].kid(), keys.keys()[0].kid());
}

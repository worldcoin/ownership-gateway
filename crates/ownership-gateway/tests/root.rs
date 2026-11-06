//! Root checks against a mock root service.

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use ownership_gateway::{
    retry::Deadline,
    root::{RootValidator, RootVerdict},
};
use serde_json::json;
use support::{TestRootService, install_crypto_provider};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path, query_param},
};
use world_id_primitives::FieldElement;

const ROOT: FieldElement = FieldElement::ONE;

fn validator(service: &TestRootService) -> RootValidator {
    install_crypto_provider();
    RootValidator::new(&service.url(), Duration::from_secs(30)).unwrap()
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(5))
}

#[tokio::test]
async fn the_verdict_comes_from_the_root_service() {
    let service = TestRootService::start().await;
    let root = FieldElement::from(42_u64);
    Mock::given(method("GET"))
        .and(path("/is-valid-root"))
        .and(query_param("root", root.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"valid": true})))
        .mount(&service.server)
        .await;
    let validator = validator(&service);
    assert_eq!(validator.check(root, deadline()).await, RootVerdict::Valid);
    service.answer_valid(false).await;
    assert_eq!(
        validator.check(root, deadline()).await,
        RootVerdict::Invalid
    );
    assert_eq!(service.checks().await, 1);
}

#[tokio::test]
async fn failed_checks_are_retried_once() {
    let service = TestRootService::start().await;
    let validator = validator(&service);
    for response in [
        ResponseTemplate::new(503),
        ResponseTemplate::new(200).set_body_string("not a verdict"),
        ResponseTemplate::new(200).set_body_string(" ".repeat(4097)),
        ResponseTemplate::new(302).insert_header("location", "https://elsewhere.example"),
    ] {
        service.answer(response).await;
        assert_eq!(
            validator.check(ROOT, deadline()).await,
            RootVerdict::Unavailable
        );
        assert_eq!(service.checks().await, 2);
    }
}

#[tokio::test]
async fn a_retry_that_succeeds_gives_the_verdict() {
    let service = TestRootService::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    Mock::given(method("GET"))
        .and(path("/is-valid-root"))
        .respond_with(move |_: &wiremock::Request| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({"valid": true}))
            }
        })
        .mount(&service.server)
        .await;
    assert_eq!(
        validator(&service).check(ROOT, deadline()).await,
        RootVerdict::Valid
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn each_attempt_times_out_after_one_second() {
    let service = TestRootService::start().await;
    service
        .answer(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(json!({"valid": true})),
        )
        .await;
    let started = std::time::Instant::now();
    assert_eq!(
        validator(&service).check(ROOT, deadline()).await,
        RootVerdict::Unavailable
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
    assert_eq!(service.checks().await, 2);
}

#[tokio::test]
async fn the_deadline_caps_the_attempt_and_skips_a_retry_that_cannot_finish() {
    let service = TestRootService::start().await;
    service
        .answer(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(3))
                .set_body_json(json!({"valid": true})),
        )
        .await;
    let validator = validator(&service);
    let started = std::time::Instant::now();
    let verdict = validator
        .check(ROOT, Deadline::after(Duration::from_millis(300)))
        .await;
    assert_eq!(verdict, RootVerdict::Unavailable);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(service.checks().await, 1);

    assert_eq!(
        validator.check(ROOT, Deadline::after(Duration::ZERO)).await,
        RootVerdict::Unavailable
    );
    assert_eq!(
        service.checks().await,
        1,
        "no attempt starts after the deadline"
    );
}

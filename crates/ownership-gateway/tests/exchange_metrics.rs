//! Token exchange outcome metrics, observed through a recorder installed for this test binary.

mod support;

use std::{sync::Arc, time::Duration};

use metrics_util::debugging::DebuggingRecorder;
use ownership_gateway::state::AppState;
use reqwest::StatusCode;
use serde_json::json;
use support::{AcceptingVerifier, TestStack, accepted_request, app_state, counter};
use wiremock::ResponseTemplate;

#[tokio::test]
async fn origins_rejected_before_the_claim_and_exhausted_deadlines_are_counted() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().unwrap();

    let stack = TestStack::start_with(Arc::new(AcceptingVerifier), 1, |redis, _, exchange| {
        AppState {
            request_deadline: Duration::from_millis(2500),
            ..app_state(Arc::new(redis.store.clone()), exchange)
        }
    })
    .await;
    stack
        .issuance
        .roots
        .answer(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(800))
                .set_body_json(json!({"valid": true})),
        )
        .await;
    let request = accepted_request(&stack.gateway).await;
    let rejected = stack
        .gateway
        .post("/v1/tokens", &request, Some("https://evil.example"))
        .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let exhausted = stack.gateway.exchange(&request).await;
    assert_eq!(exhausted.status(), StatusCode::SERVICE_UNAVAILABLE);

    let snapshot = snapshotter.snapshot().into_vec();
    assert_eq!(
        counter(
            &snapshot,
            "ownership_gateway.tokens.rejected",
            &[("reason", "origin_not_allowed")]
        ),
        1
    );
    assert_eq!(
        counter(
            &snapshot,
            "ownership_gateway.tokens.deadline_exhausted",
            &[("aud", "service-a")]
        ),
        1
    );
}

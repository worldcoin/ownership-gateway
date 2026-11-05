//! HTTP metrics, observed through a recorder installed for this test binary.

mod support;

use std::{sync::Arc, time::Duration};

use metrics_util::{
    MetricKind,
    debugging::{DebugValue, DebuggingRecorder},
};
use reqwest::StatusCode;
use support::{
    AcceptingVerifier, Fault, FaultyStore, TestGateway, TestIssuance, TestRedis, accepted_request,
    app_state, counter, labels, pairs,
};

#[tokio::test]
async fn every_response_counts_toward_the_route_metrics() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().unwrap();

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
    let oversized = gateway
        .post_raw("/v1/challenges", " ".repeat(8 * 1024))
        .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let timed_out = gateway.post("/v1/tokens", &request, None).await;
    assert_eq!(timed_out.status(), StatusCode::SERVICE_UNAVAILABLE);
    let unmatched = reqwest::get(format!("{}/v1/unknown", gateway.public.url))
        .await
        .unwrap();
    assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);

    let snapshot = snapshotter.snapshot().into_vec();
    let requests =
        |expected: &[(&str, &str)]| counter(&snapshot, "ownership_gateway.http.requests", expected);
    for expected in [
        [("route", "/v1/challenges"), ("status_class", "2xx")],
        [("route", "/v1/challenges"), ("status_class", "4xx")],
        [("route", "/v1/tokens"), ("status_class", "5xx")],
    ] {
        assert_eq!(requests(&expected), 1, "{expected:?}");
    }
    // Other local processes may probe the server's port, which also counts as unmatched.
    assert!(requests(&[("route", "unmatched"), ("status_class", "4xx")]) >= 1);
    for route in ["/v1/challenges", "/v1/tokens", "unmatched"] {
        assert!(
            snapshot.iter().any(|(key, _, _, value)| {
                key.kind() == MetricKind::Histogram
                    && key.key().name() == "ownership_gateway.http.duration"
                    && labels(key) == pairs(&[("route", route), ("histogram", "distribution")])
                    && matches!(value, DebugValue::Histogram(samples) if !samples.is_empty())
            }),
            "{route}"
        );
    }
}

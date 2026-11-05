//! Challenge issuance over HTTP.

mod support;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use ownership_gateway::{
    challenge::{Challenge, ChallengeId},
    policy::audience_context,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use support::{TestGateway, TestRedis, app_state, error_code, unreachable_store};
use world_id_primitives::FieldElement;

async fn gateway() -> (TestRedis, TestGateway) {
    let redis = TestRedis::start().await;
    let gateway = TestGateway::start(app_state(Arc::new(redis.store.clone()))).await;
    (redis, gateway)
}

fn field(body: &Value, name: &str) -> FieldElement {
    body[name].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn issues_a_challenge_bound_to_the_audience() {
    let (redis, gateway) = gateway().await;
    let requested_at = SystemTime::now();
    let body = gateway.challenge("service-a").await;
    let id: ChallengeId = body["challenge_id"].as_str().unwrap().parse().unwrap();
    let context = field(&body, "context");
    assert_eq!(context, audience_context(&"service-a".parse().unwrap()));
    let fields: Vec<_> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        [
            "challenge_id",
            "context",
            "expires_at",
            "nonce",
            "token_url"
        ]
    );
    assert_ne!(field(&body, "nonce"), FieldElement::ZERO);
    assert_eq!(body["token_url"], "https://issuer.example/base/v1/tokens");
    let expires_at: DateTime<Utc> = body["expires_at"].as_str().unwrap().parse().unwrap();
    let lifetime = SystemTime::from(expires_at)
        .duration_since(requested_at)
        .unwrap();
    assert!(lifetime <= Duration::from_secs(121) && lifetime >= Duration::from_secs(119));
    let stored: String = redis::cmd("GET")
        .arg(id.redis_key())
        .query_async(&mut redis.connection().await)
        .await
        .unwrap();
    let stored: Challenge = serde_json::from_str(&stored).unwrap();
    assert_eq!(
        stored,
        Challenge {
            aud: "service-a".parse().unwrap(),
            context,
            nonce: field(&body, "nonce"),
        }
    );
}

#[tokio::test]
async fn each_audience_gets_its_own_context_and_each_challenge_a_fresh_nonce() {
    let (_redis, gateway) = gateway().await;
    let first = gateway.challenge("service-a").await;
    let second = gateway.challenge("service-a").await;
    let other = gateway.challenge("service-b").await;
    assert_eq!(first["context"], second["context"]);
    assert_ne!(first["context"], other["context"]);
    assert_ne!(first["nonce"], second["nonce"]);
    assert_ne!(first["challenge_id"], second["challenge_id"]);
}

#[tokio::test]
async fn unknown_and_disabled_audiences_are_forbidden() {
    let (_redis, gateway) = gateway().await;
    for aud in ["missing", "disabled"] {
        let response = gateway
            .post("/v1/challenges", &json!({ "aud": aud }), None)
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(error_code(response).await, "audience_not_allowed");
    }
}

#[tokio::test]
async fn malformed_and_oversized_bodies_are_rejected() {
    let (_redis, gateway) = gateway().await;
    for body in [
        "{",
        r#"{"aud":"bad audience"}"#,
        r#"{"aud":"service-a","extra":1}"#,
    ] {
        let response = gateway.post_raw("/v1/challenges", body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(error_code(response).await, "malformed_request");
    }
    let response = gateway
        .post_raw("/v1/challenges", " ".repeat(8 * 1024))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(response).await, "body_too_large");
}

#[tokio::test]
async fn browser_origins_follow_the_audience_policy() {
    let (_redis, gateway) = gateway().await;
    let response = gateway
        .post(
            "/v1/challenges",
            &json!({"aud":"service-a"}),
            Some("https://app.example"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(headers["vary"], "Origin");

    let response = gateway
        .post(
            "/v1/challenges",
            &json!({"aud":"service-b"}),
            Some("https://app.example"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(error_code(response).await, "origin_not_allowed");

    for origin in ["https://evil.example", "https://disabled.example"] {
        let response = gateway
            .post("/v1/challenges", &json!({"aud":"service-a"}), Some(origin))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
}

#[tokio::test]
async fn preflight_allows_only_listed_origins_posting_json() {
    let (_redis, gateway) = gateway().await;
    let response = gateway
        .preflight(
            "/v1/challenges",
            "https://app.example",
            "POST",
            "Content-Type",
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let headers = response.headers();
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://app.example"
    );
    assert_eq!(headers["access-control-allow-methods"], "POST");
    assert_eq!(headers["access-control-allow-headers"], "content-type");
    assert_eq!(headers["access-control-max-age"], "600");
    for (origin, method, headers) in [
        ("https://evil.example", "POST", "content-type"),
        ("https://app.example", "GET", "content-type"),
        ("https://app.example", "POST", "content-type, authorization"),
    ] {
        let response = gateway
            .preflight("/v1/challenges", origin, method, headers)
            .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{origin} {method} {headers}"
        );
    }
}

#[tokio::test]
async fn readiness_follows_redis_and_liveness_does_not() {
    let (_redis, gateway) = gateway().await;
    assert_eq!(gateway.probe("/health").await, StatusCode::OK);
    assert_eq!(gateway.probe("/ready").await, StatusCode::OK);

    let gateway = TestGateway::start(app_state(Arc::new(unreachable_store()))).await;
    assert_eq!(gateway.probe("/health").await, StatusCode::OK);
    assert_eq!(
        gateway.probe("/ready").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let response = gateway
        .post("/v1/challenges", &json!({"aud":"service-a"}), None)
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(response).await, "retry_later");
}

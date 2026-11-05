//! HTTP ownership middleware behavior.
#![cfg(all(feature = "remote-jwks", feature = "tower"))]
use axum::{
    Router,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::get,
};
use ownership_token::{
    OwnershipLayer, RemoteJwks, TokenVerifier, VerifiedOwnership,
    test_util::{TestIssuer, claims},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
const NOW: u64 = 1_000;
const SPOOFED_HEADERS: &[&str] = &[
    "x-world-id-subject",
    "x_world_id_subject",
    "x-world_id-subject",
    "x.world.id.subject",
    "x_world-id_subject",
];
fn clock() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}
fn verifier() -> TokenVerifier {
    TokenVerifier::new(
        "https://issuer.example".parse().unwrap(),
        ["service".parse().unwrap()],
        Duration::ZERO,
    )
    .unwrap()
}

#[tokio::test]
async fn middleware_verifies_bearer_and_strips_spoofed_headers_on_all_paths() {
    let issuer = TestIssuer::new();
    let verifier = verifier();
    let layer = OwnershipLayer::new(Arc::new(verifier), issuer.jwks())
        .with_clock(clock)
        .with_unprotected_paths(["/public".parse().unwrap()]);
    let app = Router::new()
        .route("/", get(protected))
        .route("/public", get(public))
        .layer(layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}");
    let mut request = client.get(&url).header(
        AUTHORIZATION,
        format!("bearer {}", issuer.token(&claims(NOW))),
    );
    for name in SPOOFED_HEADERS {
        request = request.header(*name, "spoof");
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"audience": "service", "spoofed": false})
    );
    let mut request = client.get(format!("{url}/public"));
    for name in SPOOFED_HEADERS {
        request = request.header(*name, "spoof");
    }
    let response = request.send().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"audience": null, "spoofed": false})
    );
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "token_rejected");
    server.abort();
}

async fn protected(
    VerifiedOwnership(claims): VerifiedOwnership,
    headers: HeaderMap,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"audience": claims.aud.as_str(), "spoofed": spoofed(&headers)}))
}

async fn public(headers: HeaderMap) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"audience": null, "spoofed": spoofed(&headers)}))
}

fn spoofed(headers: &HeaderMap) -> bool {
    SPOOFED_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

#[tokio::test]
async fn middleware_returns_503_when_keys_are_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let cache = RemoteJwks::new(server.uri().parse().unwrap()).unwrap();
    let verifier = verifier();
    let app = Router::new()
        .route("/", get(protected))
        .layer(OwnershipLayer::new(Arc::new(verifier), cache).with_clock(clock));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let response = reqwest::Client::new()
        .get(format!("http://{addr}"))
        .header(
            AUTHORIZATION,
            format!("Bearer {}", TestIssuer::new().token(&claims(NOW))),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "jwks_unavailable");
    task.abort();
}

#[tokio::test]
async fn middleware_reports_an_invalid_clock_as_an_internal_error() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    fn before_epoch() -> SystemTime {
        UNIX_EPOCH - Duration::from_secs(1)
    }
    let issuer = TestIssuer::new();
    let verifier = verifier();
    let app = Router::new()
        .route("/", get(protected))
        .layer(OwnershipLayer::new(Arc::new(verifier), issuer.jwks()).with_clock(before_epoch));
    let request = Request::builder()
        .uri("/")
        .header(
            AUTHORIZATION,
            format!("Bearer {}", issuer.token(&claims(NOW))),
        )
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .extensions()
            .get::<ownership_token::Rejection>()
            .unwrap()
            .reason(),
        "invalid_clock"
    );
}

#[tokio::test]
async fn extractor_rejects_without_the_layer() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let app = Router::new().route("/", get(protected));
    let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

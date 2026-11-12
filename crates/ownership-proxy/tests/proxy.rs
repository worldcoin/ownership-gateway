//! End-to-end sidecar forwarding and health probes.
#[allow(dead_code)]
mod support;

use axum::{Router, extract::Request, routing::any};
use ownership_token::test_util::TestIssuer;
use support::{TestProxy, jwks, spawn_upstream, status, token};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

async fn echo(request: Request) -> axum::Json<serde_json::Value> {
    let headers = request.headers();
    axum::Json(serde_json::json!({
        "path": request.uri().path_and_query().unwrap().as_str(),
        "subject": headers.get("x-world-id-subject").and_then(|v| v.to_str().ok()),
        "audience": headers.get("x-world-id-audience").and_then(|v| v.to_str().ok()),
        "spoofed": headers.contains_key("x-world-id-extra")
            || headers.contains_key("x_world_id_subject")
            || headers.contains_key("x-world_id-subject"),
        "host": headers.get("host").and_then(|v| v.to_str().ok()),
        "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()),
        "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok()),
    }))
}

#[tokio::test]
async fn forwards_identity_host_request_id_and_body_without_credentials() {
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let (upstream_addr, upstream_task) = spawn_upstream(
        Router::new()
            .route("/body", any(|body: String| async move { body }))
            .fallback(any(echo)),
    )
    .await;
    let proxy = TestProxy::start(upstream_addr, &jwks_server, &["/public"]).await;
    let client = reqwest::Client::new();
    // The Connection header must not remove the identity injected after sanitization.
    let response = client
        .get(format!("{}/protected?x=1", proxy.base))
        .bearer_auth(token(&issuer))
        .header("host", "client.example")
        .header("x-request-id", "request-123")
        .header("connection", "x-world-id-subject, x-request-id")
        .header("x-world-id-subject", "spoof")
        .header("x-world-id-extra", "spoof")
        .header("x_world_id_subject", "spoof")
        .header("x-world_id-subject", "spoof")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-request-id"], "request-123");
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["path"], "/protected?x=1");
    assert_eq!(body["subject"], format!("0x{}", "01".repeat(32)));
    assert_eq!(body["audience"], "service");
    assert_eq!(body["host"], "client.example");
    assert_eq!(body["request_id"], "request-123");
    assert_eq!(body["authorization"], serde_json::Value::Null);
    assert_eq!(body["spoofed"], false);
    let response = client
        .post(format!("{}/body", proxy.base))
        .bearer_auth(token(&issuer))
        .body("forwarded body")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "forwarded body");
    upstream_task.abort();
    proxy.shutdown().await;
}

#[tokio::test]
async fn exposes_health_and_rejects_missing_tokens_and_upstream_failures() {
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let proxy = TestProxy::start("127.0.0.1:1".parse().unwrap(), &jwks_server, &["/public"]).await;
    for path in ["health", "ready"] {
        assert_eq!(status(format!("{}/{path}", proxy.admin)).await, 200);
    }
    assert_eq!(status(format!("{}/protected", proxy.base)).await, 401);
    assert_eq!(status(format!("{}/public", proxy.base)).await, 502);
    proxy.shutdown().await;
}

#[tokio::test]
async fn unprotected_requests_preserve_authorization_and_replace_invalid_request_ids() {
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let (addr, upstream_task) = spawn_upstream(Router::new().fallback(any(echo))).await;
    let proxy = TestProxy::start(addr, &jwks_server, &["/public"]).await;
    let response = reqwest::Client::new()
        .get(format!("{}/public", proxy.base))
        .header("authorization", "Basic preserved")
        .header("x_world_id_subject", "spoof")
        .header("x-world_id-subject", "spoof")
        .header("x-request-id", "x".repeat(129))
        .send()
        .await
        .unwrap();
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        uuid::Uuid::parse_str(&request_id).unwrap().get_version(),
        Some(uuid::Version::Random)
    );
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["request_id"], request_id);
    assert_eq!(body["authorization"], "Basic preserved");
    assert_eq!(body["spoofed"], false);
    proxy.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn unavailable_keys_make_proxy_and_readiness_unavailable_but_leave_liveness() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let proxy = TestProxy::start("127.0.0.1:1".parse().unwrap(), &server, &[]).await;
    let client = reqwest::Client::new();
    assert_eq!(status(format!("{}/health", proxy.admin)).await, 200);
    assert_eq!(status(format!("{}/ready", proxy.admin)).await, 503);
    let response = client
        .get(format!("{}/protected", proxy.base))
        .bearer_auth(token(&TestIssuer::new()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "jwks_unavailable");
    proxy.shutdown().await;
}

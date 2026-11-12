//! JWKS refresh behavior.
#![cfg(feature = "remote-jwks")]

use ownership_token::{JwksFetchError, KeySet, RemoteJwks, test_util::TestIssuer};
use reqwest::StatusCode;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

async fn counting_jwks(
    fail_first: bool,
) -> (MockServer, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
    let server = MockServer::start().await;
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(tokio::sync::Notify::new());
    let calls = count.clone();
    let event = observed.clone();
    let keys = TestIssuer::new().jwks();
    Mock::given(method("GET"))
        .respond_with(move |_: &wiremock::Request| {
            let number = calls.fetch_add(1, Ordering::SeqCst);
            event.notify_one();
            if fail_first && number == 0 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(&keys)
            }
        })
        .mount(&server)
        .await;
    (server, count, observed)
}

#[tokio::test]
async fn refreshes_rotated_keys_and_limits_unknown_key_requests() {
    let server = MockServer::start().await;
    let first = TestIssuer::new().jwks();
    let initial = Mock::given(method("GET"))
        .and(path("/keys"))
        .and(header(
            "user-agent",
            concat!("ownership-token/", env!("CARGO_PKG_VERSION")),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&first))
        .expect(1)
        .mount_as_scoped(&server)
        .await;
    let cache = RemoteJwks::new(format!("{}/keys", server.uri()).parse().unwrap()).unwrap();
    assert!(!cache.is_usable());
    cache.refresh().await.unwrap();
    assert!(cache.is_usable());
    assert!(cache.key(first.keys()[0].kid()).await.unwrap().is_some());
    assert!(cache.key("unknown").await.unwrap().is_none());
    server.verify().await;
    drop(initial);
    let second = TestIssuer::from_seed(2).jwks();
    let rotated = Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&second))
        .expect(1)
        .mount_as_scoped(&server)
        .await;
    // Advance past the unknown-key refresh cooldown.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    let (a, b) = tokio::join!(
        cache.key(second.keys()[0].kid()),
        cache.key(second.keys()[0].kid())
    );
    assert!(a.unwrap().is_some());
    assert!(b.unwrap().is_some());
    server.verify().await;
    drop(rotated);
}

#[tokio::test]
async fn retains_keys_during_outage_but_rejects_stale_cache() {
    let server = MockServer::start().await;
    let keys = TestIssuer::new().jwks();
    let initial = Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&keys))
        .mount_as_scoped(&server)
        .await;
    let cache = RemoteJwks::new(server.uri().parse().unwrap()).unwrap();
    cache.refresh().await.unwrap();
    drop(initial);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert_eq!(
        cache.refresh().await.unwrap_err(),
        JwksFetchError::Status(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert!(cache.key(keys.keys()[0].kid()).await.unwrap().is_some());
    tokio::time::pause();
    // Advance beyond the six-hour staleness limit.
    tokio::time::advance(Duration::from_secs(6 * 3600 + 1)).await;
    tokio::time::resume();
    assert!(!cache.is_usable());
    assert!(cache.key(keys.keys()[0].kid()).await.is_err());
}

#[tokio::test]
async fn rejects_large_or_empty_documents() {
    let server = MockServer::start().await;
    let big = Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; 65537]))
        .mount_as_scoped(&server)
        .await;
    let cache = RemoteJwks::new(server.uri().parse().unwrap()).unwrap();
    assert_eq!(cache.refresh().await.unwrap_err(), JwksFetchError::TooLarge);
    drop(big);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys": []})))
        .mount(&server)
        .await;
    assert_eq!(cache.refresh().await.unwrap_err(), JwksFetchError::Invalid);
}

#[tokio::test]
async fn refuses_redirects_and_reports_status_to_observer() {
    use std::sync::Mutex;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/other"))
        .expect(1)
        .mount(&server)
        .await;
    let errors = Arc::new(Mutex::new(Vec::new()));
    let captured = errors.clone();
    let remote = RemoteJwks::with_failure_observer(server.uri().parse().unwrap(), move |error| {
        captured.lock().unwrap().push(error);
    })
    .unwrap();
    assert_eq!(
        remote.refresh().await,
        Err(JwksFetchError::Status(StatusCode::FOUND))
    );
    assert_eq!(
        *errors.lock().unwrap(),
        vec![JwksFetchError::Status(StatusCode::FOUND)]
    );
    server.verify().await;
}

#[test]
fn accepts_ipv6_loopback_url_and_rejects_untrusted_urls() {
    for (url, accepted) in [
        ("http://[::1]:8080/keys", true),
        ("http://example.com/keys", false),
        ("https://user:secret@example.com/keys", false),
    ] {
        assert_eq!(
            url.parse::<ownership_token::JwksUrl>().is_ok(),
            accepted,
            "{url}"
        );
    }
}

#[tokio::test]
async fn rejects_chunked_jwks_over_the_streaming_limit() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Transfer-Encoding: chunked\r\n",
                    "Connection: close\r\n\r\n10001\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(&vec![b' '; 65537]).await.unwrap();
        socket.write_all(b"\r\n0\r\n\r\n").await.unwrap();
    });
    let remote = RemoteJwks::new(format!("http://{addr}/keys").parse().unwrap()).unwrap();
    assert_eq!(remote.refresh().await, Err(JwksFetchError::TooLarge));
    server.await.unwrap();
}

#[tokio::test]
async fn stalled_jwks_fetch_reports_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        accepted.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let remote = RemoteJwks::new(format!("http://{addr}/keys").parse().unwrap()).unwrap();
    let fetch = tokio::spawn(async move { remote.refresh().await });
    connected.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert_eq!(fetch.await.unwrap(), Err(JwksFetchError::Timeout));
    tokio::time::resume();
    server.abort();
}

#[tokio::test]
async fn background_refresh_recovers_unusable_cache_after_cooldown() {
    let (server, count, observed) = counting_jwks(true).await;
    let remote = RemoteJwks::new(server.uri().parse().unwrap()).unwrap();
    assert!(remote.refresh().await.is_err());
    observed.notified().await;
    tokio::time::pause();
    let task = tokio::spawn(remote.clone().run_refresh());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(29)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    observed.notified().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !remote.is_usable() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
}

#[tokio::test]
async fn refreshes_soon_after_a_snapshot_becomes_stale() {
    let (server, count, observed) = counting_jwks(false).await;
    let remote = RemoteJwks::new(server.uri().parse().unwrap()).unwrap();
    remote.refresh().await.unwrap();
    observed.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_hours(6) - Duration::from_mins(1)).await;
    let task = tokio::spawn(remote.clone().run_refresh());
    tokio::task::yield_now().await;
    // Staleness in 60 seconds, then a 30-second cooldown with up to 3 seconds jitter.
    tokio::time::advance(Duration::from_secs(89)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), observed.notified())
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    task.abort();
}

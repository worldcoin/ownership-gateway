//! Proxy failure handling and bounded shutdown.
#[allow(dead_code)]
mod support;
use axum::{Router, routing::any};
use ownership_token::test_util::TestIssuer;
use std::{sync::Arc, time::Duration};
use support::{TestProxy, jwks, spawn_upstream};

#[tokio::test]
async fn returns_502_for_a_timed_out_upstream() {
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler_entered = entered.clone();
    let app = Router::new().fallback(any(move || {
        let entered = handler_entered.clone();
        async move {
            entered.notify_one();
            std::future::pending::<&'static str>().await
        }
    }));
    let (addr, upstream) = spawn_upstream(app).await;
    let proxy = TestProxy::start(addr, &jwks_server, &["/public"]).await;
    let url = format!("{}/public", proxy.base);
    let request = tokio::spawn(async move { reqwest::get(url).await.unwrap() });
    entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::time::resume();
    assert_eq!(request.await.unwrap().status(), 502);
    proxy.shutdown().await;
    upstream.abort();
}

#[tokio::test]
async fn returns_502_for_an_upstream_upgrade() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let proxy = TestProxy::start(addr, &jwks_server, &["/public"]).await;
    assert_eq!(
        reqwest::get(format!("{}/public", proxy.base))
            .await
            .unwrap()
            .status(),
        502
    );
    proxy.shutdown().await;
    upstream.await.unwrap();
}
#[tokio::test]
async fn aborts_connections_after_shutdown_grace() {
    let server = jwks(&TestIssuer::new()).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let event = entered.clone();
    let app = Router::new().fallback(any(move || {
        let event = event.clone();
        async move {
            event.notify_one();
            std::future::pending::<&'static str>().await
        }
    }));
    let (addr, upstream) = spawn_upstream(app).await;
    let proxy =
        TestProxy::start_with_grace(addr, &server, &["/public"], Some(Duration::from_secs(1)))
            .await;
    let request = tokio::spawn(async move { reqwest::get(format!("{}/public", proxy.base)).await });
    entered.notified().await;
    proxy.stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), proxy.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(request.await.unwrap().is_err());
    upstream.abort();
}
#[tokio::test]
async fn remains_live_but_unready_while_in_flight_request_drains() {
    let issuer = TestIssuer::new();
    let jwks_server = jwks(&issuer).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handler_entered = entered.clone();
    let handler_release = release.clone();
    let app = Router::new().fallback(any(move || {
        let entered = handler_entered.clone();
        let release = handler_release.clone();
        async move {
            entered.notify_one();
            release.notified().await;
            "finished"
        }
    }));
    let (addr, upstream_task) = spawn_upstream(app).await;
    let proxy = TestProxy::start(addr, &jwks_server, &["/public"]).await;
    let client = reqwest::Client::new();
    let request_client = client.clone();
    let url = proxy.base.clone();
    let request = tokio::spawn(async move {
        request_client
            .get(format!("{url}/public"))
            .send()
            .await
            .unwrap()
    });
    entered.notified().await;
    proxy.stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .get(format!("{}/ready", proxy.admin))
                .send()
                .await
                .unwrap()
                .status()
                == 503
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        client
            .get(format!("{}/health", proxy.admin))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    release.notify_one();
    assert_eq!(request.await.unwrap().text().await.unwrap(), "finished");
    proxy.task.await.unwrap().unwrap();
    upstream_task.abort();
}

#[tokio::test]
async fn slow_upload_with_regular_frames_completes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let jwks_server = jwks(&TestIssuer::new()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (progress, mut received) = tokio::sync::mpsc::channel(3);
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
        for _ in 0..3 {
            stream.read_u8().await.unwrap();
            progress.send(()).await.unwrap();
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let proxy = TestProxy::start(addr, &jwks_server, &["/public"]).await;
    let mut client = tokio::net::TcpStream::connect(proxy.base.trim_start_matches("http://"))
        .await
        .unwrap();
    client
        .write_all(b"POST /public HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\n\r\na")
        .await
        .unwrap();
    received.recv().await.unwrap();
    for byte in *b"bc" {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(6)).await;
        tokio::time::resume();
        client.write_all(&[byte]).await.unwrap();
        received.recv().await.unwrap();
    }
    let mut response = [0; 1024];
    let len = client.read(&mut response).await.unwrap();
    assert!(
        std::str::from_utf8(&response[..len])
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    upstream.await.unwrap();
    proxy.shutdown().await;
}

//! Proxy metrics. The global recorder is process-wide, so all assertions share one test.
#[allow(dead_code)]
mod support;

use metrics::{
    Counter, CounterFn, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use ownership_token::test_util::TestIssuer;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use support::{TestProxy, draining_upstream, jwks, partial_upload, token};
use tokio::io::AsyncReadExt;
use wiremock::MockServer;

#[derive(Default)]
struct Counts {
    aborted: Arc<Count>,
    timeout: Arc<Count>,
    duration: Arc<Count>,
    upstream: Arc<Count>,
    upstream_timeout: Arc<Count>,
    verified: Arc<Count>,
    rejected: Arc<Count>,
}
#[derive(Default)]
struct Count {
    value: AtomicU64,
    changed: tokio::sync::Notify,
}
impl CounterFn for Count {
    fn increment(&self, value: u64) {
        self.value.fetch_add(value, Ordering::SeqCst);
        self.changed.notify_one();
    }
    fn absolute(&self, value: u64) {
        self.value.fetch_max(value, Ordering::SeqCst);
    }
}
impl HistogramFn for Count {
    fn record(&self, _: f64) {
        self.increment(1);
    }
}
impl Recorder for Counts {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        match key.name() {
            "ownership_proxy.requests.client_aborted" => Counter::from_arc(self.aborted.clone()),
            "ownership_proxy.requests.client_timeout" => Counter::from_arc(self.timeout.clone()),
            "ownership_proxy.upstream.errors"
                if key
                    .labels()
                    .any(|label| label.key() == "class" && label.value() == "timeout") =>
            {
                Counter::from_arc(self.upstream_timeout.clone())
            }
            "ownership_proxy.upstream.errors" => Counter::from_arc(self.upstream.clone()),
            "ownership_proxy.requests.verified" => Counter::from_arc(self.verified.clone()),
            "ownership_proxy.requests.rejected" => Counter::from_arc(self.rejected.clone()),
            _ => Counter::noop(),
        }
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        if key.name() == "ownership_proxy.http.duration"
            && key
                .labels()
                .any(|label| label.key() == "histogram" && label.value() == "distribution")
        {
            Histogram::from_arc(self.duration.clone())
        } else {
            Histogram::noop()
        }
    }
}

#[tokio::test]
async fn counts_client_failures_upstream_errors_verdicts_and_duration() {
    let counts = Arc::new(Counts::default());
    metrics::set_global_recorder(counts.clone()).unwrap();
    let jwks_server = jwks(&TestIssuer::new()).await;
    let (address, waiting, upstream_task) = draining_upstream().await;
    let proxy = TestProxy::start(address, &jwks_server, &["/public"]).await;
    let client = partial_upload(&proxy, 10000).await;
    waiting.await.unwrap();
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), counts.aborted.changed.notified())
        .await
        .unwrap();
    assert_eq!(counts.aborted.value.load(Ordering::SeqCst), 1);
    assert_eq!(counts.upstream.value.load(Ordering::SeqCst), 0);
    upstream_task.await.unwrap();
    let response = reqwest::get(format!("{}/public", proxy.base))
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(counts.upstream.value.load(Ordering::SeqCst), 1);
    let client = reqwest::Client::new();
    let protected = format!("{}/protected", proxy.base);
    assert_eq!(client.get(&protected).send().await.unwrap().status(), 401);
    let token = token(&TestIssuer::new());
    assert_eq!(
        client
            .get(&protected)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert_eq!(counts.verified.value.load(Ordering::SeqCst), 1);
    assert_eq!(counts.rejected.value.load(Ordering::SeqCst), 1);
    assert!(counts.duration.value.load(Ordering::SeqCst) > 0);
    proxy.shutdown().await;

    assert_upload_timeout(&counts, &jwks_server, Duration::from_secs(20), Some(true)).await;
    assert_upload_timeout(&counts, &jwks_server, Duration::from_secs(1), Some(false)).await;
    assert_upload_timeout(&counts, &jwks_server, Duration::from_secs(10), None).await;
    assert_upstream_backpressure_timeout(&counts, &jwks_server).await;
}

async fn assert_upload_timeout(
    counts: &Counts,
    jwks_server: &MockServer,
    response_timeout: Duration,
    expect_client_timeout: Option<bool>,
) {
    let (address, waiting, upstream_task) = draining_upstream().await;
    let proxy = TestProxy::start_with_options(
        address,
        jwks_server,
        &["/public"],
        None,
        Some((Duration::from_secs(10), response_timeout)),
    )
    .await;
    let mut client = partial_upload(&proxy, 100).await;
    waiting.await.unwrap();
    let upstream_before = counts.upstream.value.load(Ordering::SeqCst);
    let upstream_timeout_before = counts.upstream_timeout.value.load(Ordering::SeqCst);
    let timeout_before = counts.timeout.value.load(Ordering::SeqCst);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = client.read_buf(&mut response).await.unwrap();
            if n == 0
                || response
                    .windows(b"Request failed".len())
                    .any(|part| part == b"Request failed")
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let client_timeout = response.starts_with(b"HTTP/1.1 408");
    if let Some(expected) = expect_client_timeout {
        assert_eq!(client_timeout, expected);
    }
    if client_timeout {
        assert!(
            response
                .windows(b"client_timeout".len())
                .any(|part| part == b"client_timeout")
        );
    } else {
        assert!(response.starts_with(b"HTTP/1.1 502"));
    }
    assert_eq!(
        counts.timeout.value.load(Ordering::SeqCst),
        timeout_before + u64::from(client_timeout)
    );
    assert_eq!(
        counts.upstream.value.load(Ordering::SeqCst),
        upstream_before
    );
    assert_eq!(
        counts.upstream_timeout.value.load(Ordering::SeqCst),
        upstream_timeout_before + u64::from(!client_timeout)
    );
    drop(client);
    proxy.shutdown().await;
    upstream_task.await.unwrap();
}

async fn assert_upstream_backpressure_timeout(counts: &Counts, jwks_server: &MockServer) {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (_socket, _) = upstream.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let proxy = TestProxy::start_with_options(
        address,
        jwks_server,
        &["/public"],
        Some(Duration::from_secs(1)),
        Some((Duration::from_secs(1), Duration::from_secs(3))),
    )
    .await;
    let upstream_timeout_before = counts.upstream_timeout.value.load(Ordering::SeqCst);
    let client_timeout_before = counts.timeout.value.load(Ordering::SeqCst);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        reqwest::Client::new()
            .post(format!("{}/public", proxy.base))
            .body(vec![42; 4 * 1024 * 1024])
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        counts.upstream_timeout.value.load(Ordering::SeqCst),
        upstream_timeout_before + 1
    );
    assert_eq!(
        counts.timeout.value.load(Ordering::SeqCst),
        client_timeout_before
    );
    proxy.shutdown().await;
    upstream_task.abort();
}

use clap::Parser;
use ownership_proxy::config::Config;
use ownership_token::{
    RemoteJwks,
    test_util::{TestIssuer, claims},
};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

pub(crate) struct TestProxy {
    pub(crate) base: String,
    pub(crate) admin: String,
    pub(crate) stop: oneshot::Sender<()>,
    pub(crate) task: JoinHandle<anyhow::Result<()>>,
}
impl TestProxy {
    pub(crate) async fn shutdown(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }

    pub(crate) async fn start(
        upstream: SocketAddr,
        jwks_server: &wiremock::MockServer,
        unprotected_paths: &[&str],
    ) -> Self {
        Self::start_with_grace(upstream, jwks_server, unprotected_paths, None).await
    }

    pub(crate) async fn start_with_grace(
        upstream: SocketAddr,
        jwks_server: &wiremock::MockServer,
        unprotected_paths: &[&str],
        shutdown_grace: Option<Duration>,
    ) -> Self {
        Self::start_with_options(
            upstream,
            jwks_server,
            unprotected_paths,
            shutdown_grace,
            None,
        )
        .await
    }

    pub(crate) async fn start_with_options(
        upstream: SocketAddr,
        jwks_server: &wiremock::MockServer,
        unprotected_paths: &[&str],
        shutdown_grace: Option<Duration>,
        timeouts: Option<(Duration, Duration)>,
    ) -> Self {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let admin_addr = admin.local_addr().unwrap();
        let mut config = Config::try_parse_from([
            "proxy",
            "--upstream",
            &format!("http://{upstream}"),
            "--issuer",
            "https://issuer.example",
            "--jwks-url",
            &jwks_server.uri(),
            "--audiences",
            "service",
        ])
        .unwrap();
        config.listen = proxy_addr;
        config.admin_listen = admin_addr;
        config.unprotected_paths = unprotected_paths
            .iter()
            .map(|path| path.parse().unwrap())
            .collect();
        config.max_connections = 10.try_into().unwrap();
        if let Some(grace) = shutdown_grace {
            config.shutdown_grace = grace;
        }
        if let Some((body, response)) = timeouts {
            config.body_read_timeout = body;
            config.upstream_response_timeout = response;
        }
        let jwks = RemoteJwks::new(config.jwks_url.clone()).unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            ownership_proxy::serve(config, jwks, proxy, admin, async {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            base: format!("http://{proxy_addr}"),
            admin: format!("http://{admin_addr}"),
            stop,
            task,
        }
    }
}

pub(crate) async fn spawn_upstream(app: axum::Router) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, task)
}

pub(crate) fn token(issuer: &TestIssuer) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    issuer.token(&claims(now))
}

pub(crate) async fn status(url: String) -> u16 {
    reqwest::get(url).await.unwrap().status().as_u16()
}

pub(crate) async fn jwks(issuer: &TestIssuer) -> wiremock::MockServer {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issuer.jwks()))
        .mount(&server)
        .await;
    server
}

pub(crate) async fn draining_upstream() -> (SocketAddr, oneshot::Receiver<()>, JoinHandle<()>) {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (entered, waiting) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        entered.send(()).unwrap();
        while socket.read(&mut bytes).await.unwrap_or(0) != 0 {}
    });
    (address, waiting, task)
}

pub(crate) async fn partial_upload(proxy: &TestProxy, length: usize) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut client = tokio::net::TcpStream::connect(proxy.base.trim_start_matches("http://"))
        .await
        .unwrap();
    client
        .write_all(
            format!(
                "POST /public HTTP/1.1\r\nHost: example\r\nContent-Length: {length}\r\n\r\npartial"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client
}

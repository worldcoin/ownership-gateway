//! The challenge store against a real Redis.

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use ownership_gateway::{
    challenge::{Challenge, ChallengeId},
    retry::Deadline,
    store::{Attempt, ChallengeStore, Insertion, RedisStore, StoreError},
};
use support::{
    REDIS_IMAGE, REDIS_TAG, TestRedis, install_crypto_provider, plaintext_store, redis_image,
};
use testcontainers::{
    GenericImage, ImageExt as _,
    core::{IntoContainerPort as _, WaitFor},
    runners::AsyncRunner as _,
};
use world_id_primitives::FieldElement;

const TTL: Duration = Duration::from_mins(2);

fn challenge() -> Challenge {
    Challenge {
        aud: "service-a".parse().unwrap(),
        context: FieldElement::from(7_u64),
        nonce: FieldElement::from(11_u64),
    }
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(5))
}

async fn insert(store: &impl ChallengeStore) -> ChallengeId {
    let id = ChallengeId::generate();
    assert_eq!(
        store
            .insert(&id, &challenge(), TTL, deadline())
            .await
            .unwrap(),
        Insertion::Stored
    );
    id
}

#[tokio::test]
async fn challenges_round_trip_over_tls() {
    install_crypto_provider();
    let container = GenericImage::new(REDIS_IMAGE, REDIS_TAG)
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_copy_to(
            "/cert.pem",
            include_bytes!("fixtures/redis-tls/cert.pem").to_vec(),
        )
        .with_copy_to(
            "/key.pem",
            include_bytes!("fixtures/redis-tls/key.pem").to_vec(),
        )
        .with_cmd([
            "redis-server",
            "--port",
            "0",
            "--tls-port",
            "6379",
            "--tls-cert-file",
            "/cert.pem",
            "--tls-key-file",
            "/key.pem",
            "--tls-auth-clients",
            "no",
        ])
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    let client = redis::Client::build_with_tls(
        format!("rediss://127.0.0.1:{port}"),
        redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(include_bytes!("fixtures/redis-tls/ca.pem").to_vec()),
        },
    )
    .unwrap();
    let store = RedisStore::from_client(client).unwrap();
    store.check_writable().await.unwrap();
    let id = insert(&store).await;
    assert_eq!(
        store.claim_attempt(&id, deadline()).await.unwrap(),
        Attempt::Claimed(challenge())
    );
    assert_eq!(
        store.consume(&id, deadline()).await.unwrap(),
        Some(challenge())
    );
}

#[tokio::test]
async fn an_identifier_in_use_is_not_overwritten() {
    let redis = TestRedis::start().await;
    let id = insert(&redis.store).await;
    let other = Challenge {
        nonce: FieldElement::from(12_u64),
        ..challenge()
    };
    assert_eq!(
        redis
            .store
            .insert(&id, &other, TTL, deadline())
            .await
            .unwrap(),
        Insertion::IdInUse
    );
    assert_eq!(
        redis.store.consume(&id, deadline()).await.unwrap(),
        Some(challenge())
    );
}

#[tokio::test]
async fn only_one_concurrent_claim_wins() {
    let redis = TestRedis::start().await;
    let id = insert(&redis.store).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (store, id) = (redis.store.clone(), id.clone());
        tasks.spawn(async move { store.claim_attempt(&id, deadline()).await });
    }
    let claims = tasks.join_all().await;
    let claimed = claims
        .iter()
        .filter(|claim| matches!(claim, Ok(Attempt::Claimed(_))))
        .count();
    let taken = claims
        .iter()
        .filter(|claim| matches!(claim, Ok(Attempt::Taken)))
        .count();
    assert_eq!((claimed, taken), (1, 7));
}

#[tokio::test]
async fn unknown_and_discarded_challenges_cannot_be_claimed() {
    let redis = TestRedis::start().await;
    assert_eq!(
        redis
            .store
            .claim_attempt(&ChallengeId::generate(), deadline())
            .await
            .unwrap(),
        Attempt::Unknown
    );
    let id = insert(&redis.store).await;
    redis.store.discard(&id, deadline()).await.unwrap();
    assert_eq!(
        redis.store.claim_attempt(&id, deadline()).await.unwrap(),
        Attempt::Unknown
    );
}

#[tokio::test]
async fn the_attempt_marker_expires_with_the_challenge() {
    let redis = TestRedis::start().await;
    let id = insert(&redis.store).await;
    redis.store.claim_attempt(&id, deadline()).await.unwrap();
    let mut connection = redis.connection().await;
    let challenge_ttl: i64 = redis::cmd("PTTL")
        .arg(id.redis_key())
        .query_async(&mut connection)
        .await
        .unwrap();
    let attempt_ttl: i64 = redis::cmd("PTTL")
        .arg(id.attempt_key())
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(0 < attempt_ttl && attempt_ttl <= challenge_ttl);
}

#[tokio::test]
async fn a_challenge_is_consumed_once() {
    let redis = TestRedis::start().await;
    let id = insert(&redis.store).await;
    let (first, second) = tokio::join!(
        redis.store.consume(&id, deadline()),
        redis.store.consume(&id, deadline())
    );
    let consumed = [first.unwrap(), second.unwrap()];
    assert_eq!(consumed.iter().flatten().count(), 1);
}

#[tokio::test]
async fn a_malformed_record_is_an_error() {
    let redis = TestRedis::start().await;
    let id = ChallengeId::generate();
    let mut connection = redis.connection().await;
    let () = redis::cmd("SET")
        .arg(id.redis_key())
        .arg("not json")
        .arg("EX")
        .arg(60)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(matches!(
        redis.store.consume(&id, deadline()).await,
        Err(StoreError::Malformed(_))
    ));
}

#[tokio::test]
async fn nothing_is_sent_after_the_deadline() {
    let redis = TestRedis::start().await;
    let id = insert(&redis.store).await;
    let expired = Deadline::after(Duration::ZERO);
    assert!(matches!(
        redis.store.consume(&id, expired).await,
        Err(StoreError::DeadlineExceeded)
    ));
    assert_eq!(
        redis.store.consume(&id, deadline()).await.unwrap(),
        Some(challenge())
    );
}

#[tokio::test]
async fn the_write_probe_fails_while_redis_is_down_and_recovers_after_a_restart() {
    install_crypto_provider();
    let redis = redis_image()
        .with_mapped_port(0, 6379.tcp())
        .start()
        .await
        .unwrap();
    let forwarder = Forwarder::start(redis.get_host_port_ipv4(6379).await.unwrap()).await;
    let store = plaintext_store(&format!("redis://127.0.0.1:{}", forwarder.port));
    store.check_writable().await.unwrap();
    redis.stop().await.unwrap();
    assert!(store.check_writable().await.is_err());
    redis.start().await.unwrap();
    forwarder.retarget(redis.get_host_port_ipv4(6379).await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        while store.check_writable().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the store reconnects after Redis restarts");
}

#[tokio::test]
async fn after_a_failover_the_store_reconnects_to_the_writable_primary() {
    install_crypto_provider();
    let primary = redis_image().start().await.unwrap();
    // A replica of an unroutable primary keeps refusing writes with `READONLY`.
    let replica = redis_image()
        .with_cmd(["redis-server", "--replicaof", "203.0.113.1", "6379"])
        .start()
        .await
        .unwrap();
    let forwarder = Forwarder::start(replica.get_host_port_ipv4(6379).await.unwrap()).await;
    let store = plaintext_store(&format!("redis://127.0.0.1:{}", forwarder.port));
    let error = store.check_writable().await.unwrap_err();
    assert!(error.is_connection_failure(), "{error:?}");
    let id = ChallengeId::generate();
    assert!(
        store
            .insert(&id, &challenge(), TTL, deadline())
            .await
            .is_err()
    );
    forwarder.retarget(primary.get_host_port_ipv4(6379).await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        while store.check_writable().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the store replaces its connection to the replica");
    insert(&store).await;
}

/// Forwards a fixed local port to Redis, so the store keeps its URL across container restarts.
struct Forwarder {
    port: u16,
    target: Arc<AtomicU16>,
    task: tokio::task::JoinHandle<()>,
}

impl Forwarder {
    async fn start(target_port: u16) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = Arc::new(AtomicU16::new(target_port));
        let current = target.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let port = current.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Ok(mut outbound) =
                        tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        Self { port, target, task }
    }

    fn retarget(&self, port: u16) {
        self.target.store(port, Ordering::Relaxed);
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

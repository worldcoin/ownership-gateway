//! Single-use challenge storage.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use redis::{
    ErrorKind,
    ServerErrorKind::{BusyLoading, MasterDown, ReadOnly},
    Value,
    aio::ConnectionManager,
};
use thiserror::Error;
use tokio::time::Instant;

use crate::{
    challenge::{Challenge, ChallengeId},
    config::RedisUrl,
    retry::Deadline,
    telemetry::{self, Dependency, ErrorChain, FailureClass},
};

/// How long one Redis command may take.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_IN_FLIGHT_COMMANDS: usize = 128;
/// The least time between two replacements of the connection.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(1);
/// The key the write probe sets. Every pod sets the same key, with the same short expiry.
const PROBE_KEY: &str = "ownership-gateway:{readiness-probe}";
const PROBE_TTL_MILLIS: u64 = 1000;

/// Claims a challenge's verification attempt. `KEYS[1]` is the challenge and `KEYS[2]` its
/// attempt marker, which expires with the challenge. Replies nil for an unknown or expired
/// challenge, 0 if the attempt is already taken, and otherwise the stored challenge.
const CLAIM_ATTEMPT: &str = r"
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return false end
if not redis.call('SET', KEYS[2], '1', 'NX', 'PX', ttl) then return 0 end
return redis.call('GET', KEYS[1])
";

/// Whether [`ChallengeStore::insert`] stored the challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insertion {
    /// The challenge is stored under the identifier.
    Stored,
    /// The identifier is already in use; nothing was stored.
    IdInUse,
}

/// The outcome of claiming a challenge's verification attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The caller holds the challenge's only attempt.
    Claimed(Challenge),
    /// No challenge has the identifier, or it expired.
    Unknown,
    /// Another caller already claimed the attempt.
    Taken,
}

/// A storage operation failed or has an unknown outcome.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Redis or the connection to it failed.
    #[error("Redis command failed")]
    Redis(#[source] redis::RedisError),
    /// The command timed out; it may or may not have taken effect.
    #[error("Redis command timed out")]
    Timeout,
    /// The request deadline passed before the command was sent.
    #[error("request deadline passed before the Redis command was sent")]
    DeadlineExceeded,
    /// Redis held or returned something other than a challenge.
    #[error("Redis returned a malformed challenge")]
    Malformed(#[source] Option<serde_json::Error>),
}

impl StoreError {
    /// Whether the connection to Redis failed, or reached a node that cannot take writes, such as
    /// a primary demoted to replica by a failover. The command can be sent again on a new
    /// connection.
    #[must_use]
    pub fn is_connection_failure(&self) -> bool {
        let Self::Redis(error) = self else {
            return false;
        };
        error.is_connection_dropped()
            || error.is_connection_refusal()
            || matches!(
                error.kind(),
                ErrorKind::Server(ReadOnly | MasterDown | BusyLoading)
            )
    }

    fn class(&self) -> FailureClass {
        match self {
            Self::Timeout => FailureClass::Timeout,
            Self::Redis(error) if error.is_timeout() => FailureClass::Timeout,
            _ if self.is_connection_failure() => FailureClass::Connect,
            Self::Redis(_) | Self::DeadlineExceeded | Self::Malformed(_) => FailureClass::Other,
        }
    }
}

/// Atomic challenge storage.
///
/// Each command times out after 250 ms or at the deadline, whichever is sooner, and is not sent
/// once the deadline has passed.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Stores `challenge` under `id` for `ttl`, unless the identifier is in use.
    ///
    /// Retries once after a connection failure. If the failed attempt had stored the challenge,
    /// the retry reports [`Insertion::IdInUse`].
    async fn insert(
        &self,
        id: &ChallengeId,
        challenge: &Challenge,
        ttl: Duration,
        deadline: Deadline,
    ) -> Result<Insertion, StoreError>;

    /// Claims the challenge's only verification attempt and returns the challenge.
    ///
    /// The claim lasts as long as the challenge. Retries once after a connection failure. If
    /// the failed attempt had claimed the challenge, the retry reports [`Attempt::Taken`].
    async fn claim_attempt(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Attempt, StoreError>;

    /// Atomically reads and deletes the challenge, returning it if it existed.
    ///
    /// Never retried. After an error the challenge may or may not have been consumed, so the
    /// caller must treat it as spent.
    async fn consume(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Option<Challenge>, StoreError>;

    /// Deletes a challenge that must not be exchanged. Retries once after a connection failure.
    async fn discard(&self, id: &ChallengeId, deadline: Deadline) -> Result<(), StoreError>;

    /// Checks that the store accepts writes. A store that reaches only a replica fails.
    async fn check_writable(&self) -> Result<(), StoreError>;
}

/// A challenge store in Redis.
///
/// Clones share one connection. A connection failure (see [`StoreError::is_connection_failure`])
/// replaces it, at most once per second, so the next command resolves the host again and reaches
/// the new primary after a failover; the connection alone would stay on a demoted primary.
#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    connection: Arc<Mutex<Connection>>,
}

struct Connection {
    manager: ConnectionManager,
    opened_at: Instant,
}

impl Connection {
    /// Configures a connection, which opens on its first command.
    fn open(client: &redis::Client) -> Result<Self, redis::RedisError> {
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(COMMAND_TIMEOUT))
            .set_response_timeout(Some(COMMAND_TIMEOUT))
            .set_number_of_retries(0)
            .set_concurrency_limit(MAX_IN_FLIGHT_COMMANDS);
        Ok(Self {
            manager: ConnectionManager::new_lazy_with_config(client.clone(), config)?,
            opened_at: Instant::now(),
        })
    }
}

impl RedisStore {
    /// Creates a store for `url`. The connection opens on the first command and reopens after
    /// a failure, without resending the failed command.
    ///
    /// # Errors
    ///
    /// Returns an error if Redis cannot use the URL.
    pub fn new(url: &RedisUrl) -> Result<Self, redis::RedisError> {
        Self::from_client(redis::Client::open(url.as_str())?)
    }

    /// Creates a store from a configured client, such as one that trusts a private CA or, in
    /// tests, one that connects without TLS.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection manager cannot be configured.
    pub fn from_client(client: redis::Client) -> Result<Self, redis::RedisError> {
        let connection = Connection::open(&client)?;
        Ok(Self {
            client,
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn manager(&self) -> ConnectionManager {
        let connection = self.connection.lock().expect("the lock is not poisoned");
        connection.manager.clone()
    }

    /// Replaces the connection after `cause`, unless it was opened less than a second ago.
    fn replace_connection(&self, cause: &StoreError) {
        let mut connection = self.connection.lock().expect("the lock is not poisoned");
        if connection.opened_at.elapsed() < RECONNECT_INTERVAL {
            return;
        }
        tracing::warn!(
            dependency = Dependency::Redis.as_str(),
            error = %ErrorChain(cause),
            "replacing the Redis connection after a connection failure"
        );
        match Connection::open(&self.client) {
            Ok(replacement) => *connection = replacement,
            Err(error) => tracing::error!(
                dependency = Dependency::Redis.as_str(),
                error = %ErrorChain(&error),
                "configuring a replacement Redis connection failed"
            ),
        }
    }

    async fn send<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
        timeout: Duration,
    ) -> Result<T, StoreError> {
        let started = Instant::now();
        let mut connection = self.manager();
        let result = match tokio::time::timeout(timeout, command.query_async(&mut connection)).await
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(StoreError::Redis(error)),
            Err(_) => Err(StoreError::Timeout),
        };
        telemetry::record_call(
            Dependency::Redis,
            started,
            result.as_ref().map(|_| ()).map_err(StoreError::class),
        );
        if let Err(error) = &result
            && error.is_connection_failure()
        {
            self.replace_connection(error);
        }
        result
    }

    async fn command<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
        deadline: Deadline,
    ) -> Result<T, StoreError> {
        let timeout = deadline
            .attempt_timeout(COMMAND_TIMEOUT)
            .ok_or(StoreError::DeadlineExceeded)?;
        self.send(command, timeout).await
    }

    async fn command_with_retry<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
        deadline: Deadline,
    ) -> Result<T, StoreError> {
        let (result, _attempts) = deadline
            .retry_once(
                COMMAND_TIMEOUT,
                StoreError::is_connection_failure,
                |timeout| self.send(command, timeout),
            )
            .await
            .ok_or(StoreError::DeadlineExceeded)?;
        result
    }
}

fn parse_challenge(bytes: &[u8]) -> Result<Challenge, StoreError> {
    serde_json::from_slice(bytes).map_err(|error| StoreError::Malformed(Some(error)))
}

#[async_trait]
impl ChallengeStore for RedisStore {
    async fn insert(
        &self,
        id: &ChallengeId,
        challenge: &Challenge,
        ttl: Duration,
        deadline: Deadline,
    ) -> Result<Insertion, StoreError> {
        let value = serde_json::to_vec(challenge).expect("a challenge serializes to JSON");
        let ttl_millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let reply: Option<String> = self
            .command_with_retry(
                redis::cmd("SET")
                    .arg(id.redis_key())
                    .arg(value)
                    .arg("NX")
                    .arg("PX")
                    .arg(ttl_millis),
                deadline,
            )
            .await?;
        Ok(if reply.is_some() {
            Insertion::Stored
        } else {
            Insertion::IdInUse
        })
    }

    async fn claim_attempt(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Attempt, StoreError> {
        let reply: Value = self
            .command_with_retry(
                redis::cmd("EVAL")
                    .arg(CLAIM_ATTEMPT)
                    .arg(2)
                    .arg(id.redis_key())
                    .arg(id.attempt_key()),
                deadline,
            )
            .await?;
        match reply {
            Value::Nil => Ok(Attempt::Unknown),
            Value::Int(0) => Ok(Attempt::Taken),
            Value::BulkString(bytes) => parse_challenge(&bytes).map(Attempt::Claimed),
            _ => Err(StoreError::Malformed(None)),
        }
    }

    async fn consume(
        &self,
        id: &ChallengeId,
        deadline: Deadline,
    ) -> Result<Option<Challenge>, StoreError> {
        let reply: Option<Vec<u8>> = self
            .command(redis::cmd("GETDEL").arg(id.redis_key()), deadline)
            .await?;
        reply.as_deref().map(parse_challenge).transpose()
    }

    async fn discard(&self, id: &ChallengeId, deadline: Deadline) -> Result<(), StoreError> {
        let _deleted: u64 = self
            .command_with_retry(redis::cmd("DEL").arg(id.redis_key()), deadline)
            .await?;
        Ok(())
    }

    async fn check_writable(&self) -> Result<(), StoreError> {
        self.command(
            redis::cmd("SET")
                .arg(PROBE_KEY)
                .arg(1)
                .arg("PX")
                .arg(PROBE_TTL_MILLIS),
            Deadline::after(COMMAND_TIMEOUT),
        )
        .await
    }
}

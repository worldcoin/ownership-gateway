//! Request deadlines and the retry budget they impose.

use std::{ops::RangeInclusive, time::Duration};

use rand::Rng as _;
use tokio::time::Instant;

/// The jittered pause before the single retry of a remote call.
pub(crate) const RETRY_BACKOFF: RangeInclusive<Duration> =
    Duration::from_millis(20)..=Duration::from_millis(100);

/// Returns a uniformly random duration in `range`.
#[must_use]
pub fn jittered(range: RangeInclusive<Duration>) -> Duration {
    rand::thread_rng().gen_range(range)
}

/// The instant by which a request must finish.
///
/// Every remote call made for the request limits its timeout to the time left, and starts a
/// retry only if the retry can still finish in time.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);

impl Deadline {
    /// Returns the deadline `budget` from now.
    #[must_use]
    pub fn after(budget: Duration) -> Self {
        Self(Instant::now() + budget)
    }

    /// Returns the time left, or zero once the deadline has passed.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// Returns the timeout for an attempt that may take at most `limit`: the smaller of `limit`
    /// and the time left. Returns `None` once the deadline has passed; the attempt must not start.
    #[must_use]
    pub fn attempt_timeout(&self, limit: Duration) -> Option<Duration> {
        let remaining = self.remaining();
        (!remaining.is_zero()).then(|| limit.min(remaining))
    }

    /// Whether at least `duration` is left.
    #[must_use]
    pub fn covers(&self, duration: Duration) -> bool {
        self.remaining() >= duration
    }

    /// Makes a remote call that may be retried once.
    ///
    /// Calls `attempt` with the time the call may take: `limit`, or the time left if that is
    /// less. If the call fails with an error that `is_retryable` accepts, and the deadline still
    /// leaves time for a jittered [`RETRY_BACKOFF`] pause and a full `limit`, it pauses and calls
    /// `attempt` once more. Returns the last result with the number of calls made, or `None`
    /// without calling `attempt` once the deadline has passed.
    pub(crate) async fn retry_once<T, E, Call>(
        &self,
        limit: Duration,
        is_retryable: impl Fn(&E) -> bool,
        mut attempt: impl FnMut(Duration) -> Call,
    ) -> Option<(Result<T, E>, u32)>
    where
        Call: Future<Output = Result<T, E>>,
    {
        let result = attempt(self.attempt_timeout(limit)?).await;
        let backoff = jittered(RETRY_BACKOFF);
        match result {
            Err(error) if is_retryable(&error) && self.covers(backoff + limit) => {
                tokio::time::sleep(backoff).await;
                Some((attempt(limit).await, 2))
            }
            result => Some((result, 1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn attempts_are_capped_to_the_time_left() {
        let deadline = Deadline::after(Duration::from_millis(300));
        assert_eq!(
            deadline.attempt_timeout(Duration::from_millis(250)),
            Some(Duration::from_millis(250))
        );
        assert!(deadline.covers(Duration::from_millis(300)));
        tokio::time::advance(Duration::from_millis(200)).await;
        assert_eq!(
            deadline.attempt_timeout(Duration::from_millis(250)),
            Some(Duration::from_millis(100))
        );
        assert!(!deadline.covers(Duration::from_millis(250)));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(deadline.remaining(), Duration::ZERO);
        assert_eq!(deadline.attempt_timeout(Duration::from_millis(250)), None);
    }
}

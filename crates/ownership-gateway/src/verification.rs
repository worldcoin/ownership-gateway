//! Bounded verification of ownership proofs in the v1 public-input layout.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use world_id_primitives::{FieldElement, proof::OwnershipProof};
use world_id_proof::{
    ProofError,
    artifacts::{
        ZkArtifactError, ZkArtifactSource as _, cached::CachedZkArtifactSource,
        embedded::EmbeddedZkArtifacts,
    },
};

use crate::{retry::Deadline, telemetry::ErrorChain};

const VERIFY_TIMEOUT: Duration = Duration::from_secs(3);

/// A proof with the `world-id-proof` 0.20.0 public inputs:
/// `[merkle_root, nonce, expected_commitment, context]`.
pub struct V1Proof {
    /// The ownership proof, which carries its Merkle root.
    pub proof: OwnershipProof,
    /// The nonce of the challenge the proof answers.
    pub nonce: FieldElement,
    /// The commitment the client claims.
    pub commitment: FieldElement,
    /// The context of the challenge's audience.
    pub context: FieldElement,
}

/// Verifies proofs in the v1 public-input layout.
pub trait ProofVerifier: Send + Sync + 'static {
    /// Verifies the proof against every expected public input. Blocks the calling thread.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Verification`] for an invalid proof and other variants when
    /// verification could not run.
    fn verify(&self, input: &V1Proof) -> Result<(), ProofError>;
}

/// A verifier backed by the trusted artifacts embedded in `world-id-proof`.
pub struct EmbeddedVerifier {
    artifacts: CachedZkArtifactSource,
}

impl EmbeddedVerifier {
    /// Loads the verifier artifacts. Takes seconds and blocks the calling thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded artifacts cannot be loaded.
    pub fn load() -> Result<Self, ZkArtifactError> {
        let artifacts = CachedZkArtifactSource::new(EmbeddedZkArtifacts);
        artifacts.ownership_verifier()?;
        Ok(Self { artifacts })
    }
}

impl ProofVerifier for EmbeddedVerifier {
    fn verify(&self, input: &V1Proof) -> Result<(), ProofError> {
        // One thread per verification, so the worker count bounds the cores in use.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .map_err(|error| {
                ProofError::InternalError(eyre::eyre!(
                    "creating the verification thread pool: {error}"
                ))
            })?;
        pool.install(|| {
            world_id_proof::ownership_proof::verify_ownership_proof(
                &input.proof,
                input.nonce,
                input.commitment,
                input.context,
                &self.artifacts,
            )
        })
    }
}

/// The workers and the waiting queue are full.
#[derive(Debug, thiserror::Error)]
#[error("verification workers and queue are full")]
pub struct Overloaded;

/// Why an admitted verification did not accept the proof.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// The proof does not verify against the expected inputs.
    #[error("proof rejected")]
    Rejected,
    /// Verification timed out, ran past the deadline or failed to run.
    #[error("verification unavailable")]
    Unavailable,
}

/// Proof verification on a fixed number of blocking workers, with a bounded queue.
#[derive(Clone)]
pub struct VerificationPool {
    verifier: Arc<dyn ProofVerifier>,
    workers: Arc<Semaphore>,
    admission: Arc<Semaphore>,
}

impl VerificationPool {
    /// Creates a pool that runs `workers` verifications at once and queues up to `queue_depth`
    /// more.
    ///
    /// # Panics
    ///
    /// Panics if `workers + queue_depth` exceeds [`Semaphore::MAX_PERMITS`].
    #[must_use]
    pub fn new(
        verifier: Arc<dyn ProofVerifier>,
        workers: NonZeroUsize,
        queue_depth: usize,
    ) -> Self {
        let capacity = workers
            .get()
            .checked_add(queue_depth)
            .filter(|&capacity| capacity <= Semaphore::MAX_PERMITS)
            .expect("verification capacity fits a semaphore");
        Self {
            verifier,
            workers: Arc::new(Semaphore::new(workers.get())),
            admission: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Takes a place for one verification, as a worker or in the queue.
    ///
    /// # Errors
    ///
    /// Returns [`Overloaded`] at once, without waiting, when every place is taken.
    pub fn admit(&self) -> Result<Admission, Overloaded> {
        let place = self.admission.clone().try_acquire_owned().map_err(|_| {
            metrics::counter!("ownership_gateway.verify.shed").increment(1);
            Overloaded
        })?;
        Ok(Admission {
            pool: self.clone(),
            place,
        })
    }
}

/// A place in a [`VerificationPool`], held until the verification it admits finishes.
pub struct Admission {
    pool: VerificationPool,
    place: OwnedSemaphorePermit,
}

impl Admission {
    /// Verifies the proof on a blocking worker.
    ///
    /// Gives up after three seconds, including the wait for a worker, or at the deadline if that
    /// is sooner. A worker that is still running when the caller gives up keeps its place in the
    /// pool until it finishes, so a timeout never frees capacity that is still in use.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::Rejected`] for an invalid proof and
    /// [`VerificationError::Unavailable`] if verification did not finish in time or failed to run.
    pub async fn verify(self, input: V1Proof, deadline: Deadline) -> Result<(), VerificationError> {
        let Some(timeout) = deadline.attempt_timeout(VERIFY_TIMEOUT) else {
            return Err(VerificationError::Unavailable);
        };
        let started = Instant::now();
        let Self { pool, place } = self;
        let verification = async {
            let worker = pool
                .workers
                .clone()
                .acquire_owned()
                .await
                .expect("the worker semaphore is never closed");
            metrics::histogram!("ownership_gateway.verify.queue_wait")
                .record(started.elapsed().as_secs_f64());
            let verifier = pool.verifier.clone();
            let span = tracing::Span::current();
            tokio::task::spawn_blocking(move || {
                let _entered = span.enter();
                let _places = (place, worker);
                verifier.verify(&input)
            })
            .await
        };
        let result = match tokio::time::timeout(timeout, verification).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(ProofError::Verification(_)))) => Err(VerificationError::Rejected),
            Ok(Ok(Err(error))) => {
                tracing::warn!(
                    operation = "verify_proof",
                    error = %ErrorChain(&error),
                    "proof verification failed to run"
                );
                Err(VerificationError::Unavailable)
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    operation = "verify_proof",
                    error = %ErrorChain(&error),
                    "proof verification worker failed"
                );
                Err(VerificationError::Unavailable)
            }
            Err(_) => {
                tracing::warn!(
                    operation = "verify_proof",
                    timeout_ms = timeout.as_millis(),
                    "proof verification timed out"
                );
                Err(VerificationError::Unavailable)
            }
        };
        metrics::histogram!("ownership_gateway.verify.duration")
            .record(started.elapsed().as_secs_f64());
        result
    }
}

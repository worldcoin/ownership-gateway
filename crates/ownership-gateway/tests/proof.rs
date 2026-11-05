//! Bounded verification of real ownership proofs.

mod support;

use std::{
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
    time::Duration,
};

use ownership_gateway::{
    policy::audience_context,
    retry::Deadline,
    verification::{EmbeddedVerifier, ProofVerifier, V1Proof, VerificationError, VerificationPool},
};
use rand::rngs::OsRng;
use support::{GatedVerifier, ProofFixture};
use world_id_primitives::FieldElement;

struct Inputs {
    fixture: ProofFixture,
    nonce: FieldElement,
    context: FieldElement,
}

impl Inputs {
    fn v1_proof(&self) -> V1Proof {
        V1Proof {
            proof: self.fixture.proof.clone(),
            nonce: self.nonce,
            commitment: self.fixture.commitment,
            context: self.context,
        }
    }
}

/// One proof for the binary, since generating it takes seconds.
fn inputs() -> &'static Inputs {
    static INPUTS: OnceLock<Inputs> = OnceLock::new();
    INPUTS.get_or_init(|| {
        let nonce = FieldElement::random(&mut OsRng);
        let context = audience_context(&"service-a".parse().unwrap());
        Inputs {
            fixture: ProofFixture::generate(nonce, context),
            nonce,
            context,
        }
    })
}

async fn shared_inputs() -> &'static Inputs {
    tokio::task::spawn_blocking(inputs).await.unwrap()
}

fn pool(verifier: Arc<dyn ProofVerifier>, workers: usize, queue_depth: usize) -> VerificationPool {
    VerificationPool::new(verifier, NonZeroUsize::new(workers).unwrap(), queue_depth)
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(5))
}

#[tokio::test]
async fn a_real_proof_verifies_only_against_its_challenge_inputs() {
    let inputs = shared_inputs().await;
    let pool = pool(Arc::new(EmbeddedVerifier::load().unwrap()), 2, 0);
    let verify = |input| async { pool.admit().unwrap().verify(input, deadline()).await };
    verify(inputs.v1_proof()).await.unwrap();
    let other = FieldElement::from(7_u64);
    for wrong in [
        V1Proof {
            nonce: other,
            ..inputs.v1_proof()
        },
        V1Proof {
            context: other,
            ..inputs.v1_proof()
        },
        V1Proof {
            commitment: other,
            ..inputs.v1_proof()
        },
    ] {
        assert!(matches!(
            verify(wrong).await,
            Err(VerificationError::Rejected)
        ));
    }
}

#[tokio::test]
async fn admission_is_shed_once_workers_and_queue_are_full() {
    let pool = pool(Arc::new(GatedVerifier::new().0), 1, 1);
    let worker = pool.admit().unwrap();
    let queued = pool.admit().unwrap();
    assert!(pool.admit().is_err());
    drop(queued);
    let _queued = pool.admit().unwrap();
    drop(worker);
}

/// Runs a verification that blocks until released, and checks that the caller gives up after
/// `gives_up_after` while the worker keeps its place in the pool until it finishes.
///
/// Paused time does not advance on its own while a blocking task runs, so the test advances it.
async fn assert_timed_out_worker_keeps_its_place(deadline: Deadline, gives_up_after: Duration) {
    let inputs = shared_inputs().await;
    let (verifier, mut gate) = GatedVerifier::new();
    let pool = pool(Arc::new(verifier), 1, 0);
    let admission = pool.admit().unwrap();
    let running = tokio::spawn(admission.verify(inputs.v1_proof(), deadline));
    gate.started.recv().await.unwrap();
    tokio::time::advance(gives_up_after.saturating_sub(Duration::from_millis(1))).await;
    tokio::task::yield_now().await;
    assert!(!running.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(matches!(
        running.await.unwrap(),
        Err(VerificationError::Unavailable)
    ));
    assert!(pool.admit().is_err(), "the running worker keeps its place");
    gate.release.send(()).unwrap();
    gate.finished.recv().await.unwrap();
    while pool.admit().is_err() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn verification_gives_up_after_three_seconds_without_freeing_the_worker() {
    assert_timed_out_worker_keeps_its_place(
        Deadline::after(Duration::from_secs(10)),
        Duration::from_secs(3),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn verification_gives_up_at_an_earlier_deadline() {
    assert_timed_out_worker_keeps_its_place(
        Deadline::after(Duration::from_secs(1)),
        Duration::from_secs(1),
    )
    .await;
}

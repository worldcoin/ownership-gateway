//! The token endpoint, which exchanges an ownership proof for a short-lived token.
//!
//! A request claims its challenge's single verification attempt before any expensive work, so
//! concurrent requests for one challenge verify at most one proof. A rejected proof or root, a
//! disallowed origin or a disabled audience discards the challenge. A transient failure after
//! the claim (Redis, the root service or KMS) leaves the challenge claimed and therefore
//! unusable: the client must request a new challenge, which the `request_new_challenge` code
//! says.

use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{FromRequest as _, Request, State},
    http::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ownership_token::{Audience, Claims, Issuer, Subject, TokenId};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, de};
use world_id_primitives::{FieldElement, proof::OwnershipProof};

use crate::{
    challenge::{Challenge, ChallengeId},
    cors,
    error::{ApiError, ApiJson},
    retry::Deadline,
    root::{self, RootValidator, RootVerdict},
    signing::{self, KmsFailure, KmsSigner, SigningError},
    state::AppState,
    store::{self, Attempt},
    telemetry::{Dependency, ErrorChain},
    verification::{V1Proof, VerificationError, VerificationPool},
};

/// The shortest request deadline accepted: it fits the claim, a root check attempt, the consume
/// and a signing attempt. Verification is left out because its three-second limit is a ceiling,
/// not a typical cost, and counting it would exceed the five-second default.
pub const MIN_REQUEST_DEADLINE: Duration = store::COMMAND_TIMEOUT
    .saturating_add(root::ATTEMPT_TIMEOUT)
    .saturating_add(CONSUME_AND_SIGN_BUDGET);

/// The time left that a request needs to consume its challenge and make one signing attempt.
/// A request with less stops before the consume.
const CONSUME_AND_SIGN_BUDGET: Duration =
    store::COMMAND_TIMEOUT.saturating_add(signing::ATTEMPT_TIMEOUT);

/// The dependencies and settings of the token exchange.
pub struct Exchange {
    /// The issuer named in every token.
    pub issuer: Issuer,
    /// Bounded proof verification.
    pub verification: VerificationPool,
    /// Registry root checks.
    pub roots: Arc<RootValidator>,
    /// The token signer.
    pub signer: Arc<KmsSigner>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenRequest {
    challenge_id: ChallengeId,
    commitment: Commitment,
    proof: EncodedProof,
}

/// The commitment a request claims: the token's subject, and the same value as the public input
/// the proof must commit to.
struct Commitment {
    subject: Subject,
    field: FieldElement,
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let subject = Subject::deserialize(deserializer)?;
        let field = subject.as_str().parse().map_err(de::Error::custom)?;
        Ok(Self { subject, field })
    }
}

/// A standard-base64 CBOR ownership proof. It is decoded only after its challenge's attempt is
/// claimed, so a malformed proof uses up the challenge.
#[derive(Deserialize)]
#[serde(transparent)]
struct EncodedProof(String);

impl EncodedProof {
    /// Decodes the proof and drops the encoded text, so that only the decoded proof, which
    /// verification consumes, is held while the request has its verification place.
    fn decode(self) -> Option<OwnershipProof> {
        let bytes = STANDARD.decode(self.0).ok()?;
        let mut input = Cursor::new(bytes.as_slice());
        let proof = ciborium::from_reader(&mut input).ok()?;
        (usize::try_from(input.position()).ok()? == bytes.len()).then_some(proof)
    }
}

#[derive(Serialize)]
pub(crate) struct TokenResponse {
    token: String,
    expires_at: DateTime<Utc>,
}

/// Why a token request was rejected, as named in the `reason` tag of `tokens.rejected`. The
/// response says only whether the challenge or the proof failed, not which check.
#[derive(Clone, Copy, Debug)]
enum Rejection {
    /// No challenge has the identifier, or it expired.
    UnknownChallenge,
    /// Another request already claimed the challenge's attempt.
    AttemptTaken,
    /// The challenge's audience is no longer enabled.
    AudienceDisabled,
    /// The challenge's audience does not allow the browser origin.
    OriginNotAllowed,
    /// The proof is not base64 CBOR of an ownership proof.
    MalformedProof,
    /// The proof does not verify against the challenge.
    InvalidProof,
    /// The registry does not accept the proof's root.
    RootInvalid,
    /// The challenge expired or was consumed before this request could consume it.
    ChallengeConsumed,
}

impl Rejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::UnknownChallenge => "unknown_challenge",
            Self::AttemptTaken => "attempt_taken",
            Self::AudienceDisabled => "audience_disabled",
            Self::OriginNotAllowed => "origin_not_allowed",
            Self::MalformedProof => "malformed_proof",
            Self::InvalidProof => "invalid_proof",
            Self::RootInvalid => "root_invalid",
            Self::ChallengeConsumed => "challenge_consumed",
        }
    }

    /// Counts the rejection and returns its response.
    fn record(self, aud: Option<&Audience>) -> ApiError {
        let reason = self.as_str();
        match aud {
            Some(aud) => metrics::counter!(
                "ownership_gateway.tokens.rejected",
                "aud" => aud.to_string(),
                "reason" => reason
            )
            .increment(1),
            None => {
                metrics::counter!("ownership_gateway.tokens.rejected", "reason" => reason)
                    .increment(1);
            }
        }
        match self {
            Self::UnknownChallenge
            | Self::AttemptTaken
            | Self::AudienceDisabled
            | Self::ChallengeConsumed => ApiError::ChallengeUnusable,
            Self::OriginNotAllowed => ApiError::OriginNotAllowed,
            Self::MalformedProof | Self::InvalidProof | Self::RootInvalid => {
                ApiError::ProofRejected
            }
        }
    }
}

/// Exchanges a proof for a token: `POST /v1/tokens`.
///
/// The request takes its place in the verification pool before its body is read, so the pool
/// bounds the proofs buffered as well as the verifications running.
pub(crate) async fn post_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<TokenResponse>, ApiError> {
    let deadline = Deadline::after(state.request_deadline);
    let exchange = &state.exchange;
    if cors::check_any_origin(&state.policies, &headers).is_err() {
        return Err(Rejection::OriginNotAllowed.record(None));
    }
    let admission = exchange
        .verification
        .admit()
        .map_err(|_| ApiError::Overloaded)?;
    let ApiJson(TokenRequest {
        challenge_id: id,
        commitment,
        proof,
    }) = ApiJson::<TokenRequest>::from_request(request, &state).await?;
    let challenge = claim_attempt(&state, &id, deadline).await?;
    let Some(policy) = state.policies.enabled_policy(&challenge.aud) else {
        return Err(discard(
            &state,
            &id,
            &challenge,
            Rejection::AudienceDisabled,
            deadline,
        )
        .await);
    };
    if cors::check_origin(policy, &headers).is_err() {
        return Err(discard(
            &state,
            &id,
            &challenge,
            Rejection::OriginNotAllowed,
            deadline,
        )
        .await);
    }
    let Some(proof) = proof.decode() else {
        return Err(discard(&state, &id, &challenge, Rejection::MalformedProof, deadline).await);
    };
    let root = proof.merkle_root;
    let input = V1Proof {
        proof,
        nonce: challenge.nonce,
        commitment: commitment.field,
        context: challenge.context,
    };
    match admission.verify(input, deadline).await {
        Ok(()) => {}
        Err(VerificationError::Rejected) => {
            return Err(discard(&state, &id, &challenge, Rejection::InvalidProof, deadline).await);
        }
        Err(VerificationError::Unavailable) => return Err(ApiError::NeedsNewChallenge),
    }
    match exchange.roots.check(root, deadline).await {
        RootVerdict::Valid => {}
        RootVerdict::Invalid => {
            return Err(discard(&state, &id, &challenge, Rejection::RootInvalid, deadline).await);
        }
        RootVerdict::Unavailable => return Err(ApiError::NeedsNewChallenge),
    }
    if !deadline.covers(CONSUME_AND_SIGN_BUDGET) {
        metrics::counter!(
            "ownership_gateway.tokens.deadline_exhausted",
            "aud" => challenge.aud.to_string()
        )
        .increment(1);
        tracing::warn!(
            operation = "exchange_token",
            remaining_ms = deadline.remaining().as_millis(),
            "too little time left to consume the challenge and sign; it stays claimed"
        );
        return Err(ApiError::NeedsNewChallenge);
    }
    consume(&state, &id, &challenge, deadline).await?;
    let token = issue_token(
        exchange,
        challenge.aud,
        commitment.subject,
        policy.token_ttl(),
        SystemTime::now(),
        deadline,
    )
    .await?;
    Ok(Json(token))
}

async fn claim_attempt(
    state: &AppState,
    id: &ChallengeId,
    deadline: Deadline,
) -> Result<Challenge, ApiError> {
    match state.store.claim_attempt(id, deadline).await {
        Ok(Attempt::Claimed(challenge)) => Ok(challenge),
        Ok(Attempt::Unknown) => Err(Rejection::UnknownChallenge.record(None)),
        Ok(Attempt::Taken) => Err(Rejection::AttemptTaken.record(None)),
        Err(error) => {
            tracing::warn!(
                dependency = Dependency::Redis.as_str(),
                operation = "claim_attempt",
                error = %ErrorChain(&error),
                "claiming the challenge attempt failed"
            );
            Err(ApiError::NeedsNewChallenge)
        }
    }
}

/// Rejects the request and deletes its challenge. The claimed attempt already keeps the
/// challenge from being exchanged, so a failed delete only leaves it to expire.
async fn discard(
    state: &AppState,
    id: &ChallengeId,
    challenge: &Challenge,
    rejection: Rejection,
    deadline: Deadline,
) -> ApiError {
    if let Err(error) = state.store.discard(id, deadline).await {
        tracing::warn!(
            dependency = Dependency::Redis.as_str(),
            operation = "discard_challenge",
            error = %ErrorChain(&error),
            "discarding a rejected challenge failed; it expires on its own"
        );
    }
    rejection.record(Some(&challenge.aud))
}

/// Consumes the challenge. Only the request that removes the stored record may sign.
async fn consume(
    state: &AppState,
    id: &ChallengeId,
    challenge: &Challenge,
    deadline: Deadline,
) -> Result<(), ApiError> {
    match state.store.consume(id, deadline).await {
        Ok(Some(consumed)) if consumed == *challenge => Ok(()),
        Ok(_) => Err(Rejection::ChallengeConsumed.record(Some(&challenge.aud))),
        Err(error) => {
            tracing::warn!(
                dependency = Dependency::Redis.as_str(),
                operation = "consume_challenge",
                error = %ErrorChain(&error),
                "consuming the challenge failed; its outcome is unknown and no token is issued"
            );
            Err(ApiError::NeedsNewChallenge)
        }
    }
}

async fn issue_token(
    exchange: &Exchange,
    aud: Audience,
    sub: Subject,
    ttl: Duration,
    now: SystemTime,
    deadline: Deadline,
) -> Result<TokenResponse, ApiError> {
    let Ok(issued) = now.duration_since(UNIX_EPOCH) else {
        tracing::error!(
            operation = "issue_token",
            "the system clock is before the Unix epoch"
        );
        return Err(ApiError::NeedsNewChallenge);
    };
    let iat = issued.as_secs();
    let exp = iat + ttl.as_secs();
    let mut token_id = [0_u8; 16];
    OsRng.fill_bytes(&mut token_id);
    let claims = Claims {
        iss: exchange.issuer.clone(),
        aud,
        sub,
        iat,
        nbf: iat,
        exp,
        jti: TokenId::from_bytes(token_id),
    };
    let token = exchange
        .signer
        .sign_token(&claims, deadline)
        .await
        .map_err(|error| match error {
            SigningError::Kms {
                failure: KmsFailure::Throttled(_),
                ..
            } => ApiError::Throttled,
            _ => ApiError::NeedsNewChallenge,
        })?;
    // Two slow signing attempts can outlast a short token lifetime.
    if !token_is_live(iat, exp, SystemTime::now()) {
        tracing::warn!(
            operation = "issue_token",
            "the token expired while it was signed"
        );
        return Err(ApiError::NeedsNewChallenge);
    }
    metrics::counter!("ownership_gateway.tokens.issued", "aud" => claims.aud.to_string())
        .increment(1);
    Ok(TokenResponse {
        token,
        expires_at: (UNIX_EPOCH + Duration::from_secs(exp)).into(),
    })
}

fn token_is_live(iat: u64, exp: u64, now: SystemTime) -> bool {
    now.duration_since(UNIX_EPOCH)
        .is_ok_and(|now| (iat..exp).contains(&now.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_live_from_issuance_until_expiry() {
        let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
        assert!(token_is_live(100, 101, at(100)));
        assert!(!token_is_live(100, 101, at(101)));
        assert!(!token_is_live(100, 101, at(99)));
        assert!(!token_is_live(
            100,
            101,
            UNIX_EPOCH - Duration::from_secs(1)
        ));
    }
}

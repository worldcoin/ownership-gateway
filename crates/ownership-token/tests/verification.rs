//! Ownership token verification through the public API.

use ownership_token::{
    Audience, Claims, Issuer, JwkSet, KeySet, KeysUnavailable, MAX_TOKEN_LIFETIME, RejectionReason,
    Subject, TOKEN_TYPE, TokenId, TokenVerifier, VerifyError,
    test_util::{TestIssuer, claims},
};
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};

const NOW: u64 = 1100;
const LEEWAY: u64 = 60;
const ISSUED_AT: u64 = NOW - 100;

struct Fixture {
    issuer: TestIssuer,
    jwks: JwkSet,
    claims: Claims,
    verifier: TokenVerifier,
}

fn setup() -> Fixture {
    let issuer = TestIssuer::new();
    let jwks = issuer.jwks();
    let claims = claims(ISSUED_AT);
    let verifier = TokenVerifier::new(
        claims.iss.clone(),
        [claims.aud.clone()],
        Duration::from_secs(LEEWAY),
    )
    .unwrap();
    Fixture {
        issuer,
        jwks,
        claims,
        verifier,
    }
}

impl Fixture {
    async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        self.verifier
            .verify(token, &self.jwks, UNIX_EPOCH + Duration::from_secs(NOW))
            .await
    }

    async fn assert_rejected(&self, token: &str, reason: RejectionReason, case: &str) {
        let result = self.verify(token).await;
        assert_eq!(result.unwrap_err(), VerifyError::BadToken(reason), "{case}");
    }
}

#[tokio::test]
async fn verifies_signed_claims() {
    let fixture = setup();
    let token = fixture.issuer.token(&fixture.claims);
    assert_eq!(fixture.verify(&token).await.unwrap(), fixture.claims);
}

#[tokio::test]
async fn rejects_unsupported_headers_and_unknown_key() {
    let fixture = setup();
    let kid = fixture.jwks.keys()[0].kid();
    let header = json!({"alg":"ES256", "typ":TOKEN_TYPE, "kid": kid});
    let cases = [
        (
            "wrong algorithm",
            json!({"alg":"none", "typ":TOKEN_TYPE, "kid": kid}),
            RejectionReason::UnsupportedHeader,
        ),
        (
            "wrong type",
            json!({"alg":"ES256", "typ":"JWT", "kid": kid}),
            RejectionReason::UnsupportedHeader,
        ),
        (
            "empty kid",
            json!({"alg":"ES256", "typ":TOKEN_TYPE, "kid":""}),
            RejectionReason::UnsupportedHeader,
        ),
        (
            "missing type",
            json!({"alg":"ES256", "kid": kid}),
            RejectionReason::Malformed,
        ),
        (
            "missing kid",
            json!({"alg":"ES256", "typ":TOKEN_TYPE}),
            RejectionReason::Malformed,
        ),
        (
            "unknown key",
            json!({"alg":"ES256", "typ":TOKEN_TYPE, "kid":"unknown"}),
            RejectionReason::UnknownKey,
        ),
    ];
    for (case, header, reason) in cases {
        fixture
            .assert_rejected(
                &fixture.issuer.token_with_header(&header, &fixture.claims),
                reason,
                case,
            )
            .await;
    }
    for forbidden in ["jku", "x5u", "jwk", "x5c", "crit", "b64"] {
        let mut header = header.clone();
        header[forbidden] = json!(null);
        fixture
            .assert_rejected(
                &fixture.issuer.token_with_header(&header, &fixture.claims),
                RejectionReason::UnsupportedHeader,
                forbidden,
            )
            .await;
    }
}

#[tokio::test]
async fn rejects_bad_claims_and_missing_claims() {
    let fixture = setup();
    let value = serde_json::to_value(&fixture.claims).unwrap();
    for (field, bad, reason) in [
        (
            "iss",
            json!("https://other.example"),
            RejectionReason::WrongIssuer,
        ),
        ("aud", json!(["service"]), RejectionReason::Malformed),
        ("aud", json!("other"), RejectionReason::WrongAudience),
        ("sub", json!("0x01"), RejectionReason::Malformed),
        ("jti", json!("bad"), RejectionReason::Malformed),
        ("exp", json!(NOW - LEEWAY), RejectionReason::Expired),
        ("nbf", json!(NOW + LEEWAY + 1), RejectionReason::NotYetValid),
        ("iat", json!(-1), RejectionReason::Malformed),
        ("nbf", json!(1.5), RejectionReason::Malformed),
        ("exp", json!(-1), RejectionReason::Malformed),
    ] {
        let mut claims = value.clone();
        claims[field] = bad;
        fixture
            .assert_rejected(&fixture.issuer.token(&claims), reason, field)
            .await;
    }
    for field in ["iss", "aud", "sub", "iat", "nbf", "exp", "jti"] {
        let mut claims = value.clone();
        claims.as_object_mut().unwrap().remove(field);
        fixture
            .assert_rejected(
                &fixture.issuer.token(&claims),
                RejectionReason::MissingClaim,
                field,
            )
            .await;
    }
}

#[tokio::test]
async fn rejects_malformed_and_invalid_signatures() {
    let fixture = setup();
    let other = TestIssuer::from_seed(2);
    let header = json!({"alg":"ES256", "typ":TOKEN_TYPE, "kid": fixture.jwks.keys()[0].kid()});
    let token = other.token_with_header(&header, &fixture.claims);
    fixture
        .assert_rejected(&token, RejectionReason::BadSignature, "wrong signing key")
        .await;
    fixture
        .assert_rejected("broken", RejectionReason::Malformed, "compact encoding")
        .await;
    let (content, _) = token.rsplit_once('.').unwrap();
    fixture
        .assert_rejected(
            &format!("{content}.AA"),
            RejectionReason::Malformed,
            "short signature",
        )
        .await;
}

#[test]
fn jwks_round_trip() {
    let Fixture { jwks, .. } = setup();
    let serialized = serde_json::to_string(&jwks).unwrap();
    assert_eq!(serde_json::from_str::<JwkSet>(&serialized).unwrap(), jwks);
}

#[test]
fn verifier_enforces_the_leeway_limit() {
    for (seconds, accepted) in [(60, true), (61, false)] {
        assert_eq!(
            TokenVerifier::new(
                "https://issuer.example".parse().unwrap(),
                ["service".parse().unwrap()],
                Duration::from_secs(seconds)
            )
            .is_ok(),
            accepted
        );
    }
}

struct Unavailable;

impl KeySet for Unavailable {
    fn key(
        &self,
        _kid: &str,
    ) -> impl std::future::Future<
        Output = Result<Option<p256::ecdsa::VerifyingKey>, KeysUnavailable>,
    > + Send {
        std::future::ready(Err(KeysUnavailable))
    }
}

#[tokio::test]
async fn reports_unavailable_keys_separately() {
    let fixture = setup();
    let token = fixture.issuer.token(&fixture.claims);
    assert!(matches!(
        fixture
            .verifier
            .verify(&token, &Unavailable, UNIX_EPOCH)
            .await,
        Err(VerifyError::KeysUnavailable)
    ));
}

#[tokio::test]
async fn applies_leeway_at_time_boundaries() {
    let mut fixture = setup();
    fixture.claims.iat = NOW - 200;
    fixture.claims.nbf = NOW - 100;
    fixture.claims.exp = NOW - LEEWAY + 1;
    let token = fixture.issuer.token(&fixture.claims);
    assert_eq!(fixture.verify(&token).await.unwrap(), fixture.claims);
    assert_eq!(
        fixture
            .verifier
            .verify(
                &token,
                &fixture.jwks,
                UNIX_EPOCH + Duration::from_secs(NOW + 1)
            )
            .await
            .unwrap_err(),
        VerifyError::BadToken(RejectionReason::Expired)
    );
}

#[test]
fn rejects_tampered_jwk_fields() {
    let Fixture { jwks, .. } = setup();
    for (field, value) in [
        ("kid", json!("wrong")),
        ("alg", json!("ES384")),
        ("x", json!("bad")),
        ("use", json!("enc")),
    ] {
        let mut document = serde_json::to_value(&jwks).unwrap();
        document["keys"][0][field] = value;
        assert!(
            serde_json::from_value::<JwkSet>(document).is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn rejects_invalid_lifetimes_and_sender_constrained_tokens() {
    let fixture = setup();
    for (field, value, reason) in [
        ("exp", json!(ISSUED_AT), RejectionReason::InvalidLifetime),
        (
            "nbf",
            json!(ISSUED_AT - 1),
            RejectionReason::InvalidLifetime,
        ),
        (
            "exp",
            json!(ISSUED_AT + MAX_TOKEN_LIFETIME.as_secs() + 1),
            RejectionReason::InvalidLifetime,
        ),
        ("cnf", json!(null), RejectionReason::SenderConstrained),
    ] {
        let mut payload = serde_json::to_value(&fixture.claims).unwrap();
        payload[field] = value;
        fixture
            .assert_rejected(&fixture.issuer.token(&payload), reason, field)
            .await;
    }
    let mut future_issue = serde_json::to_value(&fixture.claims).unwrap();
    future_issue["iat"] = json!(NOW + LEEWAY + 1);
    future_issue["nbf"] = json!(NOW + LEEWAY + 1);
    fixture
        .assert_rejected(
            &fixture.issuer.token(&future_issue),
            RejectionReason::InvalidLifetime,
            "future issue time",
        )
        .await;
    let mut payload = serde_json::to_value(&fixture.claims).unwrap();
    payload["future_claim"] = json!(true);
    assert!(
        fixture
            .verify(&fixture.issuer.token(&payload))
            .await
            .is_ok()
    );
}

#[test]
fn rejects_invalid_claim_values() {
    assert!("http://issuer.example".parse::<Issuer>().is_err());
    assert!(
        "https://user:pass@issuer.example"
            .parse::<Issuer>()
            .is_err()
    );
    assert!("".parse::<Audience>().is_err());
    assert!(format!("0x{}", "ff".repeat(32)).parse::<Subject>().is_err());
    assert!(format!("0x{}", "AB".repeat(32)).parse::<Subject>().is_err());

    for value in ["", "service name", " service", "é", "service\n"] {
        assert!(value.parse::<Audience>().is_err(), "{value:?}");
    }
    assert!(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
            .parse::<Subject>()
            .is_err()
    );
    assert!(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"
            .parse::<Subject>()
            .is_ok()
    );
    assert!("AAAAAAAAAAAAAAAAAAAAAB".parse::<TokenId>().is_err());
}

#[tokio::test]
async fn accepts_lifetime_and_future_issue_boundaries() {
    let mut fixture = setup();
    fixture.claims.exp = fixture.claims.iat + MAX_TOKEN_LIFETIME.as_secs();
    fixture
        .verify(&fixture.issuer.token(&fixture.claims))
        .await
        .unwrap();
    fixture.claims.iat = NOW + LEEWAY;
    fixture.claims.nbf = fixture.claims.iat;
    fixture.claims.exp = fixture.claims.iat + MAX_TOKEN_LIFETIME.as_secs();
    fixture
        .verify(&fixture.issuer.token(&fixture.claims))
        .await
        .unwrap();
}

#[test]
fn fixture_accepts_the_full_nonzero_seed_range() {
    assert_ne!(
        TestIssuer::from_seed(1).jwks(),
        TestIssuer::from_seed(u8::MAX).jwks()
    );
}

#[tokio::test]
async fn reports_a_pre_epoch_clock_as_a_host_error() {
    let fixture = setup();
    let result = fixture
        .verifier
        .verify(
            &fixture.issuer.token(&fixture.claims),
            &fixture.jwks,
            UNIX_EPOCH - Duration::from_secs(1),
        )
        .await;
    assert_eq!(result.unwrap_err(), VerifyError::InvalidClock);
}

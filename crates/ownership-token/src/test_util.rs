//! Fixtures for integration tests that issue ownership tokens.
use crate::{Claims, Jwk, JwkSet, TOKEN_TYPE, TokenId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{SigningKey, signature::Signer};
use serde::Serialize;
use serde_json::{Value, json};

/// A deterministic test issuer. Never use its key outside tests.
#[derive(Debug)]
pub struct TestIssuer {
    key: SigningKey,
}
impl Default for TestIssuer {
    fn default() -> Self {
        Self::new()
    }
}
impl TestIssuer {
    /// Creates an issuer with a deterministic signing key.
    #[must_use]
    pub fn new() -> Self {
        Self::from_seed(1)
    }
    /// Creates an issuer from a nonzero deterministic seed.
    ///
    /// # Panics
    ///
    /// Panics if the seed is zero.
    #[must_use]
    pub fn from_seed(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        Self {
            key: SigningKey::from_bytes((&bytes).into()).expect("valid fixture key"),
        }
    }

    /// Returns the issuer's public key set.
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        JwkSet::new(vec![Jwk::from_public_key(self.key.verifying_key())])
    }
    /// Signs claims with the standard ownership header.
    #[must_use]
    pub fn token(&self, claims: &impl Serialize) -> String {
        self.token_with_header(
            &json!({"alg":"ES256", "typ":TOKEN_TYPE, "kid":self.jwks().keys()[0].kid()}),
            claims,
        )
    }
    /// Signs a custom header and claims, including deliberately invalid test inputs.
    #[must_use]
    pub fn token_with_header(&self, header: &Value, claims: &impl Serialize) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("serializable header")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serializable claims"))
        );
        let signature: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

/// Builds default claims at the supplied Unix timestamp for test scenarios.
#[must_use]
pub fn claims(now: u64) -> Claims {
    Claims {
        iss: "https://issuer.example".parse().expect("fixture issuer"),
        aud: "service".parse().expect("fixture audience"),
        sub: format!("0x{}", "01".repeat(32))
            .parse()
            .expect("fixture subject"),
        iat: now,
        nbf: now,
        exp: now + 600,
        jti: TokenId::from_bytes([7; 16]),
    }
}

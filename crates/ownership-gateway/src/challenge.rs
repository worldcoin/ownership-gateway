//! Challenges: their identifiers and the binding stored for each one.

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ownership_token::Audience;
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use world_id_primitives::FieldElement;

const CHALLENGE_ID_BYTES: usize = 32;

/// A challenge identifier: 32 random bytes in unpadded base64url.
///
/// Identifiers are unguessable, and knowing one is what lets a client exchange its challenge,
/// so they are never logged. `Debug` does not print the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeId(String);

/// A string that is not a canonical challenge identifier.
#[derive(Debug, thiserror::Error)]
#[error("challenge ID must be 32 bytes in canonical unpadded base64url")]
pub struct InvalidChallengeId;

impl ChallengeId {
    /// Generates an identifier from the operating system's random number generator.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CHALLENGE_ID_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Returns the encoded identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the Redis key that holds the challenge.
    #[must_use]
    pub fn redis_key(&self) -> String {
        format!("challenge:{{{}}}", self.0)
    }

    /// Returns the Redis key that marks the challenge's verification attempt as taken. It shares
    /// the challenge key's hash tag, so a script that uses both keys runs on one cluster slot.
    #[must_use]
    pub fn attempt_key(&self) -> String {
        format!("challenge-attempt:{{{}}}", self.0)
    }
}

impl fmt::Debug for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeId(..)")
    }
}

impl FromStr for ChallengeId {
    type Err = InvalidChallengeId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| InvalidChallengeId)?;
        if bytes.len() != CHALLENGE_ID_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(InvalidChallengeId);
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for ChallengeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ChallengeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// The binding stored for a challenge until it expires or is consumed. A proof for the
/// challenge must use exactly this context and nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The audience the challenge was issued for.
    pub aud: Audience,
    /// The proof context derived from the audience.
    pub context: FieldElement,
    /// The random proof nonce.
    pub nonce: FieldElement,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_parse_back() {
        let id = ChallengeId::generate();
        assert_eq!(id.as_str().parse::<ChallengeId>().unwrap(), id);
        assert_ne!(ChallengeId::generate(), id);
        assert_eq!(id.redis_key(), format!("challenge:{{{}}}", id.as_str()));
    }

    #[test]
    fn rejects_identifiers_that_are_not_canonical() {
        let short = URL_SAFE_NO_PAD.encode([1_u8; 31]);
        let padded = format!("{}=", URL_SAFE_NO_PAD.encode([1_u8; 32]));
        let standard_alphabet = URL_SAFE_NO_PAD.encode([0xfb_u8; 32]).replace('-', "+");
        let mut trailing_bits = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        trailing_bits.replace_range(42.., "B");
        for rejected in [
            String::new(),
            short,
            padded,
            standard_alphabet,
            trailing_bits,
        ] {
            assert!(rejected.parse::<ChallengeId>().is_err(), "{rejected}");
        }
    }

    #[test]
    fn debug_does_not_print_the_identifier() {
        let id = ChallengeId::generate();
        assert!(!format!("{id:?}").contains(id.as_str()));
    }
}

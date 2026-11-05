use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, de};

/// An invalid value for an ownership token claim.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{0}")]
pub struct InvalidValue(&'static str);

macro_rules! string_type {
    ($(#[$doc:meta])* $name:ident, $label:literal, $valid:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Returns the original string value.
            #[must_use]
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl FromStr for $name {
            type Err = InvalidValue;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if ($valid)(value) { Ok(Self(value.to_owned())) } else { Err(InvalidValue($label)) }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?.parse().map_err(de::Error::custom)
            }
        }
    }
}

fn valid_issuer(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn valid_audience(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_subject(value: &str) -> bool {
    const MODULUS: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    value.strip_prefix("0x").is_some_and(|hex| {
        // Equal-length lowercase hexadecimal strings sort in numeric order.
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && hex < MODULUS
    })
}

string_type! {
    /// An absolute HTTPS issuer URL, compared exactly as supplied.
    Issuer, "issuer must be an absolute HTTPS URL without credentials or fragment", valid_issuer
}
string_type! {
    /// A nonempty audience identifier containing only visible ASCII.
    Audience, "audience must contain only visible ASCII without whitespace", valid_audience
}
string_type! {
    /// A BN254 scalar field element below the modulus, as `0x` followed by 64 lowercase hex digits.
    Subject, "subject must be 0x followed by 64 lowercase hex digits below the BN254 modulus", valid_subject
}

fn valid_token_id(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 16)
}

string_type! {
    /// A 128-bit token identifier encoded as unpadded base64url.
    TokenId, "token ID must be 16 bytes of unpadded base64url", valid_token_id
}
impl TokenId {
    /// Creates an identifier from 16 independently generated random bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }
}

/// Required claims in a signed ownership token. Timestamps are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The global issuer URL.
    pub iss: Issuer,
    /// The single intended audience.
    pub aud: Audience,
    /// The credential `sub` whose ownership was proven (the WIP-103 `expected_commitment`).
    pub sub: Subject,
    /// Issuance time; it may not be later than the current time plus leeway.
    pub iat: u64,
    /// Earliest accepted time, subject to verifier leeway; must be at least `iat`.
    pub nbf: u64,
    /// Exclusive expiration time, subject to verifier leeway and the lifetime limit.
    pub exp: u64,
    /// Independently generated random identifier.
    pub jti: TokenId,
}

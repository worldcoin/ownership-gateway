//! Claims and verification for World ID ownership tokens.
//!
//! The verifier accepts only ES256 tokens from the configured issuer and audiences.
//! Applications must compare the verified subject with their own account binding.

mod claims;
mod jwk;
mod verifier;

#[cfg(feature = "test-util")]
pub mod test_util;

pub use claims::{Audience, Claims, InvalidValue, Issuer, Subject, TokenId};
pub use jwk::{Jwk, JwkSet};
pub use verifier::{
    KeySet, KeysUnavailable, MAX_LEEWAY, MAX_TOKEN_LIFETIME, RejectionReason, TokenVerifier,
    VerifierConfigError, VerifyError,
};

/// The protected `typ` header required on ownership tokens.
pub const TOKEN_TYPE: &str = "wip103+jwt";

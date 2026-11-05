//! Verify World ID ownership tokens issued by ownership-gateway.
//!
//! Applications must compare the verified subject with their own account binding.
//!
//! Features:
//! - `remote-jwks`: fetch and refresh trusted keys.
//! - `test-util`: deterministic test issuers and claims.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(feature = "remote-jwks")]
//! # async fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use ownership_token::{RemoteJwks, TokenVerifier, MAX_LEEWAY};
//! use std::time::SystemTime;
//! let jwks = RemoteJwks::new("https://issuer.example/jwks".parse()?)?;
//! jwks.refresh().await?;
//! tokio::spawn(jwks.clone().run_refresh());
//! let verifier = TokenVerifier::new(
//!     "https://issuer.example".parse()?, ["service".parse()?], MAX_LEEWAY,
//! )?;
//! let claims = verifier.verify(token, &jwks, SystemTime::now()).await?;
//! # Ok(())
//! # }
//! ```
//!
#![cfg_attr(docsrs, feature(doc_cfg))]

mod claims;
mod jwk;
#[cfg(feature = "remote-jwks")]
mod remote_jwks;
mod verifier;

#[cfg(feature = "test-util")]
pub mod test_util;

pub use claims::{Audience, Claims, InvalidValue, Issuer, Subject, TokenId};
pub use jwk::{Jwk, JwkSet};
#[cfg(feature = "remote-jwks")]
pub use remote_jwks::{InvalidJwksUrl, JwksConfigError, JwksFetchError, JwksUrl, RemoteJwks};
pub use verifier::{
    KeySet, KeysUnavailable, MAX_LEEWAY, MAX_TOKEN_LIFETIME, RejectionReason, TokenVerifier,
    VerifierConfigError, VerifyError,
};

/// The protected `typ` header required on ownership tokens.
pub const TOKEN_TYPE: &str = "wip103+jwt";

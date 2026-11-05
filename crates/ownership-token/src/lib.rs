//! Verify World ID ownership tokens issued by ownership-gateway.
//!
//! Applications must compare the verified subject with their own account binding.
//!
//! Features:
//! - `remote-jwks`: fetch and refresh trusted keys.
//! - `tower`: verify requests with an Axum-compatible layer and extractor.
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
//! ```no_run
//! # #[cfg(all(feature = "remote-jwks", feature = "tower"))]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use axum::{Router, routing::get};
//! use ownership_token::{OwnershipLayer, RemoteJwks, TokenVerifier, VerifiedOwnership, MAX_LEEWAY};
//! use std::sync::Arc;
//! async fn handler(VerifiedOwnership(claims): VerifiedOwnership) -> String {
//!     claims.sub.to_string()
//! }
//! let jwks = RemoteJwks::new("https://issuer.example/jwks".parse()?)?;
//! jwks.refresh().await?;
//! tokio::spawn(jwks.clone().run_refresh());
//! let verifier = TokenVerifier::new(
//!     "https://issuer.example".parse()?, ["service".parse()?], MAX_LEEWAY,
//! )?;
//! let app: Router = Router::new().route("/", get(handler))
//!     .layer(OwnershipLayer::new(Arc::new(verifier), jwks));
//! # Ok(())
//! # }
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]

mod claims;
mod jwk;
#[cfg(feature = "tower")]
mod layer;
#[cfg(feature = "remote-jwks")]
mod remote_jwks;
mod verifier;

#[cfg(feature = "test-util")]
pub mod test_util;

pub use claims::{Audience, Claims, InvalidValue, Issuer, Subject, TokenId, UseCase};
pub use jwk::{Jwk, JwkSet};
#[cfg(feature = "tower")]
pub use layer::{
    InvalidUnprotectedPath, OwnershipLayer, OwnershipService, Rejection, UnprotectedPath,
    VerifiedOwnership,
};
#[cfg(feature = "remote-jwks")]
pub use remote_jwks::{InvalidJwksUrl, JwksConfigError, JwksFetchError, JwksUrl, RemoteJwks};
pub use verifier::{
    KeySet, KeysUnavailable, MAX_LEEWAY, MAX_TOKEN_LIFETIME, RejectionReason, TokenVerifier,
    VerifierConfigError, VerifyError,
};

/// The protected `typ` header required on ownership tokens.
pub const TOKEN_TYPE: &str = "wip103+jwt";

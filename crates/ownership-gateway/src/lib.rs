//! The ownership gateway.
//!
//! It issues single-use challenges, exchanges WIP-103 ownership proofs for short-lived,
//! audience-scoped ES256 tokens, and serves the public keys that verify those tokens.

pub mod challenge;
pub mod config;
mod cors;
pub mod error;
pub mod jwks;
pub mod policy;
mod readiness;
pub mod retry;
pub mod root;
pub mod server;
pub mod signing;
pub mod state;
pub mod store;
mod telemetry;
pub mod verification;

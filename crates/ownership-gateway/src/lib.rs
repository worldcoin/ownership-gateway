//! The ownership gateway.
//!
//! It issues single-use challenges, exchanges WIP-103 ownership proofs for short-lived,
//! audience-scoped ES256 tokens, and serves the public keys that verify those tokens.

pub mod challenge;
pub mod config;
pub mod policy;
pub mod retry;
pub mod store;
mod telemetry;

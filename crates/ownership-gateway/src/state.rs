//! The state the public and admin routers share.

use std::{sync::Arc, time::Duration};

use axum::extract::FromRef;
use url::Url;

use crate::{exchange::Exchange, policy::Policies, store::ChallengeStore};

/// State shared by the public and admin routers.
#[derive(Clone)]
pub struct AppState {
    /// Challenge storage.
    pub store: Arc<dyn ChallengeStore>,
    /// The audience policy.
    pub policies: Arc<Policies>,
    /// The token exchange endpoint returned with every challenge.
    pub token_url: Url,
    /// The lifetime of issued challenges.
    pub challenge_ttl: Duration,
    /// The time each request may take.
    pub request_deadline: Duration,
    /// The token exchange.
    pub exchange: Arc<Exchange>,
    /// Whether challenges and tokens may be issued. When false, both endpoints answer 503.
    pub issuance_enabled: bool,
}

impl FromRef<AppState> for Arc<Policies> {
    fn from_ref(state: &AppState) -> Self {
        state.policies.clone()
    }
}

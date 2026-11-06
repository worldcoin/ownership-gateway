//! Metrics and log formatting shared by the gateway's dependency clients.

use std::{error::Error, fmt};

use tokio::time::Instant;

/// A remote dependency, as named in the `dep` metric tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dependency {
    Redis,
    Root,
    Kms,
}

impl Dependency {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Redis => "redis",
            Self::Root => "root",
            Self::Kms => "kms",
        }
    }
}

/// How a dependency call failed, as named in the `class` metric tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Timeout,
    Server,
    Connect,
    Throttled,
    Other,
}

impl FailureClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Server => "5xx",
            Self::Connect => "connect",
            Self::Throttled => "throttled",
            Self::Other => "other",
        }
    }
}

/// Records the duration of a call that started at `started` and, if it failed, its failure class.
pub(crate) fn record_call(
    dependency: Dependency,
    started: Instant,
    outcome: Result<(), FailureClass>,
) {
    metrics::histogram!("ownership_gateway.dependency.duration", "dep" => dependency.as_str())
        .record(started.elapsed().as_secs_f64());
    if let Err(class) = outcome {
        metrics::counter!(
            "ownership_gateway.dependency.errors",
            "dep" => dependency.as_str(),
            "class" => class.as_str()
        )
        .increment(1);
    }
}

/// Sets the `ready{component}` gauge for a dependency.
pub(crate) fn set_ready(component: Dependency, ready: bool) {
    metrics::gauge!("ownership_gateway.ready", "component" => component.as_str()).set(if ready {
        1.0
    } else {
        0.0
    });
}

/// Formats an error followed by its sources, separated by `: `.
pub(crate) struct ErrorChain<'a>(pub(crate) &'a (dyn Error + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(error) = source {
            write!(f, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}

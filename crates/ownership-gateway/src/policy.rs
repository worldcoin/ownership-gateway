//! The deploy-time audience policy and the proof context derived from an audience.

use std::{collections::HashSet, path::Path, str::FromStr, time::Duration};

use ownership_token::{Audience, MAX_TOKEN_LIFETIME};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use url::Url;
use world_id_primitives::FieldElement;

/// The domain tag that precedes the audience when deriving a proof context.
pub const CONTEXT_DOMAIN_TAG: &[u8] = b"world-id/ownership-gateway/context/v1\0";

/// Derives the proof context that binds an ownership proof to `audience`.
///
/// The context is SHA-256 of [`CONTEXT_DOMAIN_TAG`] followed by the UTF-8 audience, read as a
/// big-endian integer modulo the BN254 scalar field. The circuit rejects a zero context, so a
/// zero reduction becomes one. Clients and verifiers may derive the context independently, so
/// changing this construction breaks them. Challenges already issued keep the context they were
/// stored with.
#[must_use]
pub fn audience_context(audience: &Audience) -> FieldElement {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(CONTEXT_DOMAIN_TAG)
        .chain_update(audience.as_str().as_bytes())
        .finalize()
        .into();
    let context = FieldElement::from_digest(&digest);
    if context == FieldElement::ZERO {
        FieldElement::ONE
    } else {
        context
    }
}

/// A browser origin in canonical serialization, such as `https://app.example`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin(String);

/// A string that is not a canonical HTTP or HTTPS origin.
#[derive(Debug, thiserror::Error)]
#[error("allowed origins must be canonical HTTP(S) origins without a path")]
pub struct InvalidOrigin;

impl Origin {
    /// Returns the canonical origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Origin {
    type Err = InvalidOrigin;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(|_| InvalidOrigin)?;
        if !matches!(url.scheme(), "http" | "https") || url.origin().ascii_serialization() != value
        {
            return Err(InvalidOrigin);
        }
        Ok(Self(value.to_owned()))
    }
}

/// An allowlisted audience with its token lifetime and browser origins.
#[derive(Clone, Debug)]
pub struct AudiencePolicy {
    aud: Audience,
    enabled: bool,
    token_ttl: Duration,
    allowed_origins: Vec<Origin>,
}

impl AudiencePolicy {
    /// Returns the audience this policy applies to.
    #[must_use]
    pub fn aud(&self) -> &Audience {
        &self.aud
    }

    /// Returns the lifetime of tokens issued for the audience, between one second and
    /// [`MAX_TOKEN_LIFETIME`] in whole seconds.
    #[must_use]
    pub fn token_ttl(&self) -> Duration {
        self.token_ttl
    }

    /// Whether a browser on `origin` may request challenges and tokens for the audience.
    /// Origins compare exactly, so `origin` must be in canonical form.
    #[must_use]
    pub fn allows_origin(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|allowed| allowed.as_str() == origin)
    }
}

/// The audience policy file did not load.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The file could not be read.
    #[error("reading audience policy {path}")]
    Read {
        /// The configured path.
        path: String,
        /// The I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a JSON array of policy entries.
    #[error("audience policy is not a valid JSON array of policies")]
    Json(#[source] serde_json::Error),
    /// Two entries name the same audience.
    #[error("audience {0} appears more than once")]
    DuplicateAudience(Audience),
    /// An entry's token lifetime is out of range.
    #[error("audience {0}: token_ttl_secs must be between 1 and 3600")]
    TokenTtl(Audience),
    /// An entry lists an origin that is not canonical.
    #[error("audience {aud}: invalid allowed origin")]
    Origin {
        /// The audience of the entry.
        aud: Audience,
        /// The parse failure.
        #[source]
        source: InvalidOrigin,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEntry {
    aud: Audience,
    enabled: bool,
    token_ttl_secs: u64,
    allowed_origins: Vec<String>,
}

impl TryFrom<PolicyEntry> for AudiencePolicy {
    type Error = PolicyError;

    fn try_from(entry: PolicyEntry) -> Result<Self, Self::Error> {
        let token_ttl = Duration::from_secs(entry.token_ttl_secs);
        if token_ttl.is_zero() || token_ttl > MAX_TOKEN_LIFETIME {
            return Err(PolicyError::TokenTtl(entry.aud));
        }
        let allowed_origins = match entry
            .allowed_origins
            .iter()
            .map(|origin| origin.parse())
            .collect()
        {
            Ok(origins) => origins,
            Err(source) => {
                return Err(PolicyError::Origin {
                    aud: entry.aud,
                    source,
                });
            }
        };
        Ok(Self {
            aud: entry.aud,
            enabled: entry.enabled,
            token_ttl,
            allowed_origins,
        })
    }
}

/// The deploy-time audience policy: one entry per distinct audience.
#[derive(Clone, Debug)]
pub struct Policies(Vec<AudiencePolicy>);

impl Policies {
    /// Reads and parses the policy file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Read`] if the file cannot be read, or any error of
    /// [`Policies::parse`].
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let bytes = std::fs::read(path).map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&bytes)
    }

    /// Parses a JSON array of entries with `aud`, `enabled`, `token_ttl_secs` and
    /// `allowed_origins`.
    ///
    /// # Errors
    ///
    /// Returns an error naming the audience if an entry is invalid or repeats an audience.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let entries: Vec<PolicyEntry> = serde_json::from_slice(bytes).map_err(PolicyError::Json)?;
        let mut audiences = HashSet::new();
        let mut policies = Vec::with_capacity(entries.len());
        for entry in entries {
            if !audiences.insert(entry.aud.clone()) {
                return Err(PolicyError::DuplicateAudience(entry.aud));
            }
            policies.push(AudiencePolicy::try_from(entry)?);
        }
        Ok(Self(policies))
    }

    /// Returns the policy for `aud` if the audience is listed and enabled.
    #[must_use]
    pub fn enabled_policy(&self, aud: &Audience) -> Option<&AudiencePolicy> {
        self.0
            .iter()
            .find(|policy| policy.enabled && policy.aud == *aud)
    }

    /// Whether any enabled audience allows `origin`.
    #[must_use]
    pub fn allows_origin(&self, origin: &str) -> bool {
        self.0
            .iter()
            .any(|policy| policy.enabled && policy.allows_origin(origin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audience(value: &str) -> Audience {
        value.parse().unwrap()
    }

    #[test]
    fn audience_context_matches_its_documented_derivation() {
        assert_eq!(
            audience_context(&audience("service-a")).to_string(),
            "0x08b830163d29f8945b7d2f75135de924c58a54909bf837cfdf2c5c804341372e"
        );
        assert_ne!(
            audience_context(&audience("service-a")),
            audience_context(&audience("service-b"))
        );
    }

    #[test]
    fn parses_enabled_and_disabled_audiences() {
        let policies = Policies::parse(
            br#"[
                {"aud":"service-a","enabled":true,"token_ttl_secs":900,"allowed_origins":["https://app.example"]},
                {"aud":"service-b","enabled":false,"token_ttl_secs":600,"allowed_origins":["https://other.example"]}
            ]"#,
        )
        .unwrap();
        let policy = policies.enabled_policy(&audience("service-a")).unwrap();
        assert_eq!(policy.token_ttl(), Duration::from_mins(15));
        assert!(policy.allows_origin("https://app.example"));
        assert!(!policy.allows_origin("https://app.example/"));
        assert!(policies.enabled_policy(&audience("service-b")).is_none());
        assert!(policies.enabled_policy(&audience("missing")).is_none());
        assert!(policies.allows_origin("https://app.example"));
        assert!(!policies.allows_origin("https://other.example"));
    }

    #[test]
    fn rejects_invalid_entries_and_names_the_audience() {
        for (policy, message) in [
            (
                r#"[{"aud":"a","enabled":true,"token_ttl_secs":3601,"allowed_origins":[]}]"#,
                "audience a: token_ttl_secs must be between 1 and 3600",
            ),
            (
                r#"[{"aud":"a","enabled":true,"token_ttl_secs":0,"allowed_origins":[]}]"#,
                "audience a: token_ttl_secs must be between 1 and 3600",
            ),
            (
                r#"[{"aud":"a","enabled":true,"token_ttl_secs":10,"allowed_origins":["https://example.com/path"]}]"#,
                "audience a: invalid allowed origin",
            ),
            (
                r#"[{"aud":"a","enabled":true,"token_ttl_secs":10,"allowed_origins":["ftp://example.com"]}]"#,
                "audience a: invalid allowed origin",
            ),
            (
                r#"[{"aud":"a","enabled":true,"token_ttl_secs":10,"allowed_origins":[]},{"aud":"a","enabled":false,"token_ttl_secs":10,"allowed_origins":[]}]"#,
                "audience a appears more than once",
            ),
        ] {
            let error = Policies::parse(policy.as_bytes()).unwrap_err();
            assert_eq!(error.to_string(), message, "{policy}");
        }
    }

    #[test]
    fn rejects_malformed_entries() {
        for policy in [
            r#"[{"aud":"bad audience","enabled":true,"token_ttl_secs":10,"allowed_origins":[]}]"#,
            r#"[{"aud":"a","enabled":true,"token_ttl_secs":10,"allowed_origins":[],"extra":1}]"#,
            r#"[{"aud":"a","enabled":true,"allowed_origins":[]}]"#,
            r#"{"aud":"a"}"#,
        ] {
            assert!(
                matches!(
                    Policies::parse(policy.as_bytes()),
                    Err(PolicyError::Json(_))
                ),
                "{policy}"
            );
        }
    }

    #[test]
    fn loading_a_missing_file_names_the_path() {
        let error = Policies::load(Path::new("/nonexistent/policy.json")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "reading audience policy /nonexistent/policy.json"
        );
    }
}

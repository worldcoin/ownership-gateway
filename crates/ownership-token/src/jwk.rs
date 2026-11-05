use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{ecdsa::VerifyingKey, pkcs8::EncodePublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};

/// A P-256 public signing key in the ownership JWKS profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    kid: String,
    key: VerifyingKey,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct WireJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    kid: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
}

impl Jwk {
    /// Constructs a JWK with the key ID `base64url(SHA-256(SPKI DER))`, without padding.
    #[must_use]
    pub fn from_public_key(key: &VerifyingKey) -> Self {
        let der = key
            .to_public_key_der()
            .expect("P-256 public key always encodes as SPKI");
        Self {
            kid: URL_SAFE_NO_PAD.encode(Sha256::digest(der.as_bytes())),
            key: *key,
        }
    }

    /// Returns the key ID.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the verified P-256 public key.
    #[must_use]
    pub fn public_key(&self) -> &VerifyingKey {
        &self.key
    }

    fn wire(&self) -> WireJwk {
        let point = self.key.to_encoded_point(false);
        WireJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x")),
            y: URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y")),
            kid: self.kid.clone(),
            alg: "ES256".into(),
            key_use: "sig".into(),
        }
    }
}

impl Serialize for Jwk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireJwk::deserialize(deserializer)?;
        let x = URL_SAFE_NO_PAD.decode(&wire.x).map_err(de::Error::custom)?;
        let y = URL_SAFE_NO_PAD.decode(&wire.y).map_err(de::Error::custom)?;
        if x.len() != 32 || y.len() != 32 {
            return Err(de::Error::custom("invalid P-256 coordinates"));
        }
        let mut point = [0u8; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        let key = VerifyingKey::from_sec1_bytes(&point).map_err(de::Error::custom)?;
        let jwk = Self::from_public_key(&key);
        if jwk.wire() != wire {
            return Err(de::Error::custom("invalid ownership JWK profile or key ID"));
        }
        Ok(jwk)
    }
}

/// A set of public signing keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Creates a set of public keys.
    #[must_use]
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }
    /// Finds a key by its ID.
    #[must_use]
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|key| key.kid() == kid)
    }

    /// Returns the keys in the set.
    #[must_use]
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }
}

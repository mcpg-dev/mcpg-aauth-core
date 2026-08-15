// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! JSON Web Keys (Ed25519 / OKP only), JWKS documents, and RFC 7638 thumbprints.
//!
//! AAuth mandates Ed25519 support and recommends it everywhere; this
//! implementation is deliberately Ed25519-only to keep the dependency and
//! attack surface minimal. See `research/03-http-signatures.md`.
//!
//! Every JWK this module mints carries a fully-specified `alg`, and
//! [`Jwk::require_fully_specified_alg`] enforces the same on the verify path
//! where AAuth -10 §5.2.2 demands it (the `cnf` confirmation key).

pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64;

/// A public JWK. Only OKP/Ed25519 is supported; unknown members are ignored
/// on input and never emitted on output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// base64url public key (32 bytes for Ed25519)
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Jwk {
    /// Public JWK for an Ed25519 verifying key, with the fully-specified `alg`
    /// AAuth -10 requires on a published or confirmation key.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64::encode(vk.as_bytes()),
            kid: None,
            alg: Some(crate::jwt::ALG_ED25519.into()),
            use_: None,
        }
    }

    /// Parse into an Ed25519 verifying key. Fails on any non-Ed25519 key.
    ///
    /// Checks key parameters only. The `alg` rule is enforced separately by
    /// [`Jwk::require_fully_specified_alg`], which every verify path calls —
    /// signature-key-08 §3.3 requires rejecting a JWK with an absent or
    /// polymorphic `alg` and forbids inferring one from `kty`/`crv`, so the two
    /// checks must stay distinct rather than one standing in for the other.
    pub fn verifying_key(&self) -> Result<VerifyingKey, JwkError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(JwkError::UnsupportedKeyType);
        }
        let raw: [u8; 32] = b64::decode_fixed(&self.x).map_err(|_| JwkError::InvalidKey)?;
        VerifyingKey::from_bytes(&raw).map_err(|_| JwkError::InvalidKey)
    }

    /// AAuth -10 §5.2.2: a `cnf` JWK "MUST carry a fully-specified `alg`
    /// member". signature-key-08 §3.3 additionally bans the polymorphic
    /// `EdDSA` identifier.
    pub fn require_fully_specified_alg(&self) -> Result<(), JwkError> {
        match self.alg.as_deref() {
            Some(crate::jwt::ALG_ED25519) => Ok(()),
            None => Err(JwkError::MissingAlg),
            Some(crate::jwt::ALG_EDDSA_POLYMORPHIC) => Err(JwkError::PolymorphicAlg),
            Some(_) => Err(JwkError::UnsupportedAlg),
        }
    }

    /// RFC 7638 JWK thumbprint (SHA-256, base64url). For OKP keys the
    /// canonical form is `{"crv":...,"kty":...,"x":...}` — required members
    /// only, lexicographic order, no whitespace.
    pub fn thumbprint(&self) -> Result<String, JwkError> {
        if self.kty != "OKP" {
            return Err(JwkError::UnsupportedKeyType);
        }
        // crv and x are JSON strings under our control (validated base64url /
        // known curve names), but escape defensively via serde_json.
        let canonical = format!(
            "{{\"crv\":{},\"kty\":{},\"x\":{}}}",
            serde_json::to_string(&self.crv).unwrap(),
            serde_json::to_string(&self.kty).unwrap(),
            serde_json::to_string(&self.x).unwrap(),
        );
        Ok(b64::encode(&Sha256::digest(canonical.as_bytes())))
    }

    /// Copy with only the cryptographic members (for `cnf.jwk` embedding).
    /// `alg` is retained — AAuth -10 §5.2.2 requires the confirmation key to
    /// be fully specified — while `kid`/`use` are dropped.
    pub fn public_only(&self) -> Jwk {
        Jwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            kid: None,
            alg: self.alg.clone(),
            use_: None,
        }
    }
}

/// A JWKS document (`{"keys":[...]}`). Unknown/unsupported keys are retained
/// as raw values so a document containing e.g. RSA keys still parses; lookup
/// only matches supported keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<serde_json::Value>,
}

impl Jwks {
    /// Find a supported (Ed25519) key by `kid`.
    pub fn find(&self, kid: &str) -> Option<Jwk> {
        self.keys.iter().find_map(|v| {
            let k: Jwk = serde_json::from_value(v.clone()).ok()?;
            if k.kid.as_deref() == Some(kid) && k.kty == "OKP" && k.crv == "Ed25519" {
                Some(k)
            } else {
                None
            }
        })
    }
}

/// Generate a fresh Ed25519 signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    crate::rand_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkError {
    UnsupportedKeyType,
    InvalidKey,
    /// No `alg` member where a draft requires a fully-specified one.
    MissingAlg,
    /// `alg` is the polymorphic `EdDSA`, which AAuth -10 forbids.
    PolymorphicAlg,
    /// `alg` is fully specified but is not one this build implements.
    UnsupportedAlg,
}

impl std::fmt::Display for JwkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkError::UnsupportedKeyType => write!(f, "unsupported key type (Ed25519/OKP only)"),
            JwkError::InvalidKey => write!(f, "invalid key material"),
            JwkError::MissingAlg => write!(
                f,
                "JWK is missing the required `alg` member (AAuth requires a fully-specified \
                 algorithm, e.g. `{}`)",
                crate::jwt::ALG_ED25519
            ),
            JwkError::PolymorphicAlg => write!(
                f,
                "JWK `alg` is the polymorphic `{}`, which AAuth forbids; use the fully-specified \
                 `{}`",
                crate::jwt::ALG_EDDSA_POLYMORPHIC,
                crate::jwt::ALG_ED25519
            ),
            JwkError::UnsupportedAlg => write!(
                f,
                "JWK `alg` is not `{}` (the only algorithm this build implements)",
                crate::jwt::ALG_ED25519
            ),
        }
    }
}
impl std::error::Error for JwkError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A key and its published thumbprint.
    #[test]
    fn rfc8037_thumbprint() {
        let jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: None,
            alg: None,
            use_: None,
        };
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn thumbprint_ignores_optional_members() {
        let mut jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: Some("some-kid".into()),
            alg: Some("EdDSA".into()),
            use_: Some("sig".into()),
        };
        let t1 = jwk.thumbprint().unwrap();
        jwk.kid = None;
        assert_eq!(t1, jwk.thumbprint().unwrap());
    }

    #[test]
    fn roundtrip_key() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(jwk.verifying_key().unwrap(), sk.verifying_key());
    }

    /// Keys this crate mints are fully specified by construction, and the
    /// `cnf.jwk` projection keeps that (dropping only `kid`/`use`).
    #[test]
    fn minted_keys_are_fully_specified() {
        let sk = generate_signing_key();
        let mut jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(jwk.alg.as_deref(), Some("Ed25519"));
        jwk.require_fully_specified_alg().unwrap();

        jwk.kid = Some("k1".into());
        jwk.use_ = Some("sig".into());
        let cnf = jwk.public_only();
        assert_eq!(cnf.alg.as_deref(), Some("Ed25519"));
        assert!(cnf.kid.is_none() && cnf.use_.is_none());
        cnf.require_fully_specified_alg().unwrap();
    }

    /// AAuth -10 §5.2.2: the confirmation JWK MUST carry a fully-specified
    /// `alg`; absent and polymorphic are distinct, diagnosable failures.
    #[test]
    fn fully_specified_alg_rule() {
        let base = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let with_alg = |alg: Option<&str>| Jwk {
            alg: alg.map(|a| a.to_string()),
            ..base.clone()
        };
        with_alg(Some("Ed25519"))
            .require_fully_specified_alg()
            .unwrap();
        assert_eq!(
            with_alg(None).require_fully_specified_alg(),
            Err(JwkError::MissingAlg)
        );
        assert_eq!(
            with_alg(Some("EdDSA")).require_fully_specified_alg(),
            Err(JwkError::PolymorphicAlg)
        );
        for alg in ["Ed448", "HS256", "RS256", "none"] {
            assert_eq!(
                with_alg(Some(alg)).require_fully_specified_alg(),
                Err(JwkError::UnsupportedAlg),
                "{alg} must be refused"
            );
        }
    }

    /// signature-key-08 §3.3 governs any JWK a verifier selects an algorithm
    /// for, including a key from an Agent Provider's published JWKS — not only
    /// the `cnf` JWK. Discovery still parses such a key, because
    /// `verifying_key` inspects key parameters only; the `alg` rule is a
    /// separate gate, and §3.3 forbids letting `kty`/`crv` stand in for it.
    #[test]
    fn published_jwks_key_without_alg_is_rejected() {
        let jwks: Jwks = serde_json::from_str(
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}"#,
        )
        .unwrap();
        let key = jwks.find("k1").expect("discovery parses the key");
        assert!(
            key.verifying_key().is_ok(),
            "key parameters are valid on their own"
        );
        assert!(matches!(
            key.require_fully_specified_alg(),
            Err(JwkError::MissingAlg)
        ));
    }

    #[test]
    fn jwks_find_skips_unsupported() {
        let jwks: Jwks = serde_json::from_str(
            r#"{"keys":[
                {"kty":"RSA","n":"abc","e":"AQAB","kid":"k1"},
                {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}
            ]}"#,
        )
        .unwrap();
        assert!(jwks.find("k1").is_some());
        assert!(jwks.find("nope").is_none());
    }
}

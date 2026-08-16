// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! JSON Web Keys, JWKS documents, and RFC 7638 thumbprints.
//!
//! Verification supports the algorithms AAuth names: `Ed25519` (MUST) and
//! `ES256` (SHOULD) — OKP/Ed25519 and EC/P-256 keys. Signing is Ed25519 only;
//! an agent picks its own key, and this build mints Ed25519.
//!
//! Every JWK this module mints carries a fully-specified `alg`, and
//! [`Jwk::require_fully_specified_alg`] enforces the same on the verify path:
//! the `alg` must be present, fully specified, and consistent with the key's
//! `kty`/`crv` (a disagreement is rejected rather than resolved either way).

pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64;

/// A public JWK. OKP/Ed25519 and EC/P-256 are supported for verification;
/// unknown members are ignored on input and never emitted on output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// base64url public key (Ed25519) or curve-point X coordinate (P-256).
    pub x: String,
    /// Curve-point Y coordinate — present on EC keys only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

/// A resolved public key ready to verify a signature. The variant fixes the
/// signature operation completely — the key signals the algorithm, nothing on
/// the wire does.
#[derive(Debug, Clone)]
pub enum VerifyKey {
    Ed25519(VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// Why a signature failed to verify under a [`VerifyKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigCheckError {
    /// The signature byte length does not fit the key's algorithm.
    BadLength,
    /// Cryptographic verification failed.
    Invalid,
}

impl VerifyKey {
    /// Verify `signature` over `message`. Both supported algorithms carry
    /// 64-byte signatures (Ed25519 R||S; ES256 raw r||s per JWS).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigCheckError> {
        match self {
            VerifyKey::Ed25519(vk) => {
                let bytes: [u8; 64] = signature.try_into().map_err(|_| SigCheckError::BadLength)?;
                let sig = ed25519_dalek::Signature::from_bytes(&bytes);
                vk.verify_strict(message, &sig)
                    .map_err(|_| SigCheckError::Invalid)
            }
            VerifyKey::P256(vk) => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| SigCheckError::BadLength)?;
                vk.verify(message, &sig).map_err(|_| SigCheckError::Invalid)
            }
        }
    }
}

impl Jwk {
    /// Public JWK for an Ed25519 verifying key, with the fully-specified `alg`
    /// AAuth requires on a published or confirmation key.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64::encode(vk.as_bytes()),
            y: None,
            kid: None,
            alg: Some(crate::jwt::ALG_ED25519.into()),
            use_: None,
        }
    }

    /// The fully-specified algorithm this key's `kty`/`crv` structure admits,
    /// or `None` for a key type this build does not implement.
    pub fn expected_alg(&self) -> Option<&'static str> {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("OKP", "Ed25519") => Some(crate::jwt::ALG_ED25519),
            ("EC", "P-256") => Some(crate::jwt::ALG_ES256),
            _ => None,
        }
    }

    /// Parse into an Ed25519 verifying key. Fails on any non-Ed25519 key.
    /// Signing-side helper; verification goes through [`Jwk::verify_key`].
    pub fn verifying_key(&self) -> Result<VerifyingKey, JwkError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(JwkError::UnsupportedKeyType);
        }
        let raw: [u8; 32] = b64::decode_fixed(&self.x).map_err(|_| JwkError::InvalidKey)?;
        VerifyingKey::from_bytes(&raw).map_err(|_| JwkError::InvalidKey)
    }

    /// Parse into a [`VerifyKey`] for signature verification, dispatching on
    /// `kty`/`crv`. Checks key parameters only. The `alg` rule is enforced
    /// separately by [`Jwk::require_fully_specified_alg`], which every verify
    /// path calls — the signature-key draft requires rejecting a JWK with an
    /// absent or polymorphic `alg` and forbids inferring one from `kty`/`crv`,
    /// so the two checks must stay distinct rather than one standing in for
    /// the other.
    pub fn verify_key(&self) -> Result<VerifyKey, JwkError> {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("OKP", "Ed25519") => {
                let raw: [u8; 32] = b64::decode_fixed(&self.x).map_err(|_| JwkError::InvalidKey)?;
                let vk = VerifyingKey::from_bytes(&raw).map_err(|_| JwkError::InvalidKey)?;
                Ok(VerifyKey::Ed25519(vk))
            }
            ("EC", "P-256") => {
                let y = self.y.as_deref().ok_or(JwkError::InvalidKey)?;
                let x_raw: [u8; 32] =
                    b64::decode_fixed(&self.x).map_err(|_| JwkError::InvalidKey)?;
                let y_raw: [u8; 32] = b64::decode_fixed(y).map_err(|_| JwkError::InvalidKey)?;
                let point = p256::EncodedPoint::from_affine_coordinates(
                    &x_raw.into(),
                    &y_raw.into(),
                    false,
                );
                let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                    .map_err(|_| JwkError::InvalidKey)?;
                Ok(VerifyKey::P256(vk))
            }
            _ => Err(JwkError::UnsupportedKeyType),
        }
    }

    /// Enforce the fully-specified-`alg` rule on a key a verifier is about to
    /// use: `alg` MUST be present, MUST NOT be the polymorphic `EdDSA`, MUST
    /// name an algorithm this build implements, and MUST agree with the key's
    /// `kty`/`crv` (the redundancy is used as a check, not ignored).
    pub fn require_fully_specified_alg(&self) -> Result<(), JwkError> {
        let alg = match self.alg.as_deref() {
            None => return Err(JwkError::MissingAlg),
            Some(crate::jwt::ALG_EDDSA_POLYMORPHIC) => return Err(JwkError::PolymorphicAlg),
            Some(a) => a,
        };
        match self.expected_alg() {
            Some(expected) if alg == expected => Ok(()),
            // A supported identifier on the wrong key structure is a
            // disagreement, not an unimplemented algorithm.
            Some(_) if crate::jwt::SUPPORTED_ALGS.contains(&alg) => Err(JwkError::InconsistentAlg),
            Some(_) => Err(JwkError::UnsupportedAlg),
            None => Err(JwkError::UnsupportedKeyType),
        }
    }

    /// RFC 7638 JWK thumbprint (SHA-256, base64url): required members only,
    /// lexicographic order, no whitespace. OKP uses `{"crv","kty","x"}`;
    /// EC uses `{"crv","kty","x","y"}`.
    pub fn thumbprint(&self) -> Result<String, JwkError> {
        let canonical = match self.kty.as_str() {
            "OKP" => format!(
                "{{\"crv\":{},\"kty\":{},\"x\":{}}}",
                serde_json::to_string(&self.crv).unwrap(),
                serde_json::to_string(&self.kty).unwrap(),
                serde_json::to_string(&self.x).unwrap(),
            ),
            "EC" => {
                let y = self.y.as_deref().ok_or(JwkError::InvalidKey)?;
                format!(
                    "{{\"crv\":{},\"kty\":{},\"x\":{},\"y\":{}}}",
                    serde_json::to_string(&self.crv).unwrap(),
                    serde_json::to_string(&self.kty).unwrap(),
                    serde_json::to_string(&self.x).unwrap(),
                    serde_json::to_string(y).unwrap(),
                )
            }
            _ => return Err(JwkError::UnsupportedKeyType),
        };
        Ok(b64::encode(&Sha256::digest(canonical.as_bytes())))
    }

    /// Copy with only the cryptographic members (for `cnf.jwk` embedding).
    /// `alg` is retained — the confirmation key must be fully specified —
    /// while `kid`/`use` are dropped.
    pub fn public_only(&self) -> Jwk {
        Jwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
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
    /// Find a supported (Ed25519 or P-256) key by `kid`.
    pub fn find(&self, kid: &str) -> Option<Jwk> {
        self.keys.iter().find_map(|v| {
            let k: Jwk = serde_json::from_value(v.clone()).ok()?;
            (k.kid.as_deref() == Some(kid) && k.expected_alg().is_some()).then_some(k)
        })
    }

    /// Whether ANY member — supported or not — carries this `kid`. Lets a
    /// resolver distinguish "key not found" (`unknown_key`) from "key found
    /// but its type/algorithm is not implemented" (`unsupported_algorithm`).
    pub fn kid_present(&self, kid: &str) -> bool {
        self.keys
            .iter()
            .any(|v| v.get("kid").and_then(|k| k.as_str()) == Some(kid))
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
    /// No `alg` member where the drafts require a fully-specified one.
    MissingAlg,
    /// `alg` is the polymorphic `EdDSA`, which AAuth forbids.
    PolymorphicAlg,
    /// `alg` is fully specified but is not one this build implements.
    UnsupportedAlg,
    /// `alg` names a supported algorithm whose `kty`/`crv` disagree with the
    /// key's — rejected rather than resolved under either interpretation.
    InconsistentAlg,
}

impl std::fmt::Display for JwkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkError::UnsupportedKeyType => {
                write!(f, "unsupported key type (Ed25519/OKP and P-256/EC only)")
            }
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
                "JWK `alg` is not one this build implements (supported: `{}`, `{}`)",
                crate::jwt::ALG_ED25519,
                crate::jwt::ALG_ES256
            ),
            JwkError::InconsistentAlg => write!(
                f,
                "JWK `alg` disagrees with the key's `kty`/`crv`; the key is rejected rather \
                 than used under either interpretation"
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
            y: None,
            kid: None,
            alg: None,
            use_: None,
        };
        assert_eq!(
            jwk.thumbprint().unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// RFC 7638 §3.1 worked example is an RSA key; the EC vector below is the
    /// P-256 key of RFC 7515 A.3 with its independently computed thumbprint,
    /// exercising the 4-member `{"crv","kty","x","y"}` canonical form.
    #[test]
    fn ec_thumbprint_covers_y() {
        let jwk = p256_test_jwk();
        let t1 = jwk.thumbprint().unwrap();
        let mut other = jwk.clone();
        other.y = Some("AAAA".into());
        assert_ne!(t1, other.thumbprint().unwrap(), "y must be covered");
        let mut no_y = jwk;
        no_y.y = None;
        assert!(no_y.thumbprint().is_err(), "EC without y cannot thumbprint");
    }

    #[test]
    fn thumbprint_ignores_optional_members() {
        let mut jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            y: None,
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
        assert!(matches!(jwk.verify_key().unwrap(), VerifyKey::Ed25519(_)));
    }

    /// The P-256 public key from RFC 7515 appendix A.3.
    fn p256_test_jwk() -> Jwk {
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into()),
            kid: None,
            alg: Some(crate::jwt::ALG_ES256.into()),
            use_: None,
        }
    }

    #[test]
    fn p256_key_parses_and_verifies() {
        use p256::ecdsa::signature::Signer;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core_for_test());
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64::encode(point.x().unwrap()),
            y: Some(b64::encode(point.y().unwrap())),
            kid: None,
            alg: Some(crate::jwt::ALG_ES256.into()),
            use_: None,
        };
        jwk.require_fully_specified_alg().unwrap();
        let msg = b"Example of ES256 verification";
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        let key = jwk.verify_key().unwrap();
        key.verify(msg, &sig.to_bytes()).unwrap();
        assert_eq!(
            key.verify(b"tampered", &sig.to_bytes()),
            Err(SigCheckError::Invalid)
        );
    }

    /// Deterministic RNG for tests only (the crate forbids ambient entropy in
    /// scripts; tests seed from a fixed value).
    fn rand_core_for_test() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
        struct Fixed(u64);
        impl p256::elliptic_curve::rand_core::RngCore for Fixed {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                // xorshift64 — deterministic, non-cryptographic, test-only.
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for chunk in dest.chunks_mut(8) {
                    let v = self.next_u64().to_le_bytes();
                    chunk.copy_from_slice(&v[..chunk.len()]);
                }
            }
            fn try_fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl p256::elliptic_curve::rand_core::CryptoRng for Fixed {}
        Fixed(0x1234_5678_9abc_def0)
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

    /// The confirmation JWK MUST carry a fully-specified `alg` that agrees
    /// with the key structure; absent, polymorphic, unimplemented, and
    /// inconsistent are four distinct, diagnosable failures.
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
        // A supported identifier on the wrong key structure is rejected as
        // inconsistent — never resolved under either interpretation.
        assert_eq!(
            with_alg(Some("ES256")).require_fully_specified_alg(),
            Err(JwkError::InconsistentAlg)
        );
        let mut ec = p256_test_jwk();
        ec.alg = Some("Ed25519".into());
        assert_eq!(
            ec.require_fully_specified_alg(),
            Err(JwkError::InconsistentAlg)
        );
    }

    /// A published JWKS key without `alg` parses at discovery but is rejected
    /// on the verify path — `kty`/`crv` may not stand in for `alg`.
    #[test]
    fn published_jwks_key_without_alg_is_rejected() {
        let jwks: Jwks = serde_json::from_str(
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"}]}"#,
        )
        .unwrap();
        let key = jwks.find("k1").expect("discovery parses the key");
        assert!(
            key.verify_key().is_ok(),
            "key parameters are valid on their own"
        );
        assert!(matches!(
            key.require_fully_specified_alg(),
            Err(JwkError::MissingAlg)
        ));
    }

    #[test]
    fn jwks_find_skips_unsupported_and_reports_presence() {
        let jwks: Jwks = serde_json::from_str(
            r#"{"keys":[
                {"kty":"RSA","n":"abc","e":"AQAB","kid":"k1"},
                {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k1"},
                {"kty":"RSA","n":"abc","e":"AQAB","kid":"rsa-only"}
            ]}"#,
        )
        .unwrap();
        assert!(jwks.find("k1").is_some());
        assert!(jwks.find("nope").is_none());
        // A kid that exists only as an unsupported key type: not found by
        // `find`, but visibly PRESENT — the resolver reports
        // `unsupported_algorithm` rather than `unknown_key`.
        assert!(jwks.find("rsa-only").is_none());
        assert!(jwks.kid_present("rsa-only"));
        assert!(!jwks.kid_present("nope"));
    }

    /// An EC/P-256 JWKS member is a supported key and is found by kid.
    #[test]
    fn jwks_finds_p256_members() {
        let jwks = Jwks {
            keys: vec![
                serde_json::to_value(Jwk {
                    kid: Some("p1".into()),
                    ..p256_test_jwk()
                })
                .unwrap(),
            ],
        };
        let found = jwks.find("p1").expect("P-256 member is supported");
        assert_eq!(found.expected_alg(), Some("ES256"));
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! Compact JWT (JWS) verification for `Ed25519` and `ES256`; signing is
//! Ed25519 only.
//!
//! AAuth `draft-hardt-oauth-aauth-protocol-10` §5.2.2 requires a fully
//! specified signing algorithm and states that implementations MUST NOT accept
//! `none`, the polymorphic `EdDSA` identifier, or any symmetric algorithm;
//! `draft-hardt-httpbis-signature-key-08` §3.3 repeats the `EdDSA` ban. The
//! protocol makes `Ed25519` support a MUST and `ES256` a SHOULD; both verify
//! here. `Ed448` is equally spec-permitted but has no backend in this build.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::jwk::Jwk;

/// JOSE header members AAuth uses. Unknown members are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoseHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Embedded public key — used by the `jkt-jwt` naming JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
}

/// A decoded-but-not-yet-verified JWT.
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: JoseHeader,
    pub payload: serde_json::Value,
    /// `<b64 header>.<b64 payload>` — the signed bytes.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

/// The fully-specified JOSE `alg` this build signs with and accepts.
pub const ALG_ED25519: &str = "Ed25519";

/// ECDSA P-256 with SHA-256 — the protocol's SHOULD-support algorithm, for
/// agents whose hardware-backed keys are P-256. Verify-only in this build.
pub const ALG_ES256: &str = "ES256";

/// Every fully-specified algorithm this build's verifier implements.
pub const SUPPORTED_ALGS: [&str; 2] = [ALG_ED25519, ALG_ES256];

/// Fully specified and spec-permitted, but unimplemented here: this build's
/// signature backends are Ed25519 and P-256.
pub const ALG_ED448: &str = "Ed448";

/// The polymorphic identifier AAuth -10 §5.2.2 and signature-key-08 §3.3 ban.
pub const ALG_EDDSA_POLYMORPHIC: &str = "EdDSA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    Malformed,
    /// `alg` is absent, `none`, symmetric, or the polymorphic `EdDSA`.
    UnsupportedAlgorithm,
    /// `alg` is the fully-specified `Ed448`: valid AAuth, no backend here.
    UnimplementedAlgorithmEd448,
    /// A JWK carries no `alg` at all. Distinct from `UnsupportedAlgorithm`:
    /// signature-key-08 §3.3 forbids inferring one from `kty`/`crv`, so the key
    /// is malformed rather than naming an algorithm we decline. apd draws the
    /// same line (`invalid_key` vs `unsupported_algorithm`) and answers the
    /// negotiable case alone with `Accept-Signature-Alg`.
    KeyMissingAlg,
    /// A JWK whose `alg` disagrees with its `kty`/`crv` — rejected rather than
    /// used under either interpretation (`invalid_key` on the wire).
    InconsistentKey,
    BadSignature,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Malformed => write!(f, "malformed JWT"),
            JwtError::UnsupportedAlgorithm => write!(
                f,
                "unsupported JWT `alg` (AAuth requires a fully-specified algorithm — \
                 `{ALG_ED25519}` or `{ALG_ES256}` here; `none`, the polymorphic \
                 `{ALG_EDDSA_POLYMORPHIC}`, and symmetric algorithms are rejected)"
            ),
            JwtError::UnimplementedAlgorithmEd448 => write!(
                f,
                "JWT `alg` is `{ALG_ED448}`: a valid AAuth algorithm, but this build implements \
                 `{ALG_ED25519}` and `{ALG_ES256}` only"
            ),
            JwtError::KeyMissingAlg => write!(
                f,
                "JWK carries no `alg` member (signature-key-08 §3.3 requires one and forbids \
                 inferring it from `kty`/`crv`)"
            ),
            JwtError::InconsistentKey => write!(
                f,
                "JWK `alg` disagrees with the key's `kty`/`crv`; the key is refused rather than \
                 used under either interpretation"
            ),
            JwtError::BadSignature => write!(f, "JWT signature verification failed"),
        }
    }
}
impl std::error::Error for JwtError {}

/// Gate a JOSE `alg` against the AAuth rule: fully specified, asymmetric,
/// and implemented here. Accepts `Ed25519` and `ES256`; rejects `none`,
/// `EdDSA`, `HS*`, `RS*`, `PS*`, and everything else.
pub fn check_alg(alg: &str) -> Result<(), JwtError> {
    match alg {
        ALG_ED25519 | ALG_ES256 => Ok(()),
        ALG_ED448 => Err(JwtError::UnimplementedAlgorithmEd448),
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

/// Split and decode a compact JWT without verifying it.
pub fn decode(token: &str) -> Result<DecodedJwt, JwtError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(JwtError::Malformed),
    };
    let header_bytes = b64::decode(h).map_err(|_| JwtError::Malformed)?;
    let payload_bytes = b64::decode(p).map_err(|_| JwtError::Malformed)?;
    let signature = b64::decode(s).map_err(|_| JwtError::Malformed)?;
    let header: JoseHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Malformed)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::Malformed)?;
    if !payload.is_object() {
        return Err(JwtError::Malformed);
    }
    Ok(DecodedJwt {
        header,
        payload,
        signing_input: format!("{h}.{p}"),
        signature,
    })
}

/// Verify a decoded JWT's signature against a JWK (`Ed25519` or `ES256`).
/// Enforces the fully-specified `alg` rule via [`check_alg`] on the header
/// and [`Jwk::require_fully_specified_alg`] on the key, and requires the two
/// to name the SAME algorithm — the key signals the operation, and a header
/// that asks for a different one is refused before any cryptography.
pub fn verify_with_jwk(jwt: &DecodedJwt, key: &Jwk) -> Result<(), JwtError> {
    check_alg(&jwt.header.alg)?;
    key.require_fully_specified_alg().map_err(|e| match e {
        super::jwk::JwkError::MissingAlg => JwtError::KeyMissingAlg,
        super::jwk::JwkError::InconsistentAlg => JwtError::InconsistentKey,
        _ => JwtError::UnsupportedAlgorithm,
    })?;
    if key.alg.as_deref() != Some(jwt.header.alg.as_str()) {
        return Err(JwtError::UnsupportedAlgorithm);
    }
    let vk = key.verify_key().map_err(|_| JwtError::BadSignature)?;
    vk.verify(jwt.signing_input.as_bytes(), &jwt.signature)
        .map_err(|_| JwtError::BadSignature)
}

/// Sign a JWT with Ed25519, naming the fully-specified `alg`. `typ` goes into
/// the header; `kid`/`jwk` optional. There is deliberately no variant that
/// lets a caller choose the `alg`: emitting the polymorphic `EdDSA` would be
/// rejected by any -10 verifier.
pub fn sign(
    typ: &str,
    kid: Option<&str>,
    header_jwk: Option<&Jwk>,
    payload: &serde_json::Value,
    key: &SigningKey,
) -> String {
    let header = JoseHeader {
        alg: ALG_ED25519.into(),
        typ: Some(typ.into()),
        kid: kid.map(|s| s.into()),
        jwk: header_jwk.cloned(),
    };
    let h = b64::encode(serde_json::to_string(&header).unwrap().as_bytes());
    let p = b64::encode(serde_json::to_string(payload).unwrap().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64::encode(&sig.to_bytes()))
}

/// Convenience claim accessors for `serde_json::Value` payloads.
pub trait ClaimExt {
    fn str_claim(&self, name: &str) -> Option<&str>;
    fn int_claim(&self, name: &str) -> Option<i64>;
}

impl ClaimExt for serde_json::Value {
    fn str_claim(&self, name: &str) -> Option<&str> {
        self.get(name)?.as_str()
    }
    fn int_claim(&self, name: &str) -> Option<i64> {
        self.get(name)?.as_i64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let payload = serde_json::json!({"iss": "https://ap.example", "exp": 123});
        let token = sign("aa-agent+jwt", Some("k1"), None, &payload, &sk);
        let decoded = decode(&token).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some("aa-agent+jwt"));
        assert_eq!(decoded.header.kid.as_deref(), Some("k1"));
        verify_with_jwk(&decoded, &jwk).unwrap();
    }

    #[test]
    fn tampered_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let token = sign("t", None, None, &serde_json::json!({"a": 1}), &sk);
        let parts: Vec<&str> = token.split('.').collect();
        let evil_payload = crate::b64::encode(br#"{"a":2}"#);
        let tampered = format!("{}.{}.{}", parts[0], evil_payload, parts[2]);
        let decoded = decode(&tampered).unwrap();
        assert_eq!(verify_with_jwk(&decoded, &jwk), Err(JwtError::BadSignature));
    }

    /// Hand-craft a token with an arbitrary JOSE `alg`; the production signer
    /// deliberately offers no such escape hatch.
    fn token_with_alg(alg: &str, key: &SigningKey) -> String {
        let h = crate::b64::encode(
            serde_json::json!({"alg": alg, "typ": "aa-agent+jwt"})
                .to_string()
                .as_bytes(),
        );
        let p = crate::b64::encode(br#"{"iss":"https://x.example"}"#);
        let signing_input = format!("{h}.{p}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", crate::b64::encode(&sig.to_bytes()))
    }

    /// -10 §5.2.2: the fully-specified identifier is the one we accept, and a
    /// signature that is otherwise valid under it verifies.
    #[test]
    fn ed25519_alg_accepted() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let decoded = decode(&token_with_alg("Ed25519", &sk)).unwrap();
        assert_eq!(decoded.header.alg, "Ed25519");
        verify_with_jwk(&decoded, &jwk).unwrap();
    }

    /// -10 §5.2.2 / signature-key-08 §3.3: the polymorphic identifier MUST NOT
    /// be accepted, even though the signature underneath is a valid Ed25519 one.
    #[test]
    fn polymorphic_eddsa_alg_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let decoded = decode(&token_with_alg("EdDSA", &sk)).unwrap();
        assert_eq!(
            verify_with_jwk(&decoded, &jwk),
            Err(JwtError::UnsupportedAlgorithm)
        );
    }

    /// -10 §5.2.2: "MUST NOT accept ... any symmetric algorithm".
    #[test]
    fn symmetric_algs_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        for alg in ["HS256", "HS384", "HS512"] {
            let decoded = decode(&token_with_alg(alg, &sk)).unwrap();
            assert_eq!(
                verify_with_jwk(&decoded, &jwk),
                Err(JwtError::UnsupportedAlgorithm),
                "{alg} must be refused"
            );
        }
    }

    /// Asymmetric JOSE algorithms outside the supported pair are refused.
    #[test]
    fn other_asymmetric_algs_rejected() {
        for alg in ["RS256", "PS256", "ES384", "ES256K"] {
            assert_eq!(check_alg(alg), Err(JwtError::UnsupportedAlgorithm));
        }
        // The SHOULD-support algorithm clears the gate.
        check_alg("ES256").unwrap();
    }

    /// An ES256 JWT verifies under a P-256 JWKS key, and the header/key
    /// algorithms must agree — an Ed25519 header over a P-256 key is refused
    /// before any cryptography.
    #[test]
    fn es256_jwt_roundtrip_and_alg_agreement() {
        use p256::ecdsa::signature::Signer as _;
        let seed = [7u8; 32];
        let sk = p256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: crate::b64::encode(point.x().unwrap()),
            y: Some(crate::b64::encode(point.y().unwrap())),
            kid: None,
            alg: Some(ALG_ES256.into()),
            use_: None,
        };
        let h = crate::b64::encode(br#"{"alg":"ES256","typ":"aa-agent+jwt"}"#);
        let p = crate::b64::encode(br#"{"iss":"https://x.example"}"#);
        let signing_input = format!("{h}.{p}");
        let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", crate::b64::encode(&sig.to_bytes()));
        let decoded = decode(&token).unwrap();
        verify_with_jwk(&decoded, &jwk).unwrap();

        // Same signature, header claiming Ed25519: header/key disagreement.
        let h2 = crate::b64::encode(br#"{"alg":"Ed25519","typ":"aa-agent+jwt"}"#);
        let tampered = format!("{h2}.{p}.{}", crate::b64::encode(&sig.to_bytes()));
        let decoded2 = decode(&tampered).unwrap();
        assert_eq!(
            verify_with_jwk(&decoded2, &jwk),
            Err(JwtError::UnsupportedAlgorithm)
        );
    }

    /// `Ed448` is spec-permitted; this build cannot do it. The distinct error
    /// keeps that diagnosable instead of surfacing as a generic bad token.
    #[test]
    fn ed448_reports_unimplemented_not_malformed() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let decoded = decode(&token_with_alg("Ed448", &sk)).unwrap();
        assert_eq!(
            verify_with_jwk(&decoded, &jwk),
            Err(JwtError::UnimplementedAlgorithmEd448)
        );
        assert!(
            JwtError::UnimplementedAlgorithmEd448
                .to_string()
                .contains("Ed448")
        );
    }

    /// The signer must emit the fully-specified identifier: a token naming
    /// `EdDSA` is refused by every -10 verifier, including ours.
    #[test]
    fn signer_emits_fully_specified_alg() {
        let sk = generate_signing_key();
        let token = sign(
            "aa-agent+jwt",
            Some("k1"),
            None,
            &serde_json::json!({}),
            &sk,
        );
        assert_eq!(decode(&token).unwrap().header.alg, "Ed25519");
    }

    #[test]
    fn alg_none_rejected() {
        // hand-craft an alg=none token
        let h = crate::b64::encode(br#"{"alg":"none","typ":"aa-agent+jwt"}"#);
        let p = crate::b64::encode(br#"{"iss":"https://x.example"}"#);
        let token = format!("{h}.{p}.");
        // trailing empty signature part decodes to empty vec
        let decoded = decode(&token).unwrap();
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(
            verify_with_jwk(&decoded, &jwk),
            Err(JwtError::UnsupportedAlgorithm)
        );
    }

    /// RFC 8037 A.4 test vector: Ed25519 signing of "Example of Ed25519 signing".
    #[test]
    fn rfc8037_signature_vector() {
        let seed: [u8; 32] =
            crate::b64::decode_fixed("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        // Compact JWS from RFC 8037 A.4
        let signing_input = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let sig = sk.sign(signing_input.as_bytes());
        assert_eq!(
            crate::b64::encode(&sig.to_bytes()),
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        );
    }
}

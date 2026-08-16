// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! `Signature-Key` header schemes (`draft-hardt-httpbis-signature-key`):
//! parsing on the verifier side, serializing on the signer side, and the
//! `jkt-jwt` naming-JWT verification procedure.

use crate::jwk::Jwk;
use crate::jwt::{self, ClaimExt};
use crate::sfv::{self, BareItem, MemberValue, Params};
use crate::sig::{SigError, SigErrorCode};

/// A parsed `Signature-Key` dictionary member.
#[derive(Debug, Clone, PartialEq)]
pub enum SigKeyScheme {
    /// Inline public key (pseudonymous).
    Hwk(Jwk),
    /// Compact JWT carrying `cnf.jwk` (identity) — agent/auth/subscribe/event tokens.
    Jwt(String),
    /// Self-issued key delegation JWT (two-key refresh ceremony).
    JktJwt(String),
    /// Identified signer with JWKS discovery (used by PSes calling ASes).
    JwksUri {
        id: String,
        dwk: String,
        kid: String,
    },
    /// Registered but unsupported here (e.g. `x509`) or future schemes.
    Other(String),
}

fn str_param(params: &Params, key: &str) -> Result<String, SigError> {
    sfv::param(params, key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidKey,
                format!("missing or invalid '{key}' parameter"),
            )
        })
}

/// Parse one Signature-Key member value into a scheme.
pub fn parse_member(value: &MemberValue) -> Result<SigKeyScheme, SigError> {
    let (scheme_token, params) = match value {
        MemberValue::Item(BareItem::Token(t), params) => (t.as_str(), params),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                "Signature-Key member is not a token",
            ));
        }
    };
    match scheme_token {
        "hwk" => {
            let kty = str_param(params, "kty")?;
            // signature-key-08 §3.4: "The alg parameter MUST be present and
            // fully specified." (Earlier drafts forbade it outright.)
            let alg = sfv::param(params, "alg")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SigError::new(
                        SigErrorCode::InvalidKey,
                        "hwk is missing the required `alg` parameter",
                    )
                })?
                .to_string();
            jwt::check_alg(&alg).map_err(|e| {
                SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    format!("hwk `alg`: {e}"),
                )
            })?;
            let crv = str_param(params, "crv")?;
            let x = str_param(params, "x")?;
            let y = match kty.as_str() {
                // Ed25519 public keys have no Y coordinate.
                "OKP" => None,
                // EC keys carry both affine coordinates.
                "EC" => Some(str_param(params, "y")?),
                _ => {
                    return Err(SigError::new(
                        SigErrorCode::UnsupportedAlgorithm,
                        "unsupported hwk key type (OKP/Ed25519 and EC/P-256 only)",
                    ));
                }
            };
            let jwk = Jwk {
                kty,
                crv,
                x,
                y,
                kid: None,
                alg: Some(alg),
                use_: None,
            };
            // alg/kty/crv agreement (and curve support) in one gate.
            jwk.require_fully_specified_alg().map_err(|e| {
                SigError::new(SigErrorCode::UnsupportedAlgorithm, format!("hwk key: {e}"))
            })?;
            Ok(SigKeyScheme::Hwk(jwk))
        }
        "jwt" => Ok(SigKeyScheme::Jwt(str_param(params, "jwt")?)),
        "jkt-jwt" => Ok(SigKeyScheme::JktJwt(str_param(params, "jwt")?)),
        "jwks_uri" => Ok(SigKeyScheme::JwksUri {
            id: str_param(params, "id")?,
            dwk: str_param(params, "dwk")?,
            kid: str_param(params, "kid")?,
        }),
        other => Ok(SigKeyScheme::Other(other.to_string())),
    }
}

/// Serialize an `hwk` member value (Ed25519). `alg` is REQUIRED by
/// signature-key-08 §3.4; keys minted here always carry it, and a key parsed
/// from elsewhere without one falls back to the algorithm this build signs
/// with rather than emitting a non-compliant member.
pub fn serialize_hwk(jwk: &Jwk) -> String {
    format!(
        "hwk;kty={};crv={};alg={};x={}",
        sfv::serialize_string(&jwk.kty),
        sfv::serialize_string(&jwk.crv),
        sfv::serialize_string(jwk.alg.as_deref().unwrap_or(jwt::ALG_ED25519)),
        sfv::serialize_string(&jwk.x)
    )
}

/// Serialize a `jwt` member value.
pub fn serialize_jwt(token: &str) -> String {
    format!("jwt;jwt={}", sfv::serialize_string(token))
}

/// Serialize a `jkt-jwt` member value.
pub fn serialize_jkt_jwt(token: &str) -> String {
    format!("jkt-jwt;jwt={}", sfv::serialize_string(token))
}

/// Serialize a `jwks_uri` member value — how a server (PS, AS, resource)
/// signs as itself: identity `id`, metadata document `dwk`, key `kid`.
pub fn serialize_jwks_uri(id: &str, dwk: &str, kid: &str) -> String {
    format!(
        "jwks_uri;id={};dwk={};kid={}",
        sfv::serialize_string(id),
        sfv::serialize_string(dwk),
        sfv::serialize_string(kid)
    )
}

/// Result of verifying a `jkt-jwt` naming JWT.
#[derive(Debug, Clone)]
pub struct JktJwtVerified {
    /// The durable (identity) key from the JWT header.
    pub durable_jwk: Jwk,
    /// RFC 7638 thumbprint of the durable key (the enrollment lookup key).
    pub durable_jkt: String,
    /// The delegated ephemeral key from `cnf.jwk` — verifies the HTTP signature.
    pub ephemeral_jwk: Jwk,
    pub jti: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

/// Verify a `jkt-jwt` naming JWT per the spec procedure
/// (see `research/03-http-signatures.md` §4). Only `jkt-s256+jwt` is
/// supported. `max_lifetime_secs` bounds `exp - iat` (0 = unbounded).
pub fn verify_jkt_jwt(
    token: &str,
    now: u64,
    max_lifetime_secs: u64,
) -> Result<JktJwtVerified, SigError> {
    let decoded = jwt::decode(token)
        .map_err(|_| SigError::new(SigErrorCode::InvalidJwt, "malformed naming JWT"))?;
    // 1-2. typ determines the thumbprint hash algorithm
    if decoded.header.typ.as_deref() != Some("jkt-s256+jwt") {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "unsupported naming JWT typ (expected jkt-s256+jwt)",
        ));
    }
    // 3-4. extract header jwk
    let durable_jwk =
        decoded.header.jwk.clone().ok_or_else(|| {
            SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing header jwk")
        })?;
    // 5-7. compute thumbprint, compare against iss by string equality
    let thumb = durable_jwk.thumbprint().map_err(|_| {
        SigError::new(
            SigErrorCode::UnsupportedAlgorithm,
            "unsupported durable key type",
        )
    })?;
    let expected_iss = format!("urn:jkt:sha-256:{thumb}");
    let iss = decoded
        .payload
        .str_claim("iss")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing iss"))?;
    if iss != expected_iss {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT iss does not match header jwk thumbprint",
        ));
    }
    // 8. verify JWT signature with the header jwk
    jwt::verify_with_jwk(&decoded, &durable_jwk).map_err(|e| match e {
        jwt::JwtError::UnsupportedAlgorithm => {
            SigError::new(SigErrorCode::UnsupportedAlgorithm, "naming JWT algorithm")
        }
        _ => SigError::new(SigErrorCode::InvalidJwt, "naming JWT signature invalid"),
    })?;
    // 9. iat / exp
    let iat = decoded
        .payload
        .int_claim("iat")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing iat"))?;
    let exp = decoded
        .payload
        .int_claim("exp")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing exp"))?;
    let now_i = now as i64;
    if exp <= now_i {
        return Err(SigError::new(
            SigErrorCode::ExpiredJwt,
            "naming JWT expired",
        ));
    }
    if iat > now_i + 60 {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT iat in the future",
        ));
    }
    if max_lifetime_secs > 0 && exp.saturating_sub(iat) > max_lifetime_secs as i64 {
        return Err(SigError::new(
            SigErrorCode::InvalidJwt,
            "naming JWT lifetime too long",
        ));
    }
    // 10. ephemeral key from cnf.jwk
    let ephemeral_jwk: Jwk = decoded
        .payload
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(|j| serde_json::from_value(j.clone()).ok())
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidJwt, "naming JWT missing cnf.jwk"))?;
    let jti = decoded.payload.str_claim("jti").map(|s| s.to_string());
    Ok(JktJwtVerified {
        durable_jwk,
        durable_jkt: thumb,
        ephemeral_jwk,
        jti,
        iat,
        exp,
    })
}

/// Build a naming JWT (agent side of the two-key refresh ceremony).
pub fn build_naming_jwt(
    durable_key: &ed25519_dalek::SigningKey,
    ephemeral_public: &Jwk,
    now: u64,
    lifetime_secs: u64,
) -> String {
    let durable_jwk = Jwk::from_verifying_key(&durable_key.verifying_key());
    let thumb = durable_jwk.thumbprint().expect("OKP thumbprint");
    let payload = serde_json::json!({
        "iss": format!("urn:jkt:sha-256:{thumb}"),
        "iat": now,
        "exp": now + lifetime_secs,
        "jti": crate::rand_token(128),
        "cnf": { "jwk": ephemeral_public.public_only() },
    });
    jwt::sign(
        "jkt-s256+jwt",
        None,
        Some(&durable_jwk),
        &payload,
        durable_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;

    #[test]
    fn jkt_jwt_roundtrip() {
        let durable = generate_signing_key();
        let ephemeral = generate_signing_key();
        let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
        let now = 1_750_000_000u64;
        let token = build_naming_jwt(&durable, &eph_jwk, now, 300);
        let verified = verify_jkt_jwt(&token, now + 10, 300).unwrap();
        assert_eq!(verified.ephemeral_jwk.x, eph_jwk.x);
        assert_eq!(
            verified.durable_jkt,
            Jwk::from_verifying_key(&durable.verifying_key())
                .thumbprint()
                .unwrap()
        );
        assert!(verified.jti.is_some());
    }

    #[test]
    fn jkt_jwt_iss_mismatch_rejected() {
        let durable = generate_signing_key();
        let ephemeral = generate_signing_key();
        let eph_jwk = Jwk::from_verifying_key(&ephemeral.verifying_key());
        let now = 1_750_000_000u64;
        // Sign a naming JWT whose iss claims a *different* key's thumbprint.
        let other = generate_signing_key();
        let other_thumb = Jwk::from_verifying_key(&other.verifying_key())
            .thumbprint()
            .unwrap();
        let durable_jwk = Jwk::from_verifying_key(&durable.verifying_key());
        let payload = serde_json::json!({
            "iss": format!("urn:jkt:sha-256:{other_thumb}"),
            "iat": now, "exp": now + 300,
            "cnf": { "jwk": eph_jwk },
        });
        let token = crate::jwt::sign("jkt-s256+jwt", None, Some(&durable_jwk), &payload, &durable);
        let err = verify_jkt_jwt(&token, now, 300).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidJwt);
    }

    #[test]
    fn jkt_jwt_expired_rejected() {
        let durable = generate_signing_key();
        let eph = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let now = 1_750_000_000u64;
        let token = build_naming_jwt(&durable, &eph, now - 1000, 300);
        let err = verify_jkt_jwt(&token, now, 300).unwrap_err();
        assert_eq!(err.code, SigErrorCode::ExpiredJwt);
    }

    #[test]
    fn parse_schemes() {
        let d = sfv::parse_dictionary(r#"sig=jwt;jwt="a.b.c""#).unwrap();
        assert_eq!(
            parse_member(&d[0].1.value).unwrap(),
            SigKeyScheme::Jwt("a.b.c".into())
        );
        let d = sfv::parse_dictionary(
            r#"sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="k1""#,
        )
        .unwrap();
        match parse_member(&d[0].1.value).unwrap() {
            SigKeyScheme::JwksUri { id, dwk, kid } => {
                assert_eq!(id, "https://ps.example");
                assert_eq!(dwk, "aauth-person.json");
                assert_eq!(kid, "k1");
            }
            _ => panic!(),
        }
        let d = sfv::parse_dictionary(r#"sig=x509;x5u="https://x";x5t=:AA==:"#).unwrap();
        assert_eq!(
            parse_member(&d[0].1.value).unwrap(),
            SigKeyScheme::Other("x509".into())
        );
    }

    fn parse_hwk(member: &str) -> Result<SigKeyScheme, SigError> {
        let d = sfv::parse_dictionary(member).unwrap();
        parse_member(&d[0].1.value)
    }

    /// signature-key-08 §3.4: `alg` is REQUIRED on `hwk`. Until -08 the draft
    /// said the opposite, so a member without it is now rejected.
    #[test]
    fn hwk_without_alg_rejected() {
        let err = parse_hwk(r#"sig=hwk;kty="OKP";crv="Ed25519";x="AA""#)
            .expect_err("alg is required on hwk");
        assert_eq!(err.code, SigErrorCode::InvalidKey);
        assert!(err.detail.contains("alg"), "detail: {}", err.detail);
    }

    /// §3.3: "The polymorphic EdDSA identifier MUST NOT be used."
    #[test]
    fn hwk_with_polymorphic_eddsa_rejected() {
        let err = parse_hwk(r#"sig=hwk;kty="OKP";crv="Ed25519";x="AA";alg="EdDSA""#)
            .expect_err("polymorphic EdDSA is banned");
        assert_eq!(err.code, SigErrorCode::UnsupportedAlgorithm);
    }

    /// The fully-specified identifier is accepted and retained on the key.
    #[test]
    fn hwk_with_ed25519_accepted() {
        match parse_hwk(r#"sig=hwk;kty="OKP";crv="Ed25519";x="AA";alg="Ed25519""#).unwrap() {
            SigKeyScheme::Hwk(k) => {
                assert_eq!(k.alg.as_deref(), Some("Ed25519"));
                assert_eq!(k.x, "AA");
            }
            other => panic!("unexpected scheme {other:?}"),
        }
    }

    /// What we emit must be what we accept: the serialiser now carries `alg`.
    #[test]
    fn hwk_serializer_roundtrip() {
        let jwk = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let member = serialize_hwk(&jwk);
        assert!(member.contains(r#"alg="Ed25519""#), "member: {member}");
        match parse_hwk(&format!("sig={member}")).unwrap() {
            SigKeyScheme::Hwk(k) => {
                assert_eq!(k.kty, jwk.kty);
                assert_eq!(k.crv, jwk.crv);
                assert_eq!(k.x, jwk.x);
                assert_eq!(k.alg, jwk.alg);
            }
            other => panic!("unexpected scheme {other:?}"),
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! AAuth token claim types and validation: agent tokens (`aa-agent+jwt`),
//! subscribe tokens (`aa-subscribe+jwt`), and event tokens (`aa-event+jwt`).
//!
//! Verification helpers here are pure: the caller supplies the key (local
//! keys for tokens we issued; a fetched JWKS for foreign tokens) and `now`.

use serde::{Deserialize, Serialize};

use crate::ident::AgentId;
use crate::jwk::Jwk;
use crate::jwt::{self, DecodedJwt};

pub const TYP_AGENT: &str = "aa-agent+jwt";
pub const TYP_RESOURCE: &str = "aa-resource+jwt";
pub const TYP_AUTH: &str = "aa-auth+jwt";
pub const TYP_SUBSCRIBE: &str = "aa-subscribe+jwt";
pub const TYP_EVENT: &str = "aa-event+jwt";

/// Agent-token maximum lifetime per the protocol spec (24 hours).
pub const AGENT_TOKEN_MAX_TTL_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cnf {
    pub jwk: Jwk,
}

/// Claims of an `aa-agent+jwt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTokenClaims {
    pub iss: String,
    pub dwk: String,
    pub sub: String,
    pub jti: String,
    pub cnf: Cnf,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_agent: Option<String>,
}

/// Claims of an `aa-subscribe+jwt` (AAuth Events).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeTokenClaims {
    pub iss: String,
    pub dwk: String,
    pub sub: String,
    pub aud: String,
    pub cnf: Cnf,
    pub eid: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
}

/// Claims of an `aa-event+jwt` (AAuth Events). No `cnf`: the resource's own
/// JWKS key verifies both the JWT and the HTTP signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTokenClaims {
    pub iss: String,
    pub dwk: String,
    pub aud: String,
    pub eid: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Clone)]
pub struct TokenError(pub String);

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for TokenError {}

fn err(msg: impl Into<String>) -> TokenError {
    TokenError(msg.into())
}

/// Structural + temporal validation of a decoded agent token, after the JWT
/// signature has been verified by the caller. Implements the spec's agent
/// token verification steps that don't involve the HTTP request.
pub fn validate_agent_token(
    decoded: &DecodedJwt,
    now: u64,
    insecure_dev: bool,
) -> Result<AgentTokenClaims, TokenError> {
    if decoded.header.typ.as_deref() != Some(TYP_AGENT) {
        return Err(err("typ is not aa-agent+jwt"));
    }
    let claims: AgentTokenClaims = serde_json::from_value(decoded.payload.clone())
        .map_err(|e| err(format!("missing or invalid claims: {e}")))?;
    if claims.dwk != "aauth-agent.json" {
        return Err(err("dwk is not aauth-agent.json"));
    }
    crate::ident::validate_server_identifier(&claims.iss, insecure_dev)
        .map_err(|_| err("iss is not a valid server identifier"))?;
    let agent =
        AgentId::parse(&claims.sub).map_err(|_| err("sub is not a valid agent identifier"))?;
    // Bind the agent to the server that vouched for it. `iss` and `sub` were
    // each validated for shape but never against each other, so any trusted
    // issuer could mint a token naming an agent in someone else's domain —
    // and `sub` becomes the gateway principal verbatim.
    match crate::ident::host_of(&claims.iss) {
        Some(iss_host) if iss_host.eq_ignore_ascii_case(&agent.domain) => {}
        _ => {
            return Err(err(
                "sub's agent domain does not match the issuing server's host",
            ));
        }
    }
    if claims.exp <= now {
        return Err(err("agent token expired"));
    }
    if claims.iat > now + 60 {
        return Err(err("agent token iat in the future"));
    }
    if let Some(ps) = &claims.ps {
        crate::ident::validate_server_identifier(ps, insecure_dev)
            .map_err(|_| err("ps is not a valid server identifier"))?;
    }
    if let Some(parent) = &claims.parent_agent {
        let parent_id = AgentId::parse(parent)
            .map_err(|_| err("parent_agent is not a valid agent identifier"))?;
        if parent_id.is_subagent_named() {
            return Err(err("parent_agent must not itself be a sub-agent"));
        }
    }
    // AAuth -10 §5.2.2: the confirmation JWK MUST carry a fully-specified
    // `alg`. It names the algorithm the resource verifies the HTTP request
    // signature with, so an absent or polymorphic value leaves that choice
    // implicit — exactly what the fully-specified requirement removes.
    claims
        .cnf
        .jwk
        .require_fully_specified_alg()
        .map_err(|e| err(format!("cnf.jwk: {e}")))?;
    claims
        .cnf
        .jwk
        .verifying_key()
        .map_err(|_| err("cnf.jwk is not a usable key"))?;
    Ok(claims)
}

/// Full verification of an agent token against a known issuer key
/// (signature + structure). Suitable when the verifier already holds the
/// issuer's JWKS (e.g. the AP verifying tokens it issued itself).
pub fn verify_agent_token_with_key(
    token: &str,
    key: &Jwk,
    now: u64,
    insecure_dev: bool,
) -> Result<AgentTokenClaims, TokenError> {
    let decoded = jwt::decode(token).map_err(|e| err(format!("malformed token: {e}")))?;
    jwt::verify_with_jwk(&decoded, key).map_err(|e| err(format!("bad signature: {e}")))?;
    validate_agent_token(&decoded, now, insecure_dev)
}

/// Structural + temporal validation of a decoded event token (JWT signature
/// verified separately against the resource's JWKS).
pub fn validate_event_token(
    decoded: &DecodedJwt,
    now: u64,
    insecure_dev: bool,
) -> Result<EventTokenClaims, TokenError> {
    if decoded.header.typ.as_deref() != Some(TYP_EVENT) {
        return Err(err("typ is not aa-event+jwt"));
    }
    let claims: EventTokenClaims = serde_json::from_value(decoded.payload.clone())
        .map_err(|e| err(format!("missing or invalid claims: {e}")))?;
    if claims.dwk != "aauth-resource.json" {
        return Err(err("dwk is not aauth-resource.json"));
    }
    crate::ident::validate_server_identifier(&claims.iss, insecure_dev)
        .map_err(|_| err("iss is not a valid server identifier"))?;
    AgentId::parse(&claims.aud).map_err(|_| err("aud is not a valid agent identifier"))?;
    if claims.eid.is_empty() {
        return Err(err("eid is empty"));
    }
    if claims.exp <= now {
        return Err(err("event token expired"));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;

    fn agent_claims(now: u64, key_jwk: Jwk) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://ap.example",
            "dwk": "aauth-agent.json",
            "sub": "aauth:k7q3p9n2@ap.example",
            "jti": "abc",
            "cnf": {"jwk": key_jwk},
            "iat": now,
            "exp": now + 3600,
            "ps": "https://ps.example",
        })
    }

    #[test]
    fn agent_token_roundtrip() {
        let ap_key = generate_signing_key();
        let ap_jwk = Jwk::from_verifying_key(&ap_key.verifying_key());
        let agent_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let payload = agent_claims(now, Jwk::from_verifying_key(&agent_key.verifying_key()));
        let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
        let claims = verify_agent_token_with_key(&token, &ap_jwk, now + 5, false).unwrap();
        assert_eq!(claims.sub, "aauth:k7q3p9n2@ap.example");
        assert_eq!(claims.ps.as_deref(), Some("https://ps.example"));
    }

    /// `iss` and `sub` were each shape-validated but never compared, so a
    /// server could vouch for an agent in a domain it does not own — and
    /// `sub` becomes the gateway principal verbatim.
    #[test]
    fn agent_domain_must_match_the_issuing_server() {
        let ap_key = generate_signing_key();
        let ap_jwk = Jwk::from_verifying_key(&ap_key.verifying_key());
        let now = 1_750_000_000u64;
        let mut payload = agent_claims(
            now,
            Jwk::from_verifying_key(&generate_signing_key().verifying_key()),
        );
        // Same trusted issuer, agent named in someone else's domain.
        payload["sub"] = serde_json::json!("aauth:k7q3p9n2@victim.example");
        let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
        let err = verify_agent_token_with_key(&token, &ap_jwk, now + 5, false)
            .expect_err("cross-domain agent must be refused");
        assert!(format!("{err:?}").contains("domain"), "got: {err:?}");
    }

    #[test]
    fn expired_agent_token_rejected() {
        let ap_key = generate_signing_key();
        let ap_jwk = Jwk::from_verifying_key(&ap_key.verifying_key());
        let now = 1_750_000_000u64;
        let payload = agent_claims(
            now - 7200,
            Jwk::from_verifying_key(&generate_signing_key().verifying_key()),
        );
        let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
        assert!(verify_agent_token_with_key(&token, &ap_jwk, now, false).is_err());
    }

    #[test]
    fn wrong_typ_rejected() {
        let ap_key = generate_signing_key();
        let ap_jwk = Jwk::from_verifying_key(&ap_key.verifying_key());
        let now = 1_750_000_000u64;
        let payload = agent_claims(now, Jwk::from_verifying_key(&ap_key.verifying_key()));
        let token = jwt::sign("aa-auth+jwt", Some("k1"), None, &payload, &ap_key);
        assert!(verify_agent_token_with_key(&token, &ap_jwk, now, false).is_err());
    }

    /// AAuth -10 §5.2.2: `cnf.jwk` MUST carry a fully-specified `alg`. Both
    /// the absent and the polymorphic form are refused.
    #[test]
    fn cnf_jwk_must_be_fully_specified() {
        let ap_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let agent_jwk = Jwk::from_verifying_key(&generate_signing_key().verifying_key());

        for bad_alg in [None, Some("EdDSA"), Some("HS256")] {
            let mut payload = agent_claims(now, agent_jwk.clone());
            match bad_alg {
                Some(a) => payload["cnf"]["jwk"]["alg"] = serde_json::json!(a),
                None => {
                    payload["cnf"]["jwk"].as_object_mut().unwrap().remove("alg");
                }
            }
            let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
            let decoded = jwt::decode(&token).unwrap();
            let e = match validate_agent_token(&decoded, now, false) {
                Err(e) => e,
                Ok(_) => panic!("cnf.jwk alg {bad_alg:?} must be refused"),
            };
            assert!(e.0.contains("cnf.jwk"), "alg {bad_alg:?} — got: {e}");
        }

        // The fully-specified form is accepted.
        let payload = agent_claims(now, agent_jwk);
        let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
        validate_agent_token(&jwt::decode(&token).unwrap(), now, false).unwrap();
    }

    #[test]
    fn nested_subagent_parent_rejected() {
        let ap_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let mut payload = agent_claims(now, Jwk::from_verifying_key(&ap_key.verifying_key()));
        payload["sub"] = "aauth:a+b@ap.example".into();
        payload["parent_agent"] = "aauth:a+x@ap.example".into();
        let token = jwt::sign(TYP_AGENT, Some("k1"), None, &payload, &ap_key);
        let decoded = jwt::decode(&token).unwrap();
        assert!(validate_agent_token(&decoded, now, false).is_err());
    }
}

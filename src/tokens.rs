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
pub const TYP_PERSON: &str = "aa-person+jwt";
pub const TYP_RESOURCE: &str = "aa-resource+jwt";
pub const TYP_AUTH: &str = "aa-auth+jwt";
pub const TYP_SUBSCRIBE: &str = "aa-subscribe+jwt";
pub const TYP_EVENT: &str = "aa-event+jwt";

/// Agent-token maximum lifetime per the protocol spec (24 hours).
pub const AGENT_TOKEN_MAX_TTL_SECS: u64 = 24 * 3600;

/// Person-token maximum lifetime per the protocol spec (1 hour, a MUST).
pub const PERSON_TOKEN_MAX_TTL_SECS: u64 = 3600;

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

/// Claims of an `aa-person+jwt` — a PS-issued token identifying the person an
/// agent acts for, to exactly one resource. Carries identity and NO
/// authorization: the spec forbids `scope` and `account` members outright.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonTokenClaims {
    pub iss: String,
    pub dwk: String,
    pub aud: String,
    /// Directed (pairwise) opaque person identifier — unique within `iss`
    /// only. `(iss, sub)` is the identifier; `sub` alone is meaningless.
    pub sub: String,
    pub cnf: Cnf,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_s256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
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
        .verify_key()
        .map_err(|_| err("cnf.jwk is not a usable key"))?;
    Ok(claims)
}

/// Structural + temporal validation of a decoded person token, after the JWT
/// signature has been verified by the caller. `resource_identifier` is the
/// verifying resource's own server identifier — the token's `aud` MUST equal
/// it exactly.
pub fn validate_person_token(
    decoded: &DecodedJwt,
    now: u64,
    resource_identifier: &str,
    insecure_dev: bool,
) -> Result<PersonTokenClaims, TokenError> {
    if decoded.header.typ.as_deref() != Some(TYP_PERSON) {
        return Err(err("typ is not aa-person+jwt"));
    }
    // The spec forbids these members on a person token — a person token
    // carries identity and no authorization, and only `typ` distinguishes it
    // from an auth token. Reject rather than ignore, so a mis-minted token
    // cannot smuggle authorization-shaped claims to downstream policy.
    for forbidden in ["scope", "account"] {
        if decoded.payload.get(forbidden).is_some() {
            return Err(err(format!(
                "person token carries the forbidden `{forbidden}` claim"
            )));
        }
    }
    let claims: PersonTokenClaims = serde_json::from_value(decoded.payload.clone())
        .map_err(|e| err(format!("missing or invalid claims: {e}")))?;
    if claims.dwk != "aauth-person.json" {
        return Err(err("dwk is not aauth-person.json"));
    }
    crate::ident::validate_server_identifier(&claims.iss, insecure_dev)
        .map_err(|_| err("iss is not a valid server identifier"))?;
    if claims.aud != resource_identifier {
        return Err(err(
            "aud does not match this resource's identifier — the token was issued for a \
             different resource",
        ));
    }
    if claims.sub.is_empty() {
        return Err(err("sub is empty"));
    }
    if claims.exp <= now {
        return Err(err("person token expired"));
    }
    if claims.iat > now + 60 {
        return Err(err("person token iat in the future"));
    }
    if claims.exp.saturating_sub(claims.iat) > PERSON_TOKEN_MAX_TTL_SECS {
        return Err(err(format!(
            "person token lifetime exceeds the {PERSON_TOKEN_MAX_TTL_SECS}s ceiling"
        )));
    }
    claims
        .cnf
        .jwk
        .require_fully_specified_alg()
        .map_err(|e| err(format!("cnf.jwk: {e}")))?;
    claims
        .cnf
        .jwk
        .verify_key()
        .map_err(|_| err("cnf.jwk is not a usable key"))?;
    Ok(claims)
}

/// Claims of an `aa-auth+jwt` — the grant a PS (three-party) or AS
/// (four-party) issues to an agent for exactly one resource. Carries what
/// is authorized (`scope`), the person (`sub`, directed under `ps`), and the
/// agent's key (`cnf`); never an agent identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenClaims {
    pub iss: String,
    pub dwk: String,
    pub aud: String,
    pub jti: String,
    /// The person server the person is represented by — equals `iss` when a
    /// PS issued the token.
    pub ps: String,
    pub sub: String,
    pub cnf: Cnf,
    pub iat: u64,
    pub exp: u64,
    /// Space-separated scope values, when the grant carries any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_s256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

impl AuthTokenClaims {
    /// The granted scope values as a list.
    pub fn scopes(&self) -> Vec<String> {
        self.scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    }
}

/// Auth-token maximum lifetime per the protocol spec (1 hour, a MUST).
pub const AUTH_TOKEN_MAX_TTL_SECS: u64 = 3600;

/// Structural + temporal validation of a decoded auth token, after the JWT
/// signature has been verified by the caller. `resource_identifier` is the
/// verifying resource's own server identifier — `aud` MUST equal it exactly.
/// The caller decides which `dwk` it accepts (`aauth-person.json` from a
/// trusted PS, `aauth-access.json` from a trusted AS) and passes it here.
pub fn validate_auth_token(
    decoded: &DecodedJwt,
    now: u64,
    resource_identifier: &str,
    expected_dwk: &str,
    insecure_dev: bool,
) -> Result<AuthTokenClaims, TokenError> {
    if decoded.header.typ.as_deref() != Some(TYP_AUTH) {
        return Err(err("typ is not aa-auth+jwt"));
    }
    let claims: AuthTokenClaims = serde_json::from_value(decoded.payload.clone())
        .map_err(|e| err(format!("missing or invalid claims: {e}")))?;
    if claims.dwk != expected_dwk {
        return Err(err(format!("dwk is not {expected_dwk}")));
    }
    crate::ident::validate_server_identifier(&claims.iss, insecure_dev)
        .map_err(|_| err("iss is not a valid server identifier"))?;
    crate::ident::validate_server_identifier(&claims.ps, insecure_dev)
        .map_err(|_| err("ps is not a valid server identifier"))?;
    // A PS-issued auth token names itself as the person server.
    if expected_dwk == "aauth-person.json" && claims.ps != claims.iss {
        return Err(err("ps does not equal iss on a PS-issued auth token"));
    }
    if claims.aud != resource_identifier {
        return Err(err(
            "aud does not match this resource's identifier — the token was issued for a \
             different resource",
        ));
    }
    if claims.sub.is_empty() {
        return Err(err("sub is empty"));
    }
    if claims.exp <= now {
        return Err(err("auth token expired"));
    }
    if claims.iat > now + 60 {
        return Err(err("auth token iat in the future"));
    }
    if claims.exp.saturating_sub(claims.iat) > AUTH_TOKEN_MAX_TTL_SECS {
        return Err(err(format!(
            "auth token lifetime exceeds the {AUTH_TOKEN_MAX_TTL_SECS}s ceiling"
        )));
    }
    claims
        .cnf
        .jwk
        .require_fully_specified_alg()
        .map_err(|e| err(format!("cnf.jwk: {e}")))?;
    claims
        .cnf
        .jwk
        .verify_key()
        .map_err(|_| err("cnf.jwk is not a usable key"))?;
    Ok(claims)
}

/// Resource-token maximum lifetime per the protocol spec (5 minutes, a
/// SHOULD NOT exceed; person servers enforce it as a hard cap).
pub const RESOURCE_TOKEN_MAX_TTL_SECS: u64 = 300;

/// What a resource puts into an `aa-resource+jwt`: the signed statement of
/// the access it wants a person server (or access server) to authorize.
#[derive(Debug, Clone)]
pub struct ResourceTokenRequest<'a> {
    /// The resource's own server identifier (`iss`).
    pub resource: &'a str,
    /// The token's audience — the PS (three-party) or AS (four-party) URL.
    pub aud: &'a str,
    /// The `iss` of the person token the resource verified.
    pub ps: &'a str,
    /// The `sub` of that person token.
    pub sub: &'a str,
    /// The `jti` of that person token (`presented_jti`).
    pub presented_jti: &'a str,
    /// RFC 7638 thumbprint of the agent's signing key.
    pub agent_jkt: &'a str,
    /// Space-separated scope values being requested.
    pub scope: &'a str,
    pub account: Option<&'a str>,
    /// REQUIRED when the person token carried one — copied unchanged.
    pub mission_s256: Option<&'a str>,
    pub tenant: Option<&'a str>,
    /// Lifetime, seconds; clamped to [`RESOURCE_TOKEN_MAX_TTL_SECS`].
    pub ttl_secs: u64,
}

/// Mint and sign a resource token with the resource's Ed25519 key. Returns
/// the compact JWT and its `jti`.
pub fn issue_resource_token(
    req: &ResourceTokenRequest<'_>,
    kid: &str,
    key: &crate::jwk::SigningKey,
    now: u64,
) -> (String, String) {
    let ttl = req.ttl_secs.clamp(1, RESOURCE_TOKEN_MAX_TTL_SECS);
    let jti = format!("rt-{}", crate::rand_token(128));
    let mut payload = serde_json::json!({
        "iss": req.resource,
        "dwk": "aauth-resource.json",
        "aud": req.aud,
        "jti": jti,
        "ps": req.ps,
        "sub": req.sub,
        "presented_jti": req.presented_jti,
        "agent_jkt": req.agent_jkt,
        "iat": now,
        "exp": now + ttl,
        "scope": req.scope,
    });
    if let Some(a) = req.account {
        payload["account"] = serde_json::json!(a);
    }
    if let Some(m) = req.mission_s256 {
        payload["mission_s256"] = serde_json::json!(m);
    }
    if let Some(t) = req.tenant {
        payload["tenant"] = serde_json::json!(t);
    }
    (jwt::sign(TYP_RESOURCE, Some(kid), None, &payload, key), jti)
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

    fn person_claims(now: u64, key_jwk: Jwk) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://ps.example",
            "dwk": "aauth-person.json",
            "aud": "https://resource.example",
            "sub": "8f14e45fceea167a5a36dedd4bea2543",
            "cnf": {"jwk": key_jwk},
            "jti": "pt-1",
            "iat": now,
            "exp": now + 1800,
        })
    }

    #[test]
    fn person_token_roundtrip_and_aud_pinning() {
        let ps_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let agent_jwk = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let token = jwt::sign(
            TYP_PERSON,
            Some("p1"),
            None,
            &person_claims(now, agent_jwk),
            &ps_key,
        );
        let decoded = jwt::decode(&token).unwrap();
        let claims =
            validate_person_token(&decoded, now + 5, "https://resource.example", false).unwrap();
        assert_eq!(claims.sub, "8f14e45fceea167a5a36dedd4bea2543");
        // The same token at a different resource is refused on `aud`.
        assert!(
            validate_person_token(&decoded, now + 5, "https://other.example", false)
                .unwrap_err()
                .0
                .contains("aud")
        );
    }

    /// A person token MUST NOT carry `scope`/`account`, MUST NOT outlive one
    /// hour, and its `typ` alone separates it from an auth token.
    #[test]
    fn person_token_guardrails() {
        let ps_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let agent_jwk = Jwk::from_verifying_key(&generate_signing_key().verifying_key());

        let mut with_scope = person_claims(now, agent_jwk.clone());
        with_scope["scope"] = serde_json::json!("data.read");
        let t = jwt::sign(TYP_PERSON, Some("p1"), None, &with_scope, &ps_key);
        let e = validate_person_token(
            &jwt::decode(&t).unwrap(),
            now,
            "https://resource.example",
            false,
        )
        .unwrap_err();
        assert!(e.0.contains("scope"), "got: {e}");

        let mut long = person_claims(now, agent_jwk.clone());
        long["exp"] = serde_json::json!(now + 2 * 3600);
        let t = jwt::sign(TYP_PERSON, Some("p1"), None, &long, &ps_key);
        let e = validate_person_token(
            &jwt::decode(&t).unwrap(),
            now,
            "https://resource.example",
            false,
        )
        .unwrap_err();
        assert!(e.0.contains("ceiling"), "got: {e}");

        // An agent-typed JWT never validates as a person token.
        let t = jwt::sign(
            TYP_AGENT,
            Some("p1"),
            None,
            &person_claims(now, agent_jwk),
            &ps_key,
        );
        let e = validate_person_token(
            &jwt::decode(&t).unwrap(),
            now,
            "https://resource.example",
            false,
        )
        .unwrap_err();
        assert!(e.0.contains("typ"), "got: {e}");
    }

    fn auth_claims(now: u64, key_jwk: Jwk) -> serde_json::Value {
        serde_json::json!({
            "iss": "https://ps.example",
            "dwk": "aauth-person.json",
            "aud": "https://resource.example",
            "jti": "at-1",
            "ps": "https://ps.example",
            "sub": "8f14e45fceea167a5a36dedd4bea2543",
            "cnf": {"jwk": key_jwk},
            "iat": now,
            "exp": now + 900,
            "scope": "tools:read tools:write",
            "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        })
    }

    #[test]
    fn auth_token_roundtrip_scopes_and_guardrails() {
        let ps_key = generate_signing_key();
        let now = 1_750_000_000u64;
        let agent_jwk = Jwk::from_verifying_key(&generate_signing_key().verifying_key());
        let ok = jwt::sign(
            TYP_AUTH,
            Some("p1"),
            None,
            &auth_claims(now, agent_jwk.clone()),
            &ps_key,
        );
        let claims = validate_auth_token(
            &jwt::decode(&ok).unwrap(),
            now + 5,
            "https://resource.example",
            "aauth-person.json",
            false,
        )
        .unwrap();
        assert_eq!(claims.scopes(), vec!["tools:read", "tools:write"]);
        assert_eq!(claims.ps, "https://ps.example");

        // Wrong dwk expectation (an AS-issued token presented as PS-issued).
        assert!(
            validate_auth_token(
                &jwt::decode(&ok).unwrap(),
                now,
                "https://resource.example",
                "aauth-access.json",
                false
            )
            .unwrap_err()
            .0
            .contains("dwk")
        );
        // Wrong audience.
        assert!(
            validate_auth_token(
                &jwt::decode(&ok).unwrap(),
                now,
                "https://other.example",
                "aauth-person.json",
                false
            )
            .unwrap_err()
            .0
            .contains("aud")
        );
        // ps must equal iss when PS-issued.
        let mut c = auth_claims(now, agent_jwk.clone());
        c["ps"] = serde_json::json!("https://elsewhere.example");
        let t = jwt::sign(TYP_AUTH, Some("p1"), None, &c, &ps_key);
        assert!(
            validate_auth_token(
                &jwt::decode(&t).unwrap(),
                now,
                "https://resource.example",
                "aauth-person.json",
                false
            )
            .unwrap_err()
            .0
            .contains("ps")
        );
        // Over one hour.
        let mut c = auth_claims(now, agent_jwk.clone());
        c["exp"] = serde_json::json!(now + 7200);
        let t = jwt::sign(TYP_AUTH, Some("p1"), None, &c, &ps_key);
        assert!(
            validate_auth_token(
                &jwt::decode(&t).unwrap(),
                now,
                "https://resource.example",
                "aauth-person.json",
                false
            )
            .unwrap_err()
            .0
            .contains("ceiling")
        );
        // A person token never validates as an auth token.
        let t = jwt::sign(
            TYP_PERSON,
            Some("p1"),
            None,
            &auth_claims(now, agent_jwk),
            &ps_key,
        );
        assert!(
            validate_auth_token(
                &jwt::decode(&t).unwrap(),
                now,
                "https://resource.example",
                "aauth-person.json",
                false
            )
            .unwrap_err()
            .0
            .contains("typ")
        );
    }

    #[test]
    fn resource_token_roundtrip_and_ttl_clamp() {
        let res_key = generate_signing_key();
        let res_jwk = Jwk::from_verifying_key(&res_key.verifying_key());
        let now = 1_750_000_000u64;
        let (token, jti) = issue_resource_token(
            &ResourceTokenRequest {
                resource: "https://gw.example",
                aud: "https://ps.example",
                ps: "https://ps.example",
                sub: "8f14e45fceea167a5a36dedd4bea2543",
                presented_jti: "pt-1",
                agent_jkt: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
                scope: "tools:read",
                account: None,
                mission_s256: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                tenant: None,
                ttl_secs: 99_999, // clamped to the 5-minute ceiling
            },
            "gw-k1",
            &res_key,
            now,
        );
        let decoded = jwt::decode(&token).unwrap();
        jwt::verify_with_jwk(&decoded, &res_jwk).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some(TYP_RESOURCE));
        assert_eq!(decoded.header.kid.as_deref(), Some("gw-k1"));
        assert_eq!(decoded.payload["jti"], jti);
        assert!(jti.starts_with("rt-"));
        assert_eq!(decoded.payload["dwk"], "aauth-resource.json");
        assert_eq!(decoded.payload["aud"], "https://ps.example");
        assert_eq!(decoded.payload["presented_jti"], "pt-1");
        assert_eq!(decoded.payload["scope"], "tools:read");
        assert_eq!(
            decoded.payload["mission_s256"],
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert!(decoded.payload.get("account").is_none());
        assert_eq!(
            decoded.payload["exp"].as_u64().unwrap() - now,
            RESOURCE_TOKEN_MAX_TTL_SECS
        );
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

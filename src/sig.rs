// SPDX-License-Identifier: MIT OR Apache-2.0
// Vendored from aauth-core (AAuth protocol primitives), (c) 2026 apd contributors,
// https://github.com/agentprovider/source-code @ 201118bd0da4b95cfc91f45c5e29ae5733d14aad.
// Verify path for the mcpg dev.mcpg.identity.aauth plugin; see third_party/aauth-core/.

//! RFC 9421 HTTP Message Signatures, profiled for AAuth
//! (see `research/03-http-signatures.md`).
//!
//! - Signing: [`sign_request`] produces `Signature-Input`, `Signature`, and
//!   `Signature-Key` headers with the mandated covered components.
//! - Verification: [`parse_request_signature`] does everything except key
//!   resolution and the final crypto; the caller resolves the key from the
//!   [`crate::sigkey::SigKeyScheme`] (possibly fetching a JWKS) and then
//!   calls [`verify_parsed`].

use ed25519_dalek::{Signer, SigningKey};

use crate::b64;
use crate::jwk::{Jwk, JwkError, SigCheckError};
use crate::sfv::{self, BareItem, MemberValue};
use crate::sigkey::SigKeyScheme;

/// Covered components every AAuth request signature MUST include.
pub const REQUIRED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "signature-key"];

/// Machine-readable error codes for the `Signature-Error` response header
/// (`draft-hardt-httpbis-signature-key-08` error-code registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigErrorCode {
    UnsupportedAlgorithm,
    UnsupportedScheme,
    InvalidSignature,
    InvalidInput,
    InvalidRequest,
    InvalidKey,
    UnknownKey,
    IssuerMissing,
    IssuerMismatch,
    InvalidJwt,
    ExpiredJwt,
}

impl SigErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigErrorCode::UnsupportedAlgorithm => "unsupported_algorithm",
            SigErrorCode::UnsupportedScheme => "unsupported_scheme",
            SigErrorCode::InvalidSignature => "invalid_signature",
            SigErrorCode::InvalidInput => "invalid_input",
            SigErrorCode::InvalidRequest => "invalid_request",
            SigErrorCode::InvalidKey => "invalid_key",
            SigErrorCode::UnknownKey => "unknown_key",
            SigErrorCode::IssuerMissing => "issuer_missing",
            SigErrorCode::IssuerMismatch => "issuer_mismatch",
            SigErrorCode::InvalidJwt => "invalid_jwt",
            SigErrorCode::ExpiredJwt => "expired_jwt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigError {
    pub code: SigErrorCode,
    pub detail: String,
    /// For `invalid_input`: the components the verifier requires.
    pub required_input: Option<Vec<String>>,
}

impl SigError {
    pub fn new(code: SigErrorCode, detail: impl Into<String>) -> Self {
        SigError {
            code,
            detail: detail.into(),
            required_input: None,
        }
    }
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}
impl std::error::Error for SigError {}

/// The pieces of an HTTP request a verifier needs.
pub struct RequestParts<'a> {
    /// Method as sent (uppercase).
    pub method: &'a str,
    /// Host (+ optional port), lowercase — the `@authority` component.
    pub authority: &'a str,
    /// Target path without query.
    pub path: &'a str,
    /// Query string including leading `?`, or empty if none.
    pub query: &'a str,
    /// Lookup of a header by lowercase name, canonicalized per RFC 9421
    /// (values comma-joined, OWS trimmed).
    pub header: &'a dyn Fn(&str) -> Option<String>,
}

/// Verification policy.
pub struct VerifyPolicy {
    /// Unix time now.
    pub now: u64,
    /// Allowed skew for the `created` parameter (both directions), seconds.
    pub window_secs: u64,
    /// Header/derived components the endpoint requires **in addition to**
    /// [`REQUIRED_COMPONENTS`].
    pub extra_required: Vec<String>,
}

/// A parsed, structurally-validated signature; crypto not yet checked.
///
/// The RFC 9421 `alg`, `keyid`, `nonce`, and `tag` signature parameters are
/// deliberately not surfaced: under the JOSE signing algorithms this profile
/// uses, the algorithm is signaled by the key and verifiers MUST ignore the
/// `alg` parameter (signature-key-08 "Algorithm Selection"); the key is
/// identified by `Signature-Key`, so `keyid` has nothing to name.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub label: String,
    pub covered: Vec<String>,
    pub created: i64,
    pub scheme: SigKeyScheme,
    /// The exact signature base string to verify.
    pub base: String,
    pub signature: Vec<u8>,
}

fn component_value(name: &str, parts: &RequestParts) -> Result<String, SigError> {
    if let Some(derived) = name.strip_prefix('@') {
        match derived {
            "method" => Ok(parts.method.to_string()),
            "authority" => Ok(parts.authority.to_string()),
            "path" => Ok(parts.path.to_string()),
            "query" => Ok(if parts.query.is_empty() {
                "?".to_string()
            } else {
                parts.query.to_string()
            }),
            _ => Err(SigError::new(
                SigErrorCode::InvalidInput,
                format!("unsupported derived component @{derived}"),
            )),
        }
    } else {
        (parts.header)(name).ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidInput,
                format!("covered header field '{name}' not present"),
            )
        })
    }
}

/// Build the RFC 9421 signature base given covered component names, the raw
/// `Signature-Input` member text, and the request.
pub fn build_signature_base(
    covered: &[String],
    sig_params_raw: &str,
    parts: &RequestParts,
) -> Result<String, SigError> {
    let mut base = String::new();
    for name in covered {
        let value = component_value(name, parts)?;
        base.push_str(&sfv::serialize_string(name));
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(sig_params_raw);
    Ok(base)
}

/// Parse and structurally validate the signature on a request:
/// header correlation, covered-component requirements, `created` window,
/// `expires`. Returns the scheme so the caller can resolve the key, plus the
/// prepared base + signature bytes for [`verify_parsed`].
pub fn parse_request_signature(
    parts: &RequestParts,
    policy: &VerifyPolicy,
) -> Result<ParsedSignature, SigError> {
    let get = |h: &str| (parts.header)(h);
    // AAuth core profile, Verification step 1: if any of the three signature
    // headers is wholly absent, return `invalid_request` (distinct from
    // `invalid_signature`, which is for malformed/failed signatures). The AAuth
    // profile governs here over sigkey §5.4.2.
    let sig_input_hdr = get("signature-input").ok_or_else(|| {
        SigError::new(
            SigErrorCode::InvalidRequest,
            "missing Signature-Input header",
        )
    })?;
    let sig_hdr = get("signature")
        .ok_or_else(|| SigError::new(SigErrorCode::InvalidRequest, "missing Signature header"))?;
    let sig_key_hdr = get("signature-key").ok_or_else(|| {
        SigError::new(SigErrorCode::InvalidRequest, "missing Signature-Key header")
    })?;

    let inputs = sfv::parse_dictionary(&sig_input_hdr).map_err(|e| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            format!("Signature-Input: {e}"),
        )
    })?;
    let sigs = sfv::parse_dictionary(&sig_hdr)
        .map_err(|e| SigError::new(SigErrorCode::InvalidSignature, format!("Signature: {e}")))?;
    let keys = sfv::parse_dictionary(&sig_key_hdr).map_err(|e| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            format!("Signature-Key: {e}"),
        )
    })?;

    // Pick the first Signature-Key label that also appears in the other two
    // headers (single-signature deployments are the norm).
    let (label, key_member) = keys
        .iter()
        .find(|(label, _)| {
            inputs.iter().any(|(k, _)| k == label) && sigs.iter().any(|(k, _)| k == label)
        })
        .ok_or_else(|| {
            SigError::new(
                SigErrorCode::InvalidSignature,
                "no signature label present in Signature-Input, Signature, and Signature-Key",
            )
        })?;

    let scheme = crate::sigkey::parse_member(&key_member.value)?;

    let input_member = &inputs.iter().find(|(k, _)| k == label).unwrap().1;
    let (covered_items, params) = match &input_member.value {
        MemberValue::List(l) => (&l.items, &l.params),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidSignature,
                "Signature-Input member is not an inner list",
            ));
        }
    };

    let mut covered = Vec::with_capacity(covered_items.len());
    for (item, item_params) in covered_items {
        if !item_params.is_empty() {
            return Err(SigError::new(
                SigErrorCode::InvalidInput,
                "component parameters are not supported",
            ));
        }
        match item {
            BareItem::Str(s) => covered.push(s.clone()),
            _ => {
                return Err(SigError::new(
                    SigErrorCode::InvalidSignature,
                    "covered component is not a string",
                ));
            }
        }
    }

    // Required components
    let mut missing: Vec<String> = Vec::new();
    for req in REQUIRED_COMPONENTS
        .iter()
        .map(|s| s.to_string())
        .chain(policy.extra_required.iter().cloned())
    {
        if !covered.contains(&req) {
            missing.push(req);
        }
    }
    if !missing.is_empty() {
        let mut required: Vec<String> = REQUIRED_COMPONENTS.iter().map(|s| s.to_string()).collect();
        required.extend(policy.extra_required.iter().cloned());
        let mut err = SigError::new(
            SigErrorCode::InvalidInput,
            format!("missing covered components: {}", missing.join(", ")),
        );
        err.required_input = Some(required);
        return Err(err);
    }

    // created / expires
    let created = sfv::param(params, "created")
        .and_then(|v| v.as_int())
        .ok_or_else(|| {
            SigError::new(SigErrorCode::InvalidSignature, "missing created parameter")
        })?;
    let now = policy.now as i64;
    let window = policy.window_secs as i64;
    if created < now - window || created > now + window {
        return Err(SigError::new(
            SigErrorCode::InvalidSignature,
            "created timestamp outside validity window",
        ));
    }
    if let Some(expires) = sfv::param(params, "expires").and_then(|v| v.as_int())
        && expires < now
    {
        return Err(SigError::new(
            SigErrorCode::InvalidSignature,
            "signature expired",
        ));
    }

    let signature = match &sigs.iter().find(|(k, _)| k == label).unwrap().1.value {
        MemberValue::Item(BareItem::Bytes(b), _) => b.clone(),
        _ => {
            return Err(SigError::new(
                SigErrorCode::InvalidSignature,
                "Signature member is not a byte sequence",
            ));
        }
    };

    let base = build_signature_base(&covered, &input_member.raw, parts)?;

    Ok(ParsedSignature {
        label: label.clone(),
        covered,
        created,
        scheme,
        base,
        signature,
    })
}

/// Verify the signature bytes against a resolved key. The algorithm comes
/// from the key's `alg` member alone (which must be present, fully specified,
/// and consistent with `kty`/`crv`); any `alg` signature parameter on the
/// wire was already ignored at parse time.
pub fn verify_parsed(parsed: &ParsedSignature, key: &Jwk) -> Result<(), SigError> {
    key.require_fully_specified_alg().map_err(|e| match e {
        JwkError::InconsistentAlg => SigError::new(
            SigErrorCode::InvalidKey,
            "key `alg` disagrees with its `kty`/`crv`",
        ),
        other => SigError::new(SigErrorCode::UnsupportedAlgorithm, format!("{other}")),
    })?;
    let vk = key
        .verify_key()
        .map_err(|_| SigError::new(SigErrorCode::InvalidKey, "unparseable public key"))?;
    vk.verify(parsed.base.as_bytes(), &parsed.signature)
        .map_err(|e| match e {
            SigCheckError::BadLength => {
                SigError::new(SigErrorCode::InvalidSignature, "bad signature length")
            }
            SigCheckError::Invalid => SigError::new(
                SigErrorCode::InvalidSignature,
                "signature verification failed",
            ),
        })
}

/// The RFC 9530 `Content-Digest` value for a body: `sha-256=:<base64>:`.
pub fn content_digest_sha256(body: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(body);
    format!("sha-256=:{}:", b64::encode_std(&digest))
}

/// Verify a received `Content-Digest` header value against the body: every
/// recognized member (`sha-256`, `sha-512`) MUST match, and at least one
/// recognized member MUST be present. A covered `content-digest` binds the
/// signature to the header VALUE only; this is the step that binds the value
/// to the bytes.
pub fn verify_content_digest(header_value: &str, body: &[u8]) -> Result<(), SigError> {
    use sha2::Digest;
    let dict = sfv::parse_dictionary(header_value).map_err(|e| {
        SigError::new(
            SigErrorCode::InvalidSignature,
            format!("Content-Digest: {e}"),
        )
    })?;
    let mut recognized = 0usize;
    for (name, member) in &dict {
        let expected: Option<Vec<u8>> = match name.as_str() {
            "sha-256" => Some(sha2::Sha256::digest(body).to_vec()),
            "sha-512" => Some(sha2::Sha512::digest(body).to_vec()),
            _ => None,
        };
        let Some(expected) = expected else { continue };
        recognized += 1;
        match &member.value {
            MemberValue::Item(BareItem::Bytes(got), _) if *got == expected => {}
            _ => {
                return Err(SigError::new(
                    SigErrorCode::InvalidSignature,
                    format!("Content-Digest {name} does not match the body"),
                ));
            }
        }
    }
    if recognized == 0 {
        return Err(SigError::new(
            SigErrorCode::InvalidSignature,
            "Content-Digest carries no recognized algorithm (sha-256 / sha-512)",
        ));
    }
    Ok(())
}

/// The three headers produced by signing a request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub signature_input: String,
    pub signature: String,
    pub signature_key: String,
}

/// Sign a request per the AAuth profile.
///
/// `signature_key_value` is the full `Signature-Key` member value (e.g.
/// `jwt;jwt="eyJ..."` — see [`crate::sigkey`] serializers). `extra_covered`
/// names additional headers to cover; their values must be resolvable via
/// `header`.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    authority: &str,
    path: &str,
    query: &str,
    extra_covered: &[&str],
    header: &dyn Fn(&str) -> Option<String>,
    signature_key_value: &str,
    key: &SigningKey,
    created: u64,
) -> Result<SignedHeaders, SigError> {
    let signature_key_header = format!("sig={signature_key_value}");
    let mut covered: Vec<String> = REQUIRED_COMPONENTS.iter().map(|s| s.to_string()).collect();
    covered.extend(extra_covered.iter().map(|s| s.to_string()));

    let covered_refs: Vec<&str> = covered.iter().map(|s| s.as_str()).collect();
    let sig_params_raw = format!(
        "{};created={created}",
        sfv::serialize_string_list(&covered_refs)
    );

    let skh = signature_key_header.clone();
    let header_with_sigkey = move |name: &str| -> Option<String> {
        if name == "signature-key" {
            Some(skh.clone())
        } else {
            header(name)
        }
    };
    let parts = RequestParts {
        method,
        authority,
        path,
        query,
        header: &header_with_sigkey,
    };
    let base = build_signature_base(&covered, &sig_params_raw, &parts)?;
    let sig = key.sign(base.as_bytes());
    Ok(SignedHeaders {
        signature_input: format!("sig={sig_params_raw}"),
        signature: format!("sig=:{}:", b64::encode_std(&sig.to_bytes())),
        signature_key: signature_key_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::generate_signing_key;
    use crate::sigkey;
    use std::collections::HashMap;

    fn verify_roundtrip(extra: &[&str], headers: HashMap<String, String>) {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let hdrs = headers.clone();
        let lookup = move |name: &str| hdrs.get(name).cloned();
        let signed = sign_request(
            "POST",
            "ap.example",
            "/agent-token",
            "",
            extra,
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now,
        )
        .unwrap();

        let mut all = headers;
        all.insert("signature-input".into(), signed.signature_input);
        all.insert("signature".into(), signed.signature);
        all.insert("signature-key".into(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "POST",
            authority: "ap.example",
            path: "/agent-token",
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: extra.iter().map(|s| s.to_string()).collect(),
        };
        let parsed = parse_request_signature(&parts, &policy).unwrap();
        match &parsed.scheme {
            SigKeyScheme::Hwk(k) => assert_eq!(k.x, jwk.x),
            other => panic!("unexpected scheme {other:?}"),
        }
        verify_parsed(&parsed, &jwk).unwrap();
    }

    #[test]
    fn content_digest_roundtrip_and_tamper() {
        let body = br#"{"iss":"https://ps.example","jti":"at-1"}"#;
        let value = content_digest_sha256(body);
        assert!(value.starts_with("sha-256=:"), "{value}");
        verify_content_digest(&value, body).unwrap();
        assert_eq!(
            verify_content_digest(&value, b"tampered").unwrap_err().code,
            SigErrorCode::InvalidSignature
        );
        // Unrecognized-only algorithms cannot bind the body.
        assert!(verify_content_digest("md5=:AAAA:", body).is_err());
        // An unrecognized member alongside a matching sha-256 is fine.
        verify_content_digest(&format!("md5=:AAAA:, {value}"), body).unwrap();
    }

    #[test]
    fn jwks_uri_scheme_serializes_and_parses() {
        let member = sigkey::serialize_jwks_uri("https://ps.example", "aauth-person.json", "ps-1");
        let d = sfv::parse_dictionary(&format!("sig={member}")).unwrap();
        match sigkey::parse_member(&d[0].1.value).unwrap() {
            SigKeyScheme::JwksUri { id, dwk, kid } => {
                assert_eq!(id, "https://ps.example");
                assert_eq!(dwk, "aauth-person.json");
                assert_eq!(kid, "ps-1");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn sign_verify_roundtrip_basic() {
        verify_roundtrip(&[], HashMap::new());
    }

    #[test]
    fn sign_verify_with_extra_headers() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        verify_roundtrip(&["content-type"], headers);
    }

    #[test]
    fn tampered_path_fails() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let lookup = |_: &str| None;
        let signed = sign_request(
            "POST",
            "ap.example",
            "/a",
            "",
            &[],
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now,
        )
        .unwrap();
        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), signed.signature_input);
        all.insert("signature".to_string(), signed.signature);
        all.insert("signature-key".to_string(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "POST",
            authority: "ap.example",
            path: "/b", // tampered
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let parsed = parse_request_signature(&parts, &policy).unwrap();
        assert!(verify_parsed(&parsed, &jwk).is_err());
    }

    #[test]
    fn stale_created_rejected() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let lookup = |_: &str| None;
        let signed = sign_request(
            "GET",
            "ap.example",
            "/x",
            "",
            &[],
            &lookup,
            &sigkey::serialize_hwk(&jwk),
            &sk,
            now - 3600,
        )
        .unwrap();
        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), signed.signature_input);
        all.insert("signature".to_string(), signed.signature);
        all.insert("signature-key".to_string(), signed.signature_key);
        let lookup2 = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "GET",
            authority: "ap.example",
            path: "/x",
            query: "",
            header: &lookup2,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidSignature);
    }

    #[test]
    fn missing_required_component_reports_required_input() {
        // Hand-build a signature that omits signature-key from covered components.
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        let raw = format!("(\"@method\" \"@authority\" \"@path\");created={now}");
        let parts_for_base = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &|_| None,
        };
        let covered = vec![
            "@method".to_string(),
            "@authority".to_string(),
            "@path".to_string(),
        ];
        let base = build_signature_base(&covered, &raw, &parts_for_base).unwrap();
        use ed25519_dalek::Signer;
        let sig = sk.sign(base.as_bytes());

        let mut all = HashMap::new();
        all.insert("signature-input".to_string(), format!("sig={raw}"));
        all.insert(
            "signature".to_string(),
            format!("sig=:{}:", crate::b64::encode_std(&sig.to_bytes())),
        );
        all.insert(
            "signature-key".to_string(),
            format!("sig={}", sigkey::serialize_hwk(&jwk)),
        );
        let lookup = move |name: &str| all.get(name).cloned();
        let parts = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &lookup,
        };
        let policy = VerifyPolicy {
            now,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidInput);
        assert!(
            err.required_input
                .unwrap()
                .contains(&"signature-key".to_string())
        );
    }

    #[test]
    fn missing_signature_headers_are_invalid_request() {
        // AAuth core profile Verification step 1: absent headers → invalid_request.
        let lookup = |_: &str| None;
        let parts = RequestParts {
            method: "GET",
            authority: "a.example",
            path: "/x",
            query: "",
            header: &lookup,
        };
        let policy = VerifyPolicy {
            now: 1_750_000_000,
            window_secs: 60,
            extra_required: vec![],
        };
        let err = parse_request_signature(&parts, &policy).unwrap_err();
        assert_eq!(err.code, SigErrorCode::InvalidRequest);
    }

    /// signature-key-08 "Algorithm Selection": signers MUST NOT send the
    /// RFC 9421 `alg` signature parameter and verifiers MUST ignore it if
    /// present. A request carrying one — under ANY value, including a JOSE
    /// spelling or garbage — verifies exactly as if it were absent, because
    /// the algorithm comes from the key alone. `keyid`, `nonce`, and `tag`
    /// take the same ignored path.
    #[test]
    fn alg_and_keyid_params_are_ignored() {
        let sk = generate_signing_key();
        let jwk = Jwk::from_verifying_key(&sk.verifying_key());
        let now = 1_750_000_000u64;
        for params in [
            format!("created={now};alg=\"ed25519\""),
            format!("created={now};alg=\"Ed25519\""),
            format!("created={now};alg=\"rsa-pss-sha512\""),
            format!("created={now};keyid=\"k1\";nonce=\"n\";tag=\"t\""),
        ] {
            let raw = format!("(\"@method\" \"@authority\" \"@path\" \"signature-key\");{params}");
            let sig_key_member = sigkey::serialize_hwk(&jwk);
            let sig_key_header = format!("sig={sig_key_member}");
            let skh = sig_key_header.clone();
            let lookup = move |name: &str| (name == "signature-key").then(|| skh.clone());
            let parts_for_base = RequestParts {
                method: "GET",
                authority: "a.example",
                path: "/x",
                query: "",
                header: &lookup,
            };
            let covered: Vec<String> = REQUIRED_COMPONENTS.iter().map(|s| s.to_string()).collect();
            let base = build_signature_base(&covered, &raw, &parts_for_base).unwrap();
            let sig = sk.sign(base.as_bytes());

            let mut all = HashMap::new();
            all.insert("signature-input".to_string(), format!("sig={raw}"));
            all.insert(
                "signature".to_string(),
                format!("sig=:{}:", crate::b64::encode_std(&sig.to_bytes())),
            );
            all.insert("signature-key".to_string(), sig_key_header.clone());
            let lookup2 = move |name: &str| all.get(name).cloned();
            let parts = RequestParts {
                method: "GET",
                authority: "a.example",
                path: "/x",
                query: "",
                header: &lookup2,
            };
            let policy = VerifyPolicy {
                now,
                window_secs: 60,
                extra_required: vec![],
            };
            let parsed = parse_request_signature(&parts, &policy)
                .unwrap_or_else(|e| panic!("params `{params}` must parse: {e}"));
            verify_parsed(&parsed, &jwk)
                .unwrap_or_else(|e| panic!("params `{params}` must be ignored: {e}"));
        }
    }
}

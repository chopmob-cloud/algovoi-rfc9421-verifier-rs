//! RFC 9421 + RFC 9530 verification top-level. Faithful port of `verify.py`.
//!
//! Two entry points:
//!   - [`verify_signature`]: caller has already built the signing base.
//!   - [`verify_request`]: parses Signature-Input + Signature, builds the signing
//!     base, verifies the signature and the Content-Digest in one call.
//!
//! This core surface supports Ed25519 only. ECDSA lives in the separate
//! `algovoi-rfc9421-ecdsa` add-on crate, which reuses these primitives.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::content_digest::verify_content_digest;
use crate::freshness::{check_freshness, FreshnessOptions};
use crate::keycheck::{check_ed25519_public_key, WeakKeyError};
use crate::parse::{parse_signature_input, parse_signature_value, ParsedSignatureInput};
use crate::signing_base::{build_signing_base, Mode, ParamValue, SigningBaseInput};

/// Raised when verification setup is invalid (not when a signature merely fails
/// to verify, which is captured in [`VerifyResult::errors`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct VerifyError(pub String);

impl VerifyError {
    pub fn new(msg: impl Into<String>) -> Self {
        VerifyError(msg.into())
    }
}

impl From<WeakKeyError> for VerifyError {
    fn from(e: WeakKeyError) -> Self {
        VerifyError(e.to_string())
    }
}

/// Result of an RFC 9421 verification. `valid` is true only if every check ran
/// and every check passed.
#[derive(Debug, Clone, Default)]
pub struct VerifyResult {
    pub valid: bool,
    pub signature_valid: bool,
    pub content_digest_valid: bool,
    pub signing_base: String,
    pub covered_components: Vec<String>,
    pub parameters: Vec<(String, ParamValue)>,
    pub label: String,
    pub errors: Vec<String>,
}

impl VerifyResult {
    /// Record a failure message, clear `valid`, and return self (Python `.fail`).
    pub fn fail(mut self, msg: impl Into<String>) -> Self {
        self.errors.push(msg.into());
        self.valid = false;
        self
    }
}

/// Validate and normalise a raw Ed25519 public key (must be 32 bytes).
pub fn public_key_bytes(public_key: &[u8]) -> Result<[u8; 32], VerifyError> {
    if public_key.len() != 32 {
        return Err(VerifyError::new(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(public_key);
    Ok(out)
}

/// Parse a hex (optionally `0x`-prefixed) Ed25519 public key into 32 bytes.
pub fn public_key_from_hex(hex_str: &str) -> Result<[u8; 32], VerifyError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = decode_hex(stripped)
        .map_err(|e| VerifyError::new(format!("public key hex is invalid: {e}")))?;
    if bytes.len() != 32 {
        return Err(VerifyError::new(format!(
            "Ed25519 public key hex must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit {:?}", bytes[i] as char))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit {:?}", bytes[i + 1] as char))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Verify an Ed25519 signature over the signing base. Faithful port of
/// `verify_signature`.
///
/// Returns `Ok(true)` on success, `Ok(false)` on signature mismatch, `Err` on
/// invalid inputs (wrong algorithm, bad key/signature shape, weak key).
pub fn verify_signature(
    signing_base: &str,
    signature_bytes: &[u8],
    public_key: &[u8],
    algorithm: &str,
) -> Result<bool, VerifyError> {
    if algorithm.to_lowercase() != "ed25519" {
        return Err(VerifyError::new(format!(
            "core supports ed25519 only; got {algorithm:?}"
        )));
    }
    if signature_bytes.len() != 64 {
        return Err(VerifyError::new(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let pk_bytes = public_key_bytes(public_key)?;

    // Trust-boundary key gate before verification.
    check_ed25519_public_key(&pk_bytes)?;

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| VerifyError::new(format!("public key is not a valid Ed25519 point: {e}")))?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(signing_base.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Options for [`verify_request`], mirroring the Python keyword arguments.
pub struct VerifyRequestOptions<'a> {
    pub scheme: &'a str,
    pub require_content_digest: bool,
    pub require_algorithm: Option<&'a str>,
    pub mode: Mode,
    pub now: Option<i64>,
    pub max_age_seconds: Option<i64>,
    pub max_skew_seconds: i64,
    pub enforce_expires: bool,
    pub require_created: bool,
    pub expected_tag: Option<&'a str>,
    pub require_tag: bool,
    pub allowed_algorithms: Vec<String>,
}

impl<'a> Default for VerifyRequestOptions<'a> {
    fn default() -> Self {
        VerifyRequestOptions {
            scheme: "https",
            require_content_digest: true,
            require_algorithm: None,
            mode: Mode::Rfc9421,
            now: None,
            max_age_seconds: None,
            max_skew_seconds: 60,
            enforce_expires: true,
            require_created: false,
            expected_tag: None,
            require_tag: false,
            allowed_algorithms: vec!["ed25519".to_string()],
        }
    }
}

/// A parsed request whose common (algorithm-independent) checks have passed,
/// ready for the algorithm-specific signature verification. Used by the ECDSA
/// add-on to reuse the core pipeline without duplicating it.
pub struct PreparedRequest {
    pub parsed: ParsedSignatureInput,
    pub sig_bytes: Vec<u8>,
    pub signing_base: String,
    pub result: VerifyResult,
    pub alg: String,
}

/// Run every algorithm-independent step of request verification: locate and
/// parse the headers, freshness, tag policy, content-digest coverage, signing
/// base construction, and the alg allow-list. On success returns a
/// [`PreparedRequest`]; on any failure returns the failed [`VerifyResult`].
///
/// This is the shared spine reused by both the core Ed25519 [`verify_request`]
/// and the ECDSA add-on.
///
/// The `Err` variant deliberately carries the full [`VerifyResult`] by value so
/// the caller can return it verbatim, mirroring the reference Python which
/// returns the failed result object.
#[allow(clippy::result_large_err)]
pub fn prepare_request(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    opts: &VerifyRequestOptions,
) -> Result<PreparedRequest, VerifyResult> {
    let mut result = VerifyResult::default();

    let norm: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let si_value = match norm.get("signature-input") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Err(result.fail("Signature-Input header missing")),
    };
    let s_value = match norm.get("signature") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Err(result.fail("Signature header missing")),
    };

    let parsed = match parse_signature_input(&si_value) {
        Ok(p) => p,
        Err(e) => return Err(result.fail(format!("Signature-Input parse error: {e}"))),
    };
    result.label = parsed.label.clone();
    result.covered_components = parsed.covered_components.clone();
    result.parameters = parsed.parameters.clone();

    let (s_label, sig_bytes) = match parse_signature_value(&s_value) {
        Ok(v) => v,
        Err(e) => return Err(result.fail(format!("Signature parse error: {e}"))),
    };
    if !s_label.is_empty() && !parsed.label.is_empty() && s_label != parsed.label {
        return Err(result.fail(format!(
            "Signature label {s_label:?} does not match Signature-Input label {:?}",
            parsed.label
        )));
    }

    // Freshness / replay window, before the cryptographic check.
    let now = opts.now.unwrap_or_else(current_unix_time);
    let fopts = FreshnessOptions {
        now,
        max_age_seconds: opts.max_age_seconds,
        max_skew_seconds: opts.max_skew_seconds,
        enforce_expires: opts.enforce_expires,
        require_created: opts.require_created,
        params_signed: opts.mode == Mode::Rfc9421,
    };
    if let Err(e) = check_freshness(&parsed.parameters, parsed.covered_components.iter(), &fopts) {
        return Err(result.fail(format!("Freshness check failed: {e}")));
    }

    // Anti cross-protocol reuse via the `tag` parameter.
    let tag_value = parsed.parameter("tag");
    if opts.require_tag && tag_value.is_none() {
        return Err(result.fail("Signature 'tag' parameter required but absent"));
    }
    if let Some(expected) = opts.expected_tag {
        let matches = matches!(tag_value, Some(ParamValue::Str(s)) if s == expected);
        if !matches {
            let got = tag_value.map(|v| v.as_signing_str());
            return Err(result.fail(format!(
                "Signature 'tag' {got:?} does not match expected {expected:?}"
            )));
        }
    }

    if opts.require_content_digest {
        let cd_header = match norm.get("content-digest") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return Err(result.fail("Content-Digest header required but missing")),
        };
        let covered: Vec<String> = parsed
            .covered_components
            .iter()
            .map(|c| c.to_lowercase().trim().trim_matches('"').to_string())
            .collect();
        if !covered.iter().any(|c| c == "content-digest") {
            return Err(result.fail("Content-Digest required but not a covered signature component"));
        }
        match verify_content_digest(body, &cd_header, opts.require_algorithm) {
            Ok(()) => result.content_digest_valid = true,
            Err(e) => return Err(result.fail(format!("Content-Digest verification failed: {e}"))),
        }
    } else {
        result.content_digest_valid = true;
    }

    // Build the signing base.
    let params_map: HashMap<String, ParamValue> = parsed
        .parameters
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let sb_input = SigningBaseInput {
        covered_components: parsed.covered_components.clone(),
        method: Some(method),
        authority: Some(authority),
        path: Some(path),
        target_uri: None,
        scheme: Some(opts.scheme),
        status: None,
        headers: norm.clone(),
        parameters: params_map,
        mode: opts.mode,
        signature_params_raw: if opts.mode == Mode::Rfc9421 {
            Some(parsed.params_block.clone())
        } else {
            None
        },
    };
    let signing_base = match build_signing_base(&sb_input) {
        Ok(sb) => sb,
        Err(e) => return Err(result.fail(format!("Signing-base build error: {e}"))),
    };
    result.signing_base = signing_base.clone();

    // Algorithm-downgrade hardening: reject a missing alg; pin to the allow-list.
    let alg = match parsed.parameter("alg") {
        None => return Err(result.fail("Signature-Input missing 'alg' parameter")),
        Some(ParamValue::Int(_)) => {
            return Err(result.fail("Signature-Input 'alg' parameter must be string, got int"))
        }
        Some(ParamValue::Str(s)) => s.clone(),
    };
    let allowed: Vec<String> = opts
        .allowed_algorithms
        .iter()
        .map(|a| a.to_lowercase())
        .collect();
    if !allowed.contains(&alg.to_lowercase()) {
        let mut sorted = opts.allowed_algorithms.clone();
        sorted.sort();
        return Err(result.fail(format!(
            "Signature algorithm {alg:?} is not in the allowed set {sorted:?}"
        )));
    }

    Ok(PreparedRequest {
        parsed,
        sig_bytes,
        signing_base,
        result,
        alg,
    })
}

/// High-level verification of an RFC 9421-signed HTTP request (Ed25519). Faithful
/// port of `verify_request` for the core's single supported algorithm.
pub fn verify_request(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    public_key: &[u8],
    opts: &VerifyRequestOptions,
) -> VerifyResult {
    let prepared = match prepare_request(method, authority, path, headers, body, opts) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let PreparedRequest {
        sig_bytes,
        signing_base,
        mut result,
        alg,
        ..
    } = prepared;

    match verify_signature(&signing_base, &sig_bytes, public_key, &alg) {
        Ok(true) => result.signature_valid = true,
        Ok(false) => {
            return result.fail("Ed25519 signature does not verify against signing base")
        }
        Err(e) => return result.fail(format!("Signature verification setup error: {e}")),
    }

    result.valid = result.signature_valid && result.content_digest_valid;
    result
}

fn current_unix_time() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

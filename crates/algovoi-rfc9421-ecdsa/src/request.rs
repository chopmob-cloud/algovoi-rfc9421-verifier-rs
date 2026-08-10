//! Pure-wrapper RFC 9421 request verification with ECDSA support.
//!
//! Faithful port of the reference `request.py`. This does NOT modify or
//! re-publish the core verifier. Ed25519 requests are delegated verbatim to the
//! untouched `algovoi-rfc9421-verifier`; ECDSA requests reuse the core's already
//! hardened primitives (Signature-Input parsing, freshness, Content-Digest,
//! signing-base construction, downgrade/allow-list) and add only the ECDSA
//! signature check.

use std::collections::HashMap;

use algovoi_rfc9421_verifier::{
    build_signing_base, check_freshness, parse_signature_input, parse_signature_value,
    public_key_from_hex, verify_content_digest, verify_request as core_verify_request, FreshnessOptions,
    Mode, ParamValue, SigningBaseInput, VerifyRequestOptions, VerifyResult,
};

use crate::verify::{verify_p256, verify_p384, ECDSAError, PublicKeyInput};

/// Default accepted algorithms: Ed25519 (via core) plus the ECDSA suites.
pub fn default_allowed() -> Vec<String> {
    vec![
        "ed25519".to_string(),
        "ecdsa-p256-sha256".to_string(),
        "ecdsa-p384-sha384".to_string(),
    ]
}

/// Options for [`verify_request`]. Same as the core's, but the default
/// `allowed_algorithms` is the Ed25519 + ECDSA set.
pub struct EcdsaRequestOptions<'a> {
    pub inner: VerifyRequestOptions<'a>,
}

impl<'a> Default for EcdsaRequestOptions<'a> {
    fn default() -> Self {
        let inner = VerifyRequestOptions {
            allowed_algorithms: default_allowed(),
            ..VerifyRequestOptions::default()
        };
        EcdsaRequestOptions { inner }
    }
}

fn current_unix_time() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verify an RFC 9421 request signed with Ed25519 or ECDSA (P-256/P-384).
///
/// Same semantics as the core `verify_request`, extended to ECDSA. Faithful port
/// of the reference `request.py`.
pub fn verify_request(
    method: &str,
    authority: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    public_key: &PublicKeyInput,
    opts: &EcdsaRequestOptions,
) -> VerifyResult {
    let norm: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let si_value = match norm.get("signature-input") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return VerifyResult::default().fail("Signature-Input header missing"),
    };
    let parsed = match parse_signature_input(&si_value) {
        Ok(p) => p,
        Err(e) => {
            return VerifyResult::default().fail(format!("Signature-Input parse error: {e}"))
        }
    };

    let alg = parsed.parameter("alg").cloned();

    // Ed25519 -> delegate entirely to the untouched core verifier.
    if let Some(ParamValue::Str(ref a)) = alg {
        if a.to_lowercase() == "ed25519" {
            let pk_bytes = match public_key {
                PublicKeyInput::Bytes(b) => b.clone(),
                PublicKeyInput::Hex(s) => match public_key_from_hex(s) {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        return VerifyResult::default()
                            .fail(format!("Signature verification setup error: {e}"))
                    }
                },
            };
            return core_verify_request(
                method,
                authority,
                path,
                headers,
                body,
                &pk_bytes,
                &opts.inner,
            );
        }
    }

    // ECDSA path: reuse the core's hardened primitives, add the ECDSA check.
    let mut result = VerifyResult {
        label: parsed.label.clone(),
        covered_components: parsed.covered_components.clone(),
        parameters: parsed.parameters.clone(),
        ..Default::default()
    };

    let s_value = match norm.get("signature") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return result.fail("Signature header missing"),
    };
    let (s_label, sig_bytes) = match parse_signature_value(&s_value) {
        Ok(v) => v,
        Err(e) => return result.fail(format!("Signature parse error: {e}")),
    };
    if !s_label.is_empty() && !parsed.label.is_empty() && s_label != parsed.label {
        return result.fail(format!(
            "Signature label {s_label:?} does not match Signature-Input label {:?}",
            parsed.label
        ));
    }

    let now = opts.inner.now.unwrap_or_else(current_unix_time);
    let fopts = FreshnessOptions {
        now,
        max_age_seconds: opts.inner.max_age_seconds,
        max_skew_seconds: opts.inner.max_skew_seconds,
        enforce_expires: opts.inner.enforce_expires,
        require_created: opts.inner.require_created,
        params_signed: opts.inner.mode == Mode::Rfc9421,
    };
    if let Err(e) = check_freshness(&parsed.parameters, parsed.covered_components.iter(), &fopts) {
        return result.fail(format!("Freshness check failed: {e}"));
    }

    let tag_value = parsed.parameter("tag");
    if opts.inner.require_tag && tag_value.is_none() {
        return result.fail("Signature 'tag' parameter required but absent");
    }
    if let Some(expected) = opts.inner.expected_tag {
        let matches = matches!(tag_value, Some(ParamValue::Str(s)) if s == expected);
        if !matches {
            let got = tag_value.map(|v| v.as_signing_str());
            return result.fail(format!(
                "Signature 'tag' {got:?} does not match expected {expected:?}"
            ));
        }
    }

    // Note: mirroring the reference add-on, the ECDSA path does NOT require
    // content-digest to be a covered component (the core Ed25519 path does).
    if opts.inner.require_content_digest {
        let cd = match norm.get("content-digest") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return result.fail("Content-Digest header required but missing"),
        };
        match verify_content_digest(body, &cd, opts.inner.require_algorithm) {
            Ok(()) => result.content_digest_valid = true,
            Err(e) => return result.fail(format!("Content-Digest verification failed: {e}")),
        }
    } else {
        result.content_digest_valid = true;
    }

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
        scheme: Some(opts.inner.scheme),
        status: None,
        headers: norm.clone(),
        parameters: params_map,
        mode: opts.inner.mode,
        signature_params_raw: if opts.inner.mode == Mode::Rfc9421 {
            Some(parsed.params_block.clone())
        } else {
            None
        },
    };
    let signing_base = match build_signing_base(&sb_input) {
        Ok(sb) => sb,
        Err(e) => return result.fail(format!("Signing-base build error: {e}")),
    };
    result.signing_base = signing_base.clone();

    // Algorithm-downgrade hardening: reject a missing alg; pin to the allow-list.
    let alg_str = match &alg {
        None => return result.fail("Signature-Input missing 'alg' parameter"),
        Some(ParamValue::Int(_)) => {
            return result.fail("Signature-Input 'alg' parameter must be string, got int")
        }
        Some(ParamValue::Str(s)) => s.clone(),
    };
    let allowed: Vec<String> = opts
        .inner
        .allowed_algorithms
        .iter()
        .map(|a| a.to_lowercase())
        .collect();
    if !allowed.contains(&alg_str.to_lowercase()) {
        let mut sorted = opts.inner.allowed_algorithms.clone();
        sorted.sort();
        return result.fail(format!(
            "Signature algorithm {alg_str:?} is not in the allowed set {sorted:?}"
        ));
    }

    let sig_ok: Result<bool, ECDSAError> = match alg_str.to_lowercase().as_str() {
        "ecdsa-p256-sha256" => verify_p256(&signing_base, &sig_bytes, public_key),
        "ecdsa-p384-sha384" => verify_p384(&signing_base, &sig_bytes, public_key),
        _ => {
            return result.fail(format!(
                "no ECDSA verifier available for algorithm {alg_str:?}"
            ))
        }
    };
    match sig_ok {
        Ok(true) => result.signature_valid = true,
        Ok(false) => return result.fail("ECDSA signature does not verify against signing base"),
        Err(e) => return result.fail(format!("Signature verification setup error: {e}")),
    }

    result.valid = result.signature_valid && result.content_digest_valid;
    result
}

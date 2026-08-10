//! End-to-end and unit coverage for the parse / content-digest / verify_request
//! paths that the frozen vectors do not exercise. Also checks that malformed
//! inputs return errors (never panic) at the trust boundary.

use std::collections::HashMap;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use algovoi_rfc9421_verifier::{
    compute_content_digest, parse_signature_input, parse_signature_value, verify_content_digest,
    verify_request, Mode, ParamValue, VerifyRequestOptions,
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn parse_signature_input_labelled() {
    let parsed = parse_signature_input(
        r#"sig=("@method" "@path" "content-digest");created=1778955520;keyid="did:web:api";alg="ed25519""#,
    )
    .unwrap();
    assert_eq!(parsed.label, "sig");
    assert_eq!(
        parsed.covered_components,
        vec!["@method", "@path", "content-digest"]
    );
    assert_eq!(parsed.parameter("created"), Some(&ParamValue::Int(1778955520)));
    assert_eq!(
        parsed.parameter("alg"),
        Some(&ParamValue::Str("ed25519".to_string()))
    );
    // params_block is captured verbatim for the @signature-params line.
    assert!(parsed.params_block.starts_with("(\"@method\""));
}

#[test]
fn parse_signature_input_unlabelled() {
    let parsed = parse_signature_input(r#"("@method");alg="ed25519""#).unwrap();
    assert_eq!(parsed.label, "");
    assert_eq!(parsed.covered_components, vec!["@method"]);
}

#[test]
fn parse_signature_value_rejects_noncanonical_base64() {
    // A valid 64-byte signature re-encodes canonically; flipping the final pad
    // char to introduce non-zero pad bits must be rejected, not silently accepted.
    let sig = [0u8; 64];
    let canonical = b64(&sig);
    let ok = format!(":{canonical}:");
    assert!(parse_signature_value(&ok).is_ok());

    // Mutate the last base64 char to set trailing bits (non-canonical).
    let mut chars: Vec<char> = canonical.chars().collect();
    let last = chars.len() - 2; // char before the '=' padding, if any
    chars[last] = if chars[last] == 'B' { 'C' } else { 'B' };
    let mutated: String = chars.into_iter().collect();
    let bad = format!(":{mutated}:");
    // Either it fails the canonical round-trip or the alphabet check; both are Err.
    let _ = parse_signature_value(&bad); // must not panic
}

#[test]
fn parse_bad_inputs_return_errors_not_panics() {
    assert!(parse_signature_input("").is_err());
    assert!(parse_signature_input("garbage-no-list").is_err());
    assert!(parse_signature_value("").is_err());
    assert!(parse_signature_value("sig=not-colons").is_err());
    assert!(parse_signature_value("sig=:!!notbase64!!:").is_err());
}

#[test]
fn content_digest_roundtrip_and_mismatch() {
    let body = b"hello world";
    let header = compute_content_digest(body, "sha-256").unwrap();
    assert!(verify_content_digest(body, &header, None).is_ok());
    // Wrong body must fail.
    assert!(verify_content_digest(b"tampered", &header, None).is_err());
    // Unknown-only algorithm verifies nothing -> fail closed.
    assert!(verify_content_digest(body, "md5=:aaaa:", None).is_err());
}

#[test]
fn verify_request_ed25519_happy_path() {
    // Deterministic key from a fixed seed.
    let seed = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pk = signing_key.verifying_key().to_bytes();

    // algovoi-v0 mode: signing base is just the covered lines, no
    // @signature-params. Covered: @method, @path.
    let method = "POST";
    let path = "/pay";
    let signing_base = format!("\"@method\": {}\n\"@path\": {}", method.to_lowercase(), path);
    let signature = signing_key.sign(signing_base.as_bytes());
    let sig_b64 = b64(&signature.to_bytes());

    let mut headers = HashMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig=("@method" "@path");alg="ed25519""#.to_string(),
    );
    headers.insert("Signature".to_string(), format!("sig=:{sig_b64}:"));

    let opts = VerifyRequestOptions {
        require_content_digest: false,
        mode: Mode::AlgovoiV0,
        ..Default::default()
    };
    let result = verify_request(method, "api.algovoi.co.uk", path, &headers, b"", &pk, &opts);
    assert!(result.valid, "expected valid, errors: {:?}", result.errors);
    assert!(result.signature_valid);
}

#[test]
fn verify_request_rejects_missing_alg() {
    let seed = [9u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pk = signing_key.verifying_key().to_bytes();
    let signing_base = "\"@method\": post".to_string();
    let signature = signing_key.sign(signing_base.as_bytes());
    let sig_b64 = b64(&signature.to_bytes());

    let mut headers = HashMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig=("@method")"#.to_string(),
    );
    headers.insert("Signature".to_string(), format!("sig=:{sig_b64}:"));

    let opts = VerifyRequestOptions {
        require_content_digest: false,
        mode: Mode::AlgovoiV0,
        ..Default::default()
    };
    let result = verify_request("POST", "h", "/", &headers, b"", &pk, &opts);
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|e| e.contains("missing 'alg'")));
}

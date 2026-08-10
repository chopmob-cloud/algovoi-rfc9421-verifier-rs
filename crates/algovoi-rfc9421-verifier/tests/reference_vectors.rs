//! Frozen reference-vector conformance test.
//!
//! Loads the frozen `reference_vectors_v0.json` (from py verifier 0.4.2) and
//! asserts the Rust port reproduces every case byte for byte:
//!   - signing_base: exact bytes
//!   - keygate: exact accept/reject decision (and small-order classification)
//!   - ed25519_verify: exact valid/invalid decision

use std::collections::HashMap;

use base64::Engine;
use serde_json::Value;

use algovoi_rfc9421_verifier::{
    build_signing_base, check_ed25519_public_key, is_small_order, verify_signature, Mode,
    ParamValue, SigningBaseInput,
};

fn load_vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/reference_vectors_v0.json"
    );
    let text = std::fs::read_to_string(path).expect("read reference vectors");
    serde_json::from_str(&text).expect("parse reference vectors")
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("valid base64 in vector")
}

fn value_to_param(v: &Value) -> ParamValue {
    if let Some(i) = v.as_i64() {
        ParamValue::Int(i)
    } else if let Some(s) = v.as_str() {
        ParamValue::Str(s.to_string())
    } else {
        ParamValue::Str(v.to_string())
    }
}

#[test]
fn signing_base_vectors() {
    let vectors = load_vectors();
    let cases = vectors["signing_base"].as_array().expect("signing_base array");
    let mut passed = 0usize;
    let total = cases.len();

    for (idx, case) in cases.iter().enumerate() {
        let input = &case["in"];
        let mode = Mode::parse(case["mode"].as_str().unwrap()).expect("valid mode");

        let covered: Vec<String> = input["covered_components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();

        let headers: HashMap<String, String> = input
            .get("headers")
            .and_then(|h| h.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let parameters: HashMap<String, ParamValue> = input
            .get("parameters")
            .and_then(|p| p.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), value_to_param(v)))
                    .collect()
            })
            .unwrap_or_default();

        let method = input.get("method").and_then(|v| v.as_str());
        let authority = input.get("authority").and_then(|v| v.as_str());
        let path = input.get("path").and_then(|v| v.as_str());
        let target_uri = input.get("target_uri").and_then(|v| v.as_str());
        let scheme = input.get("scheme").and_then(|v| v.as_str());
        let status = input.get("status").and_then(|v| v.as_i64());
        let signature_params_raw = case
            .get("signature_params_raw")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let sb_input = SigningBaseInput {
            covered_components: covered,
            method,
            authority,
            path,
            target_uri,
            scheme,
            status,
            headers,
            parameters,
            mode,
            signature_params_raw,
        };

        let got = build_signing_base(&sb_input).expect("build signing base");
        let expected = b64_decode(case["signing_base_b64"].as_str().unwrap());
        assert_eq!(
            got.as_bytes(),
            expected.as_slice(),
            "signing_base case {idx} mismatch.\n  got:      {:?}\n  expected: {:?}",
            got,
            String::from_utf8_lossy(&expected)
        );
        passed += 1;
    }

    println!("signing_base: {passed}/{total} passed");
    assert_eq!(passed, total);
}

#[test]
fn keygate_vectors() {
    let vectors = load_vectors();
    let cases = vectors["keygate"].as_array().expect("keygate array");
    let mut passed = 0usize;
    let total = cases.len();

    for (idx, case) in cases.iter().enumerate() {
        let pk = hex::decode(case["pk_hex"].as_str().unwrap()).expect("hex pk");
        let expect_rejected = !case["rejected"].is_null();
        let expect_small_order = case["small_order"].as_bool().unwrap();

        let decision = check_ed25519_public_key(&pk);
        let rejected = decision.is_err();
        assert_eq!(
            rejected, expect_rejected,
            "keygate case {idx} rejection mismatch (pk={})",
            case["pk_hex"]
        );

        let small = is_small_order(&pk);
        assert_eq!(
            small, expect_small_order,
            "keygate case {idx} small_order mismatch (pk={})",
            case["pk_hex"]
        );
        passed += 1;
    }

    println!("keygate: {passed}/{total} passed");
    assert_eq!(passed, total);
}

#[test]
fn ed25519_verify_vectors() {
    let vectors = load_vectors();
    let cases = vectors["ed25519_verify"].as_array().expect("ed25519_verify array");
    let mut passed = 0usize;
    let total = cases.len();

    for (idx, case) in cases.iter().enumerate() {
        let sb_bytes = b64_decode(case["signing_base_b64"].as_str().unwrap());
        let signing_base = String::from_utf8(sb_bytes).expect("utf-8 signing base");
        let sig = hex::decode(case["sig_hex"].as_str().unwrap()).expect("hex sig");
        let pk = hex::decode(case["pk_hex"].as_str().unwrap()).expect("hex pk");
        let expect_valid = case["expect_valid"].as_bool().unwrap();

        let got = verify_signature(&signing_base, &sig, &pk, "ed25519")
            .expect("verify_signature setup ok");
        assert_eq!(got, expect_valid, "ed25519_verify case {idx} mismatch");
        passed += 1;
    }

    println!("ed25519_verify: {passed}/{total} passed");
    assert_eq!(passed, total);
}

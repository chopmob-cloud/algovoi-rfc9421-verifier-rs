//! ECDSA add-on unit tests: P-256 and P-384, valid + tampered, using the
//! `p256`/`p384` crates to generate key/signature pairs.

use algovoi_rfc9421_ecdsa::{
    set_strict_low_s, verify_p256, verify_p384, EcdsaRequestOptions, PublicKeyInput,
};

const SIGNING_BASE: &str = "\"@method\": POST\n\"@path\": /pay\n\"@authority\": api.algovoi.co.uk";

#[test]
fn p256_valid_and_tampered() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let sig: Signature = sk.sign(SIGNING_BASE.as_bytes());
    let raw = sig.to_bytes(); // 64-byte r||s
    assert_eq!(raw.len(), 64);

    let pk = PublicKeyInput::Bytes(vk.to_encoded_point(false).as_bytes().to_vec());

    // Valid.
    assert_eq!(
        verify_p256(SIGNING_BASE, &raw, &pk),
        Ok(true),
        "valid P-256 signature must verify"
    );

    // Tampered signature byte.
    let mut bad = raw.to_vec();
    bad[0] ^= 0x01;
    assert_eq!(
        verify_p256(SIGNING_BASE, &bad, &pk),
        Ok(false),
        "tampered P-256 signature must not verify"
    );

    // Tampered message.
    assert_eq!(
        verify_p256("different signing base", &raw, &pk),
        Ok(false),
        "P-256 signature over a different base must not verify"
    );

    // Also accept compressed SEC1 public keys.
    let pk_compressed = PublicKeyInput::Bytes(vk.to_encoded_point(true).as_bytes().to_vec());
    assert_eq!(verify_p256(SIGNING_BASE, &raw, &pk_compressed), Ok(true));

    // And hex-encoded keys.
    let pk_hex = PublicKeyInput::Hex(hex_encode(vk.to_encoded_point(false).as_bytes()));
    assert_eq!(verify_p256(SIGNING_BASE, &raw, &pk_hex), Ok(true));
}

#[test]
fn p256_wrong_length_errors() {
    let pk = PublicKeyInput::Bytes(vec![0x04; 65]);
    assert!(
        verify_p256(SIGNING_BASE, &[0u8; 10], &pk).is_err(),
        "wrong signature length must be a setup error"
    );
}

#[test]
fn p256_zero_scalar_rejected() {
    // r||s all zero: r and s are zero, out of [1, n-1] -> Ok(false), no panic.
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::OsRng;
    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let _sig: Signature = sk.sign(SIGNING_BASE.as_bytes());
    let pk = PublicKeyInput::Bytes(vk.to_encoded_point(false).as_bytes().to_vec());
    let zero = [0u8; 64];
    assert_eq!(verify_p256(SIGNING_BASE, &zero, &pk), Ok(false));
}

#[test]
fn p384_valid_and_tampered() {
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::{Signature, SigningKey};
    use rand_core::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let sig: Signature = sk.sign(SIGNING_BASE.as_bytes());
    let raw = sig.to_bytes(); // 96-byte r||s
    assert_eq!(raw.len(), 96);

    let pk = PublicKeyInput::Bytes(vk.to_encoded_point(false).as_bytes().to_vec());

    assert_eq!(
        verify_p384(SIGNING_BASE, &raw, &pk),
        Ok(true),
        "valid P-384 signature must verify"
    );

    let mut bad = raw.to_vec();
    bad[0] ^= 0x01;
    assert_eq!(
        verify_p384(SIGNING_BASE, &bad, &pk),
        Ok(false),
        "tampered P-384 signature must not verify"
    );

    assert_eq!(
        verify_p384("different signing base", &raw, &pk),
        Ok(false),
        "P-384 signature over a different base must not verify"
    );
}

#[test]
fn p384_wrong_length_errors() {
    let pk = PublicKeyInput::Bytes(vec![0x04; 97]);
    assert!(verify_p384(SIGNING_BASE, &[0u8; 64], &pk).is_err());
}

#[test]
fn strict_low_s_toggle_is_available() {
    // Default off; toggling must not panic and must be observable.
    set_strict_low_s(true);
    assert!(algovoi_rfc9421_ecdsa::strict_low_s());
    set_strict_low_s(false);
    assert!(!algovoi_rfc9421_ecdsa::strict_low_s());
}

#[test]
fn default_options_allow_all_three_algs() {
    let opts = EcdsaRequestOptions::default();
    let allowed = &opts.inner.allowed_algorithms;
    assert!(allowed.iter().any(|a| a == "ed25519"));
    assert!(allowed.iter().any(|a| a == "ecdsa-p256-sha256"));
    assert!(allowed.iter().any(|a| a == "ecdsa-p384-sha384"));
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

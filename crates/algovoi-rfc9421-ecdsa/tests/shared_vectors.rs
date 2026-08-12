//! Cross-language ECDSA differential test against the SHARED reference vectors.
//!
//! Loads `reference_ecdsa_v0.json` (the same file the Go/Python/TS add-ons run
//! against) and asserts that this crate's `verify_p256` / `verify_p384` agree
//! with `expect_valid` for every entry: valid vectors verify true, tampered
//! vectors verify false. Passing this in both Rust and Go proves cross-language
//! ECDSA parity against one shared set.
//!
//! The message (`msg_hex`) is the raw signing base the add-on verifies over; the
//! public API hashes it internally (SHA-256 for P-256, SHA-384 for P-384), so we
//! pass the decoded message bytes as the signing base and let the crate hash.

use algovoi_rfc9421_ecdsa::{verify_p256, verify_p384, PublicKeyInput};
use serde::Deserialize;

// Locate the shared reference vectors at RUNTIME (not via a compile-time
// include_str!, which would make the whole crate fail to build when the
// multilang repo is absent). Default: the multilang repo checked out alongside
// this one, resolved from this crate's manifest dir so it is independent of the
// working directory. Override with ALGOVOI_REFERENCE_ECDSA_VECTORS. When neither
// resolves, the test skips rather than fails, so `cargo test` stays green
// without that third checkout.
fn vectors_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ALGOVOI_REFERENCE_ECDSA_VECTORS") {
        return std::path::PathBuf::from(p);
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../algovoi-rfc9421-verifier-multilang/vectors/reference_ecdsa_v0.json")
}

#[derive(Debug, Deserialize)]
struct Vector {
    msg_hex: String,
    pub_uncompressed_hex: String,
    sig_raw_hex: String,
    expect_valid: bool,
}

#[derive(Debug, Deserialize)]
struct Vectors {
    p256: Vec<Vector>,
    p384: Vec<Vector>,
}

fn run(
    vectors: &[Vector],
    verify: impl Fn(&str, &[u8], &PublicKeyInput) -> Result<bool, algovoi_rfc9421_ecdsa::ECDSAError>,
    label: &str,
) -> (usize, usize) {
    let total = vectors.len();
    let mut passed = 0usize;
    for (i, v) in vectors.iter().enumerate() {
        let msg_bytes = hex::decode(&v.msg_hex).expect("msg_hex must be valid hex");
        let msg = std::str::from_utf8(&msg_bytes)
            .expect("shared vector message is expected to be UTF-8 signing-base text");
        let sig = hex::decode(&v.sig_raw_hex).expect("sig_raw_hex must be valid hex");
        let pk = PublicKeyInput::Bytes(
            hex::decode(&v.pub_uncompressed_hex).expect("pub_uncompressed_hex must be valid hex"),
        );

        let got = match verify(msg, &sig, &pk) {
            Ok(b) => b,
            Err(e) => panic!("{label}[{i}]: unexpected setup error: {e}"),
        };
        assert_eq!(
            got, v.expect_valid,
            "{label}[{i}]: verify returned {got}, expected {}",
            v.expect_valid
        );
        passed += 1;
    }
    (passed, total)
}

#[test]
fn shared_vectors_cross_language_parity() {
    let path = vectors_path();
    let json = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        // Multilang repo not checked out: skip (a no-op test passes) rather than
        // fail. Set ALGOVOI_REFERENCE_ECDSA_VECTORS to run it.
        Err(_) => {
            eprintln!(
                "skipping shared_vectors: reference_ecdsa_v0.json not found at {} \
                 (set ALGOVOI_REFERENCE_ECDSA_VECTORS to run)",
                path.display()
            );
            return;
        }
    };
    let vectors: Vectors =
        serde_json::from_str(&json).expect("reference_ecdsa_v0.json must parse");

    let (p256_pass, p256_total) = run(&vectors.p256, verify_p256, "p256");
    let (p384_pass, p384_total) = run(&vectors.p384, verify_p384, "p384");

    eprintln!("shared_vectors: p256 {p256_pass}/{p256_total}, p384 {p384_pass}/{p384_total}");
    assert_eq!(p256_pass, p256_total, "all p256 shared vectors must match");
    assert_eq!(p384_pass, p384_total, "all p384 shared vectors must match");
}

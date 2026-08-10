//! AlgoVoi RFC 9421 verifier core (Rust).
//!
//! A faithful Rust port of the AlgoVoi RFC 9421 verifier: Ed25519 signature
//! verification with a trust-boundary public-key gate, RFC 9421 Section 2.5
//! signing-base construction, Signature-Input / Signature parsing, RFC 9530
//! Content-Digest verification, and signature freshness checks.
//!
//! This is the CORE crate. ECDSA (P-256/P-384) lives in the separate
//! `algovoi-rfc9421-ecdsa` add-on crate, which depends on this core. The core
//! never depends on the add-on (mirroring the Python/TypeScript "pure add-on"
//! architecture).
//!
//! The verifier is a trust boundary: every public entry point returns a
//! `Result` (or a `VerifyResult` carrying errors) and never panics on malformed
//! headers, keys, or signatures.

pub mod content_digest;
pub mod freshness;
pub mod keycheck;
pub mod parse;
pub mod signing_base;
pub mod verify;

pub use content_digest::{compute_content_digest, verify_content_digest, ContentDigestError};
pub use freshness::{check_freshness, FreshnessError, FreshnessOptions};
pub use keycheck::{check_ed25519_public_key, is_small_order, WeakKeyError};
pub use parse::{
    parse_signature_input, parse_signature_value, ParsedSignatureInput, SignatureInputParseError,
};
pub use signing_base::{
    build_signing_base, Mode, ParamValue, SigningBaseError, SigningBaseInput,
};
pub use verify::{
    prepare_request, public_key_from_hex, verify_request, verify_signature, PreparedRequest,
    VerifyError, VerifyRequestOptions, VerifyResult,
};

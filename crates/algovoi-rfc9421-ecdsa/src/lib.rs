//! `algovoi-rfc9421-ecdsa`: ECDSA (P-256/P-384) add-on for the AlgoVoi RFC 9421
//! verifier (Rust).
//!
//! A PURE add-on: it does not modify or re-publish the core verifier. It depends
//! on `algovoi-rfc9421-verifier` (the core does NOT depend on this crate),
//! reusing the core's hardened primitives and adding only the ECDSA signature
//! check for the RFC 9421 suites `ecdsa-p256-sha256` and `ecdsa-p384-sha384`.
//!
//! Ed25519 requests are delegated verbatim to the untouched core verifier.

pub mod request;
pub mod verify;

pub use request::{default_allowed, verify_request, EcdsaRequestOptions};
pub use verify::{set_strict_low_s, strict_low_s, verify_p256, verify_p384, ECDSAError, PublicKeyInput};

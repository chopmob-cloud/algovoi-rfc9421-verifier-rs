//! ECDSA verification providers for the AlgoVoi RFC 9421 verifier.
//!
//! Implements the two RFC 9421-registered ECDSA algorithms:
//!   - `ecdsa-p256-sha256` (RFC 9421 3.3.5): P-256, SHA-256, 64-byte r||s signature
//!   - `ecdsa-p384-sha384` (RFC 9421 3.3.6): P-384, SHA-384, 96-byte r||s signature
//!
//! RFC 9421 carries the signature as the raw big-endian concatenation r||s (each
//! component field-element-sized), NOT DER. Public keys are supplied out of band
//! as SEC1 point bytes (compressed or uncompressed) or hex.
//!
//! Hardening applied before accepting a signature (faithful to the reference
//! Python `verify.py`):
//!   - the public-key point must be on the curve and not the identity;
//!   - the signature length must match the curve exactly (64 / 96 bytes);
//!   - r and s must each be in [1, n-1];
//!   - optional low-s (canonical) enforcement, off by default for spec interop.

use std::sync::atomic::{AtomicBool, Ordering};

use algovoi_rfc9421_verifier::VerifyError;

/// Raised on an ECDSA setup error (bad key/signature shape).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ECDSAError(pub String);

impl ECDSAError {
    fn new(msg: impl Into<String>) -> Self {
        ECDSAError(msg.into())
    }
}

impl From<ECDSAError> for VerifyError {
    fn from(e: ECDSAError) -> Self {
        VerifyError::new(e.0)
    }
}

static STRICT_LOW_S: AtomicBool = AtomicBool::new(false);

/// Enable/disable canonical low-s enforcement (anti-malleability). Off by
/// default: standard ECDSA signers may emit high-s and stay RFC 9421 compliant.
pub fn set_strict_low_s(enabled: bool) {
    STRICT_LOW_S.store(enabled, Ordering::SeqCst);
}

/// Whether strict low-s enforcement is currently on.
pub fn strict_low_s() -> bool {
    STRICT_LOW_S.load(Ordering::SeqCst)
}

fn coerce_pubkey_bytes(public_key: &PublicKeyInput) -> Result<Vec<u8>, ECDSAError> {
    match public_key {
        PublicKeyInput::Hex(s) => {
            let raw = s.strip_prefix("0x").unwrap_or(s);
            decode_hex(raw).map_err(|e| ECDSAError::new(format!("public_key hex is invalid: {e}")))
        }
        PublicKeyInput::Bytes(b) => Ok(b.clone()),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
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

/// How a public key is supplied: raw SEC1 point bytes or a hex string.
#[derive(Debug, Clone)]
pub enum PublicKeyInput {
    Bytes(Vec<u8>),
    Hex(String),
}

impl From<&[u8]> for PublicKeyInput {
    fn from(b: &[u8]) -> Self {
        PublicKeyInput::Bytes(b.to_vec())
    }
}
impl From<Vec<u8>> for PublicKeyInput {
    fn from(b: Vec<u8>) -> Self {
        PublicKeyInput::Bytes(b)
    }
}
impl From<&str> for PublicKeyInput {
    fn from(s: &str) -> Self {
        PublicKeyInput::Hex(s.to_string())
    }
}

/// Verify an `ecdsa-p256-sha256` signature (raw 64-byte r||s) over the signing
/// base. Returns `Ok(false)` on a cryptographic mismatch or an out-of-range
/// r/s; `Err` on a shape error (bad length, invalid key encoding, off-curve).
pub fn verify_p256(
    signing_base: &str,
    signature_bytes: &[u8],
    public_key: &PublicKeyInput,
) -> Result<bool, ECDSAError> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::EncodedPoint;

    const FIELD: usize = 32;
    if signature_bytes.len() != 2 * FIELD {
        return Err(ECDSAError::new(format!(
            "secp256r1 signature must be {} bytes (r||s), got {}",
            2 * FIELD,
            signature_bytes.len()
        )));
    }
    // Signature::from_slice enforces r, s in [1, n-1] (rejects zero / out of range).
    let signature = match Signature::from_slice(signature_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if strict_low_s() && signature.normalize_s().is_some() {
        // normalize_s() returns Some only when s was high (non-canonical).
        return Ok(false);
    }

    let key_bytes = coerce_pubkey_bytes(public_key)?;
    let point = EncodedPoint::from_bytes(&key_bytes)
        .map_err(|e| ECDSAError::new(format!("public_key is not a valid point on secp256r1: {e}")))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| ECDSAError::new(format!("public_key is not a valid point on secp256r1: {e}")))?;

    Ok(verifying_key.verify(signing_base.as_bytes(), &signature).is_ok())
}

/// Verify an `ecdsa-p384-sha384` signature (raw 96-byte r||s) over the signing
/// base. Same contract as [`verify_p256`].
pub fn verify_p384(
    signing_base: &str,
    signature_bytes: &[u8],
    public_key: &PublicKeyInput,
) -> Result<bool, ECDSAError> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::EncodedPoint;

    const FIELD: usize = 48;
    if signature_bytes.len() != 2 * FIELD {
        return Err(ECDSAError::new(format!(
            "secp384r1 signature must be {} bytes (r||s), got {}",
            2 * FIELD,
            signature_bytes.len()
        )));
    }
    let signature = match Signature::from_slice(signature_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if strict_low_s() && signature.normalize_s().is_some() {
        return Ok(false);
    }

    let key_bytes = coerce_pubkey_bytes(public_key)?;
    let point = EncodedPoint::from_bytes(&key_bytes)
        .map_err(|e| ECDSAError::new(format!("public_key is not a valid point on secp384r1: {e}")))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| ECDSAError::new(format!("public_key is not a valid point on secp384r1: {e}")))?;

    Ok(verifying_key.verify(signing_base.as_bytes(), &signature).is_ok())
}

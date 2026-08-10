//! RFC 9530 Content-Digest field implementation. Faithful port of
//! `content_digest.py`. Supports SHA-256 (mandatory) and SHA-512 (recommended);
//! the digest is computed over the message body bytes verbatim.

use std::sync::OnceLock;

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use regex::Regex;
use sha2::{Digest, Sha256, Sha512};

/// Raised when content-digest verification fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ContentDigestError(pub String);

impl ContentDigestError {
    fn new(msg: impl Into<String>) -> Self {
        ContentDigestError(msg.into())
    }
}

fn entry_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"([a-z0-9-]+)=:([A-Za-z0-9+/=]+):").unwrap())
}

fn b64_validate_engine() -> &'static GeneralPurpose {
    static E: OnceLock<GeneralPurpose> = OnceLock::new();
    E.get_or_init(|| {
        let cfg = GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical);
        GeneralPurpose::new(&alphabet::STANDARD, cfg)
    })
}

fn is_supported(algo: &str) -> bool {
    algo == "sha-256" || algo == "sha-512"
}

fn digest_of(algo: &str, body: &[u8]) -> Vec<u8> {
    match algo {
        "sha-256" => Sha256::digest(body).to_vec(),
        "sha-512" => Sha512::digest(body).to_vec(),
        _ => unreachable!("digest_of called with unsupported algorithm"),
    }
}

/// Compute the Content-Digest header value for a body: `<algo>=:<base64>:`.
pub fn compute_content_digest(body: &[u8], algorithm: &str) -> Result<String, ContentDigestError> {
    let algo_lower = algorithm.to_lowercase();
    if !is_supported(&algo_lower) {
        return Err(ContentDigestError::new(format!(
            "unsupported algorithm {algorithm:?}; supported: [\"sha-256\", \"sha-512\"]"
        )));
    }
    let digest = digest_of(&algo_lower, body);
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(&digest);
    Ok(format!("{algo_lower}=:{digest_b64}:"))
}

/// Verify that the Content-Digest header matches the body. Faithful port of
/// `verify_content_digest`. Returns `Ok(())` on success (Python returns True).
pub fn verify_content_digest(
    body: &[u8],
    header_value: &str,
    require_algorithm: Option<&str>,
) -> Result<(), ContentDigestError> {
    let entries: Vec<(String, String)> = entry_re()
        .captures_iter(header_value)
        .map(|c| {
            (
                c.get(1).unwrap().as_str().to_string(),
                c.get(2).unwrap().as_str().to_string(),
            )
        })
        .collect();
    if entries.is_empty() {
        return Err(ContentDigestError::new(format!(
            "no valid digest entries in header: {header_value:?}"
        )));
    }

    let required_alg = require_algorithm.map(|a| a.to_lowercase());
    let mut required_seen = false;
    let mut verified_any = false;

    let engine = b64_validate_engine();

    for (algo, digest_b64) in &entries {
        let algo_lower = algo.to_lowercase();
        if !is_supported(&algo_lower) {
            // Unknown algorithms are skipped per RFC 9530.
            continue;
        }
        if let Some(ref req) = required_alg {
            if &algo_lower == req {
                required_seen = true;
            }
        }
        let expected_bytes = engine.decode(digest_b64).map_err(|e| {
            ContentDigestError::new(format!(
                "digest entry {algo_lower:?} is not valid base64: {e}"
            ))
        })?;
        // Reject non-canonical base64 (non-zero pad bits).
        let reencoded = base64::engine::general_purpose::STANDARD.encode(&expected_bytes);
        if &reencoded != digest_b64 {
            return Err(ContentDigestError::new(format!(
                "digest entry {algo_lower:?} is not canonical base64 (non-zero pad bits)"
            )));
        }
        let actual_bytes = digest_of(&algo_lower, body);
        if expected_bytes != actual_bytes {
            let actual_b64 = base64::engine::general_purpose::STANDARD.encode(&actual_bytes);
            return Err(ContentDigestError::new(format!(
                "digest mismatch on {algo_lower}: header claims {digest_b64} but body hashes to {actual_b64}"
            )));
        }
        verified_any = true;
    }

    if let Some(ref req) = required_alg {
        if !required_seen {
            return Err(ContentDigestError::new(format!(
                "required algorithm {req:?} not present in header"
            )));
        }
    }
    if !verified_any {
        return Err(ContentDigestError::new(
            "no recognized digest algorithm in Content-Digest header; nothing verified",
        ));
    }

    Ok(())
}

//! RFC 9421 Signature-Input and Signature header parsers.
//!
//! Faithful port of the reference `parse.py`. The Signature-Input header carries
//! the covered components and signing parameters in RFC 8941 structured-fields
//! form; the Signature header carries the base64 signature bytes wrapped in
//! colons. Both labelled and unlabelled forms are accepted.

use std::sync::OnceLock;

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use regex::Regex;

use crate::signing_base::ParamValue;

/// Raised when a Signature-Input or Signature header cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SignatureInputParseError(pub String);

impl SignatureInputParseError {
    fn new(msg: impl Into<String>) -> Self {
        SignatureInputParseError(msg.into())
    }
}

/// Parsed Signature-Input header for a single label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignatureInput {
    pub label: String,
    pub covered_components: Vec<String>,
    pub parameters: Vec<(String, ParamValue)>,
    pub raw: String,
    /// The post-label portion of the header value, verbatim. This is what the
    /// `@signature-params` line of the RFC 9421 signing base must contain.
    pub params_block: String,
}

impl ParsedSignatureInput {
    /// Convenience lookup mirroring Python dict semantics (last write wins).
    pub fn parameter(&self, key: &str) -> Option<&ParamValue> {
        self.parameters
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

struct Res {
    label: Regex,
    covered: Regex,
    quoted: Regex,
    param: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        label: Regex::new(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*").unwrap(),
        covered: Regex::new(r#"\(\s*(?:"[^"]*"\s*)*\)"#).unwrap(),
        quoted: Regex::new(r#""([^"]*)""#).unwrap(),
        param: Regex::new(r#"([A-Za-z][A-Za-z0-9_-]*)=([^;,\s]+|"[^"]*")"#).unwrap(),
    })
}

/// A base64 engine matching Python `base64.b64decode(validate=True)`: standard
/// alphabet, canonical padding required, but trailing (pad) bits are permitted at
/// decode time. The canonical round-trip is enforced separately by the caller.
fn b64_validate_engine() -> &'static GeneralPurpose {
    static E: OnceLock<GeneralPurpose> = OnceLock::new();
    E.get_or_init(|| {
        let cfg = GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical);
        GeneralPurpose::new(&alphabet::STANDARD, cfg)
    })
}

/// Parse a Signature-Input header value. Faithful port of
/// `parse_signature_input`.
pub fn parse_signature_input(
    header_value: &str,
) -> Result<ParsedSignatureInput, SignatureInputParseError> {
    let r = res();
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(SignatureInputParseError::new("empty header value"));
    }

    let (label, rest): (String, &str) = if let Some(m) = r.label.captures(trimmed) {
        let full = m.get(0).unwrap();
        let label = m.get(1).unwrap().as_str().to_string();
        (label, &trimmed[full.end()..])
    } else if trimmed.starts_with('(') {
        (String::new(), trimmed)
    } else {
        let snippet: String = trimmed.chars().take(40).collect();
        return Err(SignatureInputParseError::new(format!(
            "no label or covered-components list found at start: {snippet:?}"
        )));
    };

    // Capture the post-label portion verbatim.
    let params_block = rest.to_string();

    // _COVERED_RE.match(rest): match must be anchored at the start.
    let covered_match = match r.covered.find(rest) {
        Some(m) if m.start() == 0 => m,
        _ => {
            return Err(SignatureInputParseError::new(
                "no covered-components list found",
            ))
        }
    };
    let covered_raw = &rest[covered_match.start()..covered_match.end()];
    let covered_components: Vec<String> = r
        .quoted
        .captures_iter(covered_raw)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();
    let after = &rest[covered_match.end()..];

    let mut parameters: Vec<(String, ParamValue)> = Vec::new();
    for caps in r.param.captures_iter(after) {
        let key = caps.get(1).unwrap().as_str().to_string();
        let raw_val = caps.get(2).unwrap().as_str();
        let value = if raw_val.starts_with('"') && raw_val.ends_with('"') && raw_val.len() >= 2 {
            ParamValue::Str(raw_val[1..raw_val.len() - 1].to_string())
        } else {
            match raw_val.parse::<i64>() {
                Ok(i) => ParamValue::Int(i),
                Err(_) => ParamValue::Str(raw_val.to_string()),
            }
        };
        parameters.push((key, value));
    }

    Ok(ParsedSignatureInput {
        label,
        covered_components,
        parameters,
        raw: trimmed.to_string(),
        params_block,
    })
}

/// Parse a Signature header value. Faithful port of `parse_signature_value`.
///
/// Returns `(label, signature_bytes)`. Rejects non-canonical base64 (the raw
/// header must round-trip exactly) to defeat signature-string malleability.
pub fn parse_signature_value(
    header_value: &str,
) -> Result<(String, Vec<u8>), SignatureInputParseError> {
    let r = res();
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(SignatureInputParseError::new("empty Signature header value"));
    }

    let (label, rest): (String, String) = if let Some(m) = r.label.captures(trimmed) {
        let full = m.get(0).unwrap();
        let label = m.get(1).unwrap().as_str().to_string();
        (label, trimmed[full.end()..].trim().to_string())
    } else if trimmed.starts_with(':') {
        (String::new(), trimmed.to_string())
    } else {
        let snippet: String = trimmed.chars().take(40).collect();
        return Err(SignatureInputParseError::new(format!(
            "no label or signature-value prefix found at start: {snippet:?}"
        )));
    };

    if !rest.starts_with(':') || !rest.ends_with(':') || rest.len() < 2 {
        return Err(SignatureInputParseError::new(
            "signature value must be wrapped in colons (RFC 8941 byte-sequence form)",
        ));
    }
    let sig_b64 = &rest[1..rest.len() - 1];

    let engine = b64_validate_engine();
    let sig_bytes = engine.decode(sig_b64).map_err(|e| {
        SignatureInputParseError::new(format!("signature value is not valid base64: {e}"))
    })?;

    // Reject non-canonical base64: the canonical re-encoding must round-trip
    // exactly, else the raw signature header is malleable (breaks replay/dedup
    // keys derived from it).
    let reencoded = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
    if reencoded != sig_b64 {
        return Err(SignatureInputParseError::new(
            "signature value is not canonical base64 (non-zero pad bits)",
        ));
    }

    Ok((label, sig_bytes))
}

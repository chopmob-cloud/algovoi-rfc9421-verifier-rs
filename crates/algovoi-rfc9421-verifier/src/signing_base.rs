//! RFC 9421 Section 2.5 signing-base construction.
//!
//! The signing base is a deterministic byte sequence assembled from the HTTP
//! message's covered components in the order they appear in the Signature-Input
//! header's covered-components list. Each line is:
//!
//! ```text
//! "<component-name>": <component-value>
//! ```
//!
//! joined with `\n`. This is a faithful port of the reference `signing_base.py`.

use std::collections::HashMap;

/// Raised when the signing base cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SigningBaseError(pub String);

impl SigningBaseError {
    fn new(msg: impl Into<String>) -> Self {
        SigningBaseError(msg.into())
    }
}

/// A parameter value carried in Signature-Input (`created`, `expires`, `alg`...).
///
/// Mirrors the Python parser which stores either an int or a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    Int(i64),
    Str(String),
}

impl ParamValue {
    /// The value as it renders into the signing base (Python `str(value)`).
    pub fn as_signing_str(&self) -> String {
        match self {
            ParamValue::Int(i) => i.to_string(),
            ParamValue::Str(s) => s.clone(),
        }
    }
}

/// The signing-base construction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Legacy internal format: `@method` lowercased, no `@signature-params` line.
    #[default]
    AlgovoiV0,
    /// RFC 9421 Section 2.5: `@method` as-supplied, `@signature-params` appended.
    Rfc9421,
}

impl Mode {
    /// Parse the wire mode string used by the reference and the vectors.
    pub fn parse(s: &str) -> Result<Mode, SigningBaseError> {
        match s {
            "algovoi-v0" => Ok(Mode::AlgovoiV0),
            "rfc9421" => Ok(Mode::Rfc9421),
            other => Err(SigningBaseError::new(format!(
                "mode must be 'algovoi-v0' or 'rfc9421', got {other:?}"
            ))),
        }
    }
}

/// Inputs for [`build_signing_base`]. `None` fields are treated as "not supplied"
/// exactly like the Python keyword defaults.
#[derive(Debug, Default, Clone)]
pub struct SigningBaseInput<'a> {
    pub covered_components: Vec<String>,
    pub method: Option<&'a str>,
    pub authority: Option<&'a str>,
    pub path: Option<&'a str>,
    pub target_uri: Option<&'a str>,
    pub scheme: Option<&'a str>,
    pub status: Option<i64>,
    pub headers: HashMap<String, String>,
    pub parameters: HashMap<String, ParamValue>,
    pub mode: Mode,
    pub signature_params_raw: Option<String>,
}

/// Build the RFC 9421 signing base. Faithful port of `build_signing_base`.
pub fn build_signing_base(input: &SigningBaseInput) -> Result<String, SigningBaseError> {
    if input.mode == Mode::Rfc9421 && input.signature_params_raw.is_none() {
        return Err(SigningBaseError::new(
            "rfc9421 mode requires signature_params_raw \
             (the post-label portion of the Signature-Input header)",
        ));
    }

    // Headers looked up case-insensitively.
    let headers: HashMap<String, String> = input
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let mut lines: Vec<String> = Vec::with_capacity(input.covered_components.len() + 1);

    for component in &input.covered_components {
        let c = component.to_lowercase();
        let value: String = match c.as_str() {
            "@method" => {
                let method = input
                    .method
                    .ok_or_else(|| SigningBaseError::new("@method covered but method not supplied"))?;
                if input.mode == Mode::Rfc9421 {
                    method.to_string()
                } else {
                    method.to_lowercase()
                }
            }
            "@authority" => {
                let authority = input.authority.ok_or_else(|| {
                    SigningBaseError::new("@authority covered but authority not supplied")
                })?;
                authority.to_lowercase()
            }
            "@path" => {
                let path = input
                    .path
                    .ok_or_else(|| SigningBaseError::new("@path covered but path not supplied"))?;
                path.to_string()
            }
            "@target-uri" => {
                let target_uri = input.target_uri.ok_or_else(|| {
                    SigningBaseError::new("@target-uri covered but target_uri not supplied")
                })?;
                target_uri.to_string()
            }
            "@scheme" => {
                let scheme = input
                    .scheme
                    .ok_or_else(|| SigningBaseError::new("@scheme covered but scheme not supplied"))?;
                scheme.to_lowercase()
            }
            "@status" => {
                let status = input
                    .status
                    .ok_or_else(|| SigningBaseError::new("@status covered but status not supplied"))?;
                status.to_string()
            }
            "created" => {
                let v = input.parameters.get("created").ok_or_else(|| {
                    SigningBaseError::new(
                        "'created' covered but no 'created' parameter in Signature-Input",
                    )
                })?;
                v.as_signing_str()
            }
            "expires" => {
                let v = input.parameters.get("expires").ok_or_else(|| {
                    SigningBaseError::new(
                        "'expires' covered but no 'expires' parameter in Signature-Input",
                    )
                })?;
                v.as_signing_str()
            }
            other if other.starts_with('@') => {
                return Err(SigningBaseError::new(format!(
                    "unsupported derived component: {component:?}"
                )));
            }
            _ => {
                // Regular header component.
                headers.get(&c).cloned().ok_or_else(|| {
                    SigningBaseError::new(format!(
                        "covered header {component:?} not present in supplied headers"
                    ))
                })?
            }
        };
        lines.push(format!("\"{c}\": {value}"));
    }

    if input.mode == Mode::Rfc9421 {
        // signature_params_raw presence already checked above.
        let raw = input.signature_params_raw.as_deref().unwrap_or("");
        lines.push(format!("\"@signature-params\": {raw}"));
    }

    Ok(lines.join("\n"))
}

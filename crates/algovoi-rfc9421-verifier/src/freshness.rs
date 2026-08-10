//! RFC 9421 signature freshness and replay checks. Faithful port of
//! `freshness.py`.
//!
//! Trust rule: only covered (signed) `created` / `expires` values are honoured.
//! A freshness requirement against an uncovered, unsigned parameter fails closed.

use std::collections::HashSet;

use crate::signing_base::ParamValue;

/// Raised when a signature is stale, not yet valid, expired, or malformed in its
/// time parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FreshnessError(pub String);

impl FreshnessError {
    fn new(msg: impl Into<String>) -> Self {
        FreshnessError(msg.into())
    }
}

/// Options for [`check_freshness`], mirroring the Python keyword arguments.
#[derive(Debug, Clone)]
pub struct FreshnessOptions {
    pub now: i64,
    pub max_age_seconds: Option<i64>,
    pub max_skew_seconds: i64,
    pub enforce_expires: bool,
    pub require_created: bool,
    pub params_signed: bool,
}

impl Default for FreshnessOptions {
    fn default() -> Self {
        FreshnessOptions {
            now: 0,
            max_age_seconds: None,
            max_skew_seconds: 60,
            enforce_expires: true,
            require_created: false,
            params_signed: true,
        }
    }
}

fn covered_names<I, S>(covered_components: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut names = HashSet::new();
    for component in covered_components {
        let raw = component.as_ref().trim().trim_matches('"');
        let name = raw
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_lowercase();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names
}

fn as_int(value: &ParamValue, name: &str) -> Result<i64, FreshnessError> {
    match value {
        ParamValue::Int(i) => Ok(*i),
        ParamValue::Str(s) => s
            .parse::<i64>()
            .map_err(|_| FreshnessError::new(format!("'{name}' is not an integer: {s:?}"))),
    }
}

/// Validate the time-based signature parameters. No-op when nothing to check.
///
/// `parameters` are looked up by key; pass the parsed Signature-Input parameters.
pub fn check_freshness<I, S>(
    parameters: &[(String, ParamValue)],
    covered_components: I,
    opts: &FreshnessOptions,
) -> Result<(), FreshnessError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let covered = covered_names(covered_components);

    // dict semantics: last write wins.
    let get = |key: &str| -> Option<&ParamValue> {
        parameters.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v)
    };
    let created = get("created");
    let expires = get("expires");

    let signed = |name: &str| -> bool { covered.contains(name) || opts.params_signed };

    if opts.max_age_seconds.is_some() || opts.require_created {
        let created = created.ok_or_else(|| {
            FreshnessError::new("freshness required but no 'created' parameter present")
        })?;
        if !signed("created") {
            return Err(FreshnessError::new(
                "freshness required but 'created' is not signed \
                 (not a covered component and params are unsigned)",
            ));
        }
        let created_i = as_int(created, "created")?;
        if created_i > opts.now + opts.max_skew_seconds {
            return Err(FreshnessError::new(
                "signature 'created' is in the future beyond the allowed skew",
            ));
        }
        if let Some(max_age) = opts.max_age_seconds {
            if created_i < opts.now - max_age {
                return Err(FreshnessError::new(
                    "signature is older than the maximum allowed age",
                ));
            }
        }
    }

    if opts.enforce_expires {
        if let Some(expires) = expires {
            if !signed("expires") {
                return Err(FreshnessError::new(
                    "'expires' present but not signed \
                     (not a covered component and params are unsigned)",
                ));
            }
            let expires_i = as_int(expires, "expires")?;
            if opts.now > expires_i + opts.max_skew_seconds {
                return Err(FreshnessError::new("signature has expired"));
            }
        }
    }

    Ok(())
}

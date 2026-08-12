# algovoi-rfc9421-verifier-rs

[![ci](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier-rs/actions/workflows/ci.yml)

A Rust implementation of the AlgoVoi RFC 9421 (HTTP Message Signatures) plus
RFC 9530 (Content-Digest) verifier, laid out as TWO independent crates that
mirror the Python / TypeScript / Go "pure add-on" architecture:

- `crates/algovoi-rfc9421-verifier` is the core: Ed25519 verification, the
  public-key trust-boundary gate, signing-base construction, `Signature-Input` /
  `Signature` parsing, RFC 9530 Content-Digest verification, and freshness /
  replay checks.
- `crates/algovoi-rfc9421-ecdsa` is a SEPARATE add-on providing the RFC 9421
  `ecdsa-p256-sha256` and `ecdsa-p384-sha384` verifiers. It depends on the core
  crate; the core NEVER depends on the add-on.

This is a port of `algovoi-rfc9421-verifier` and `algovoi-rfc9421-ecdsa`. It
reproduces the reference signing-base bytes, the Ed25519 key-gate decisions, and
the verification results byte-for-byte, validated against the frozen
cross-language reference vectors.

## Behaviour parity points

- Signing base (`build_signing_base`): per covered component emit
  `"<lowercased-name>": <value>`, newline-joined. `algovoi-v0` mode lowercases
  `@method` and appends no `@signature-params` line; `rfc9421` mode preserves
  `@method` as supplied and appends `"@signature-params": <params-block>`.
  `@authority` / `@scheme` are lowercased; `@path` / `@target-uri` are verbatim;
  `@status` is the integer as a string; unknown `@`-components error; headers are
  looked up case-insensitively.
- Parse (`parse_signature_input` / `parse_signature_value`): labelled and
  unlabelled forms; the Signature value must be canonical base64 (re-encoding must
  round-trip exactly), rejecting the pad-bit malleability class.
- Key gate (`check_ed25519_public_key`): rejects non-canonical (y >= p),
  off-curve, and small-order (`[8]P == identity`) Ed25519 public keys, fail-closed
  and before verification.
- ECDSA add-on: raw fixed-width `r||s` signatures (P-256 64 bytes, P-384 96
  bytes), point-on-curve validation, `r, s` in `[1, n-1]`, and optional strict
  low-s enforcement (off by default via `set_strict_low_s`).

## Cross-language conformance battery

This verifier is one implementation in the twelve-way
[algovoi-rfc9421-conformance](https://github.com/chopmob-cloud/algovoi-rfc9421-conformance)
consensus. The `crates/algovoi-rfc9421-ecdsa/tests/negative_v1.rs` runner reads
that repo's one frozen, signed corpus (`rfc9421_negative_v3`, 96 cases across
seven sections) and must reproduce the reference verdict byte-for-byte per case:
signing-base construction (both modes), `Signature-Input` / `Signature` parsing,
the Ed25519 small-order key gate, Ed25519 verify, ECDSA P-256/P-384 verify, and
(v3) **RSA-PSS-SHA512 / RSA-PKCS1v1.5-SHA256** verify from an SPKI key. RSA is
not part of this crate's runtime surface; it is exercised through the `rsa`
dev-dependency only.

CI (`.github/workflows/ci.yml`) gates every push and pull request on this
battery against the signed v3 corpus, so a divergence from the shared oracle,
including the RSA cases, fails the build.

## Build and test

```
cargo build --workspace
cargo test --workspace
```

The `shared_vectors` test reads reference vectors from the
[algovoi-rfc9421-verifier-multilang](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier-multilang)
repo at runtime, defaulting to a checkout alongside this one; override with
`ALGOVOI_REFERENCE_ECDSA_VECTORS`. When that repo is absent (as in CI) the test
**skips** rather than failing the build, so `cargo test --workspace` stays green
without a third checkout.

To run the conformance battery against the signed corpus, check out
`algovoi-rfc9421-conformance` and point `ALGOVOI_NEGATIVE_V1` at
`corpus/rfc9421_negative_v3/rfc9421_negative_v3.json`:

```
ALGOVOI_NEGATIVE_V1=/path/to/algovoi-rfc9421-conformance/corpus/rfc9421_negative_v3/rfc9421_negative_v3.json \
  cargo test -p algovoi-rfc9421-ecdsa --test negative_v1
```

Minimum supported Rust version: 1.74.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.

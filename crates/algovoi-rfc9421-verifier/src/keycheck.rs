//! Ed25519 public-key validation for the verifier's trust boundary.
//!
//! Rejects, fail-closed and before signature verification:
//!
//!   1. non-canonical encodings (y-coordinate >= p, i.e. a duplicate encoding of
//!      a valid point, a malleability class), and points not on the curve;
//!   2. small-order points (order dividing the cofactor 8, including the
//!      identity), which permit signature-malleability / cross-key verification
//!      classes.
//!
//! This mirrors the reference Python `keycheck.py` byte for byte: RFC 8032
//! Appendix A arithmetic in extended homogeneous coordinates, deriving
//! small-order-ness mathematically ([8]P == identity) rather than trusting a
//! hard-coded blocklist.

use num_bigint::BigInt;
use num_bigint::Sign;

use std::sync::OnceLock;

/// Raised when an Ed25519 public key is non-canonical, off-curve, or small-order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WeakKeyError {
    #[error("public key is not a canonical on-curve Ed25519 point")]
    NotOnCurve,
    #[error("public key is a small-order Ed25519 point")]
    SmallOrder,
}

struct Consts {
    p: BigInt,
    d: BigInt,
    sqrt_m1: BigInt,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        let one = BigInt::from(1u8);
        // p = 2**255 - 19
        let p = (BigInt::from(1u8) << 255) - BigInt::from(19u8);
        // d = (-121665 * inv(121666)) % p
        let inv_121666 = modinv(&BigInt::from(121666u32), &p);
        let d = modp(&(BigInt::from(-121665i64) * inv_121666), &p);
        // sqrt(-1) = 2**((p-1)/4) mod p
        let sqrt_m1 = modpow(&BigInt::from(2u8), &((&p - &one) / BigInt::from(4u8)), &p);
        Consts { p, d, sqrt_m1 }
    })
}

/// Non-negative modulo, matching Python's `%` semantics.
fn modp(x: &BigInt, p: &BigInt) -> BigInt {
    let r = x % p;
    if r.sign() == Sign::Minus {
        r + p
    } else {
        r
    }
}

fn modpow(base: &BigInt, exp: &BigInt, p: &BigInt) -> BigInt {
    // num-bigint modpow requires a non-negative base; reduce first.
    modp(base, p).modpow(exp, p)
}

/// Modular inverse via Fermat's little theorem: base**(p-2) mod p.
fn modinv(base: &BigInt, p: &BigInt) -> BigInt {
    modpow(base, &(p - BigInt::from(2u8)), p)
}

/// Extended homogeneous coordinates (X, Y, Z, T).
type Point = (BigInt, BigInt, BigInt, BigInt);

fn recover_x(y: &BigInt, sign: i64) -> Option<BigInt> {
    let c = consts();
    let p = &c.p;
    if y >= p {
        return None; // non-canonical y encoding
    }
    // x2 = (y*y - 1) * inv(d*y*y + 1) % p
    let yy = y * y;
    let num = &yy - BigInt::from(1u8);
    let den = &c.d * &yy + BigInt::from(1u8);
    let x2 = modp(&(num * modinv(&den, p)), p);
    if x2 == BigInt::from(0u8) {
        return if sign != 0 { None } else { Some(BigInt::from(0u8)) };
    }
    // x = x2 ** ((p+3)//8) % p
    let mut x = modpow(&x2, &((p + BigInt::from(3u8)) / BigInt::from(8u8)), p);
    if modp(&(&x * &x - &x2), p) != BigInt::from(0u8) {
        x = modp(&(&x * &c.sqrt_m1), p);
    }
    if modp(&(&x * &x - &x2), p) != BigInt::from(0u8) {
        return None; // not a square, point not on curve
    }
    // enforce sign bit
    let x_is_odd = (&x & BigInt::from(1u8)) == BigInt::from(1u8);
    if (x_is_odd as i64) != sign {
        x = p - &x;
    }
    Some(x)
}

/// Decode a 32-byte Ed25519 public key to extended coords, or None if invalid.
fn decode(pk: &[u8]) -> Option<Point> {
    if pk.len() != 32 {
        return None;
    }
    let c = consts();
    let p = &c.p;
    // little-endian
    let mut y = BigInt::from_bytes_le(Sign::Plus, pk);
    let sign = ((&y >> 255) & BigInt::from(1u8)) == BigInt::from(1u8);
    // y &= (1<<255) - 1
    let mask = (BigInt::from(1u8) << 255) - BigInt::from(1u8);
    y &= mask;
    let x = recover_x(&y, sign as i64)?;
    let t = modp(&(&x * &y), p);
    Some((x, y, BigInt::from(1u8), t))
}

fn add(pp: &Point, q: &Point) -> Point {
    let c = consts();
    let p = &c.p;
    let a = modp(&((&pp.1 - &pp.0) * (&q.1 - &q.0)), p);
    let b = modp(&((&pp.1 + &pp.0) * (&q.1 + &q.0)), p);
    let cc = modp(&(BigInt::from(2u8) * &pp.3 * &q.3 * &c.d), p);
    let dd = modp(&(BigInt::from(2u8) * &pp.2 * &q.2), p);
    let e = &b - &a;
    let f = &dd - &cc;
    let g = &dd + &cc;
    let h = &b + &a;
    (
        modp(&(&e * &f), p),
        modp(&(&g * &h), p),
        modp(&(&f * &g), p),
        modp(&(&e * &h), p),
    )
}

fn mul8(pp: &Point) -> Point {
    let p2 = add(pp, pp);
    let p4a = add(&p2, &p2);
    let p4b = add(&p2, &p2);
    add(&p4a, &p4b)
}

fn is_identity(pp: &Point) -> bool {
    let c = consts();
    let p = &c.p;
    // affine (0, 1): X == 0 and Y == Z (mod p)
    modp(&pp.0, p) == BigInt::from(0u8) && modp(&(&pp.1 - &pp.2), p) == BigInt::from(0u8)
}

/// True iff `pk` decodes to a point whose order divides 8 (including identity).
///
/// Returns false for keys that fail to decode (handled by
/// [`check_ed25519_public_key`]).
pub fn is_small_order(pk: &[u8]) -> bool {
    match decode(pk) {
        None => false,
        Some(point) => is_identity(&mul8(&point)),
    }
}

/// Return `Err` if `pk` is non-canonical, off-curve, or small-order.
///
/// Returns `Ok(())` for a canonical, on-curve, large-order public key.
pub fn check_ed25519_public_key(pk: &[u8]) -> Result<(), WeakKeyError> {
    let point = decode(pk).ok_or(WeakKeyError::NotOnCurve)?;
    if is_identity(&mul8(&point)) {
        return Err(WeakKeyError::SmallOrder);
    }
    Ok(())
}

//! Elligator2 encoding/decoding for Curve25519 public keys.
//!
//! Elligator2 maps Curve25519 points to uniformly random 32-byte strings,
//! making public keys indistinguishable from random noise.
//!
//! Only ~50% of Curve25519 points have an Elligator2 representative.
//! Use [`keypair::EphemeralKeypair`] which retries until a representable
//! key is found.
//!
//! ## Reference
//! - Spec: https://elligator.cr.yp.to/elligator-20130828.pdf
//! - obfs4 usage: https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt

use curve25519_dalek::montgomery::MontgomeryPoint;
use crate::Result;

// ── Constants ────────────────────────────────────────────────────────────────

/// The non-square u in GF(2^255-19) used by Elligator2.
/// u = 2 (Curve25519 uses u=2 as the non-square constant)
const ELLIGATOR2_U: u64 = 2;

// ── Public API ───────────────────────────────────────────────────────────────

/// Encode a Curve25519 Montgomery point as a uniform 32-byte representative.
///
/// Returns `None` if the point has no Elligator2 representative (~50% of points).
/// In that case, generate a new keypair and retry.
///
/// # Arguments
/// * `point` — a Curve25519 public key (Montgomery u-coordinate)
///
/// # Returns
/// * `Some([u8; 32])` — uniform representative bytes
/// * `None` — this point is not Elligator2-representable
pub fn encode(point: &MontgomeryPoint) -> Option<[u8; 32]> {
    // TODO: Implement Elligator2 encoding
    //
    // Algorithm (from spec):
    // Given Montgomery curve point (u, v):
    //   1. Compute r = sqrt(-u / (ELLIGATOR2_U * (u + A)))
    //      where A = 486662 (Curve25519 parameter)
    //   2. If r doesn't exist (not a QR mod p) → return None
    //   3. Choose r or -r such that 0 ≤ r ≤ (p-1)/2
    //   4. Encode r as little-endian 32 bytes
    //
    // NOTE: This MUST be constant-time. Use curve25519_dalek's FieldElement.
    let _ = point;
    todo!("Elligator2 encode — see obfs4 spec §3.1")
}

/// Decode a uniform 32-byte representative back to a Curve25519 point.
///
/// This always succeeds (every 32-byte string is a valid Elligator2 input).
///
/// # Arguments
/// * `representative` — 32 bytes from the wire
///
/// # Returns
/// The decoded Curve25519 Montgomery point (public key).
pub fn decode(representative: &[u8; 32]) -> Result<MontgomeryPoint> {
    // TODO: Implement Elligator2 decoding
    //
    // Algorithm:
    //   1. Interpret representative as little-endian field element r
    //   2. Compute u = -A / (1 + ELLIGATOR2_U * r²)
    //      where A = 486662
    //   3. If u*(u² + A*u + 1) is a QR → v = sqrt(...), keep u
    //      else → u = -u - A, v = sqrt(u*(u²+A*u+1))
    //   4. Return MontgomeryPoint(u)
    let _ = representative;
    todo!("Elligator2 decode — see obfs4 spec §3.1")
}

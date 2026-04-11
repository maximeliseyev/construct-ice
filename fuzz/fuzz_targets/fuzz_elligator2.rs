//! Fuzz target: Elligator2 encode/decode roundtrip.
//!
//! Tests that:
//! 1. `pubkey_from_representative` never panics on any 32-byte input.
//! 2. `representative_from_privkey_tweaked` never panics on any (privkey, tweak).
//! 3. If `representative_from_privkey_tweaked` returns `Some(repr)`, then
//!    `pubkey_from_representative(repr)` must return the correct public key
//!    (roundtrip invariant).
//!
//! This is security-critical: the Elligator2 representative is the first field
//! in every client handshake. A panic in the decode path would crash the server
//! for any connecting client.

#![no_main]

use arbitrary::Arbitrary;
use construct_ice::crypto::elligator2::{pubkey_from_representative, representative_from_privkey_tweaked};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Arbitrary 32 bytes fed as a representative (decode path).
    representative: [u8; 32],
    /// Arbitrary private key for the encode path.
    privkey: [u8; 32],
    /// Tweak byte for `representative_from_privkey_tweaked`.
    tweak: u8,
}

fuzz_target!(|input: FuzzInput| {
    // 1. Decode path: must never panic on any 32-byte input.
    let _decoded = pubkey_from_representative(&input.representative);

    // 2. Encode path: must never panic.
    let repr_opt = representative_from_privkey_tweaked(&input.privkey, input.tweak);

    // 3. Roundtrip: if encode succeeded, decode must recover the same public key.
    if let Some(repr) = repr_opt {
        use curve25519_elligator2::MontgomeryPoint;
        let expected_pub = MontgomeryPoint::mul_base_clamped(input.privkey);
        let recovered_pub = pubkey_from_representative(&repr);
        assert_eq!(
            recovered_pub.to_bytes(),
            expected_pub.to_bytes(),
            "Elligator2 roundtrip failed: encode → decode did not recover original pubkey"
        );
    }
});

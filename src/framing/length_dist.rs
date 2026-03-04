//! SipHash-based PRNG for frame length distribution.
//!
//! obfs4 randomizes frame sizes to prevent traffic analysis.
//! The PRNG is seeded from session key material so both sides
//! independently produce the same length sequence.

use siphasher::sip::SipHasher13;
use std::hash::Hasher;

/// PRNG state for frame length generation.
pub struct LengthDistPrng {
    key0: u64,
    key1: u64,
    counter: u64,
}

impl LengthDistPrng {
    /// Create a new PRNG from the 16-byte seed derived by KDF.
    pub fn new(seed: &[u8; 16]) -> Self {
        let key0 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        let key1 = u64::from_le_bytes(seed[8..16].try_into().unwrap());
        LengthDistPrng { key0, key1, counter: 0 }
    }

    /// Generate next pseudo-random u64 value.
    fn next_u64(&mut self) -> u64 {
        let mut h = SipHasher13::new_with_keys(self.key0, self.key1);
        h.write_u64(self.counter);
        self.counter += 1;
        h.finish()
    }

    /// Generate next frame padding size in bytes.
    ///
    /// Returns a value in `[0, max_padding]` with distribution
    /// that makes traffic analysis harder.
    pub fn next_padding_len(&mut self, max_payload: usize) -> usize {
        // TODO: implement obfs4 spec §3.6 length distribution
        // The spec uses a more complex distribution (not pure uniform)
        // to match expected traffic patterns
        let raw = self.next_u64();
        (raw as usize) % (max_payload + 1)
    }
}

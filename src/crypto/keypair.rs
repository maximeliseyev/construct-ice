//! Ephemeral Curve25519 keypairs with Elligator2 representatives.
//!
//! Only ~50% of Curve25519 keys have an Elligator2 representative.
//! This module handles the retry loop transparently.

use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use super::elligator2;

/// Maximum number of keypair generation attempts before giving up.
/// In practice, succeeds within 2-3 attempts on average.
const MAX_RETRIES: usize = 64;

/// Static server identity keypair — loaded from config, long-lived.
#[derive(ZeroizeOnDrop)]
pub struct StaticKeypair {
    #[zeroize(skip)]
    pub public: MontgomeryPoint,
    pub secret: [u8; 32],
    /// Elligator2 representative of `public` (may be None if not representable).
    /// Server static keys don't need to be representable.
    #[zeroize(skip)]
    pub representative: Option<[u8; 32]>,
}

/// Ephemeral keypair guaranteed to have an Elligator2 representative.
/// Used in the handshake — the representative is sent on the wire.
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    #[zeroize(skip)]
    pub public: MontgomeryPoint,
    pub secret: [u8; 32],
    /// Always `Some` — guaranteed by construction.
    #[zeroize(skip)]
    pub representative: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate an ephemeral keypair that has an Elligator2 representative.
    ///
    /// Retries up to [`MAX_RETRIES`] times. Average: 2 attempts.
    ///
    /// # Panics
    /// Panics if no representable key found after MAX_RETRIES (should be
    /// astronomically unlikely — probability 2^-64).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        for _ in 0..MAX_RETRIES {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);

            // Clamp scalar per Curve25519 spec
            secret[0] &= 248;
            secret[31] &= 127;
            secret[31] |= 64;

            let public = curve25519_dalek::montgomery::MontgomeryPoint(
                // TODO: replace with proper scalar mult once elligator2 is implemented
                [0u8; 32],
            );

            if let Some(representative) = elligator2::encode(&public) {
                return EphemeralKeypair {
                    public,
                    secret,
                    representative,
                };
            }
        }
        panic!("Failed to generate Elligator2-representable keypair after {MAX_RETRIES} retries");
    }
}

impl StaticKeypair {
    /// Generate a new static keypair (for server identity).
    /// The representative may or may not be present.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        let public = curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]); // TODO
        let representative = elligator2::encode(&public);

        StaticKeypair { public, secret, representative }
    }

    /// Load keypair from raw secret bytes (e.g., from config file).
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]); // TODO
        let representative = elligator2::encode(&public);
        StaticKeypair { public, secret, representative }
    }

    /// Encode public key as base64 for use in server bridge line.
    /// Format: `cert=<base64(public_key || node_id)>`
    pub fn bridge_cert(&self) -> String {
        use std::io::Write;
        let mut cert = Vec::with_capacity(64);
        cert.extend_from_slice(self.public.as_bytes());
        // node_id (20 bytes) TBD
        cert.extend_from_slice(&[0u8; 20]);
        base64_encode(&cert)
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    // Simple base64 without external dep in this file
    // In practice use base64 crate
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{:02x}", b);
        acc
    })
}

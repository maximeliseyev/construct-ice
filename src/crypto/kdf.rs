//! Key derivation for obfs4 session keys.
//!
//! After the X25519 DH exchange in the handshake, HKDF-SHA256 derives
//! all session keys for both directions.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Result};

/// Length of each derived key material chunk.
pub const KEY_LEN: usize = 32;
/// Length of HMAC key used in handshake verification.
pub const MAC_KEY_LEN: usize = 32;

/// All session keys derived from the DH shared secret.
pub struct SessionKeys {
    /// Client→Server encryption key (ChaCha20-Poly1305)
    pub client_to_server: [u8; KEY_LEN],
    /// Server→Client encryption key
    pub server_to_client: [u8; KEY_LEN],
    /// Client→Server nonce seed
    pub client_nonce_seed: [u8; KEY_LEN],
    /// Server→Client nonce seed
    pub server_nonce_seed: [u8; KEY_LEN],
    /// SipHash seed for frame length distribution PRNG
    pub length_prng_seed: [u8; 16],
}

impl SessionKeys {
    /// Derive all session keys from DH output + handshake material.
    ///
    /// # Arguments
    /// * `dh_output` — raw 32-byte X25519 shared secret
    /// * `client_representative` — client's Elligator2 representative (from wire)
    /// * `server_representative` — server's Elligator2 representative (from wire)
    pub fn derive(
        dh_output: &[u8; 32],
        client_representative: &[u8; 32],
        server_representative: &[u8; 32],
    ) -> Result<Self> {
        // HKDF info = "obfs4 key material" || client_repr || server_repr
        let mut info = Vec::with_capacity(18 + 32 + 32);
        info.extend_from_slice(b"obfs4 key material");
        info.extend_from_slice(client_representative);
        info.extend_from_slice(server_representative);

        let hk = Hkdf::<Sha256>::new(None, dh_output);

        // Expand enough bytes for all keys: 32+32+32+32+16 = 144 bytes
        let mut okm = [0u8; 144];
        hk.expand(&info, &mut okm).map_err(|_| Error::KdfError)?;

        Ok(SessionKeys {
            client_to_server: okm[0..32].try_into().unwrap(),
            server_to_client: okm[32..64].try_into().unwrap(),
            client_nonce_seed: okm[64..96].try_into().unwrap(),
            server_nonce_seed: okm[96..128].try_into().unwrap(),
            length_prng_seed: okm[128..144].try_into().unwrap(),
        })
    }
}

/// Derive the handshake MAC key used to bind the handshake to the server's
/// static public key (proves knowledge of server identity).
///
/// MAC_KEY = HKDF-SHA256(server_pubkey, "obfs4 mac key")
pub fn derive_mac_key(server_pubkey: &[u8; 32]) -> [u8; MAC_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, server_pubkey);
    let mut key = [0u8; MAC_KEY_LEN];
    hk.expand(b"obfs4 mac key", &mut key).expect("HKDF expand for mac key");
    key
}

//! Frame encoder: wraps plaintext payload into obfs4 wire frames.
//!
//! ## Wire format per frame
//! ```text
//! Frame = EncryptedLength[2] || EncryptedPayload || Padding || Poly1305MAC[16]
//! ```
//! The length field is encrypted with ChaCha20 keyed from session key,
//! so an observer cannot determine payload vs padding boundary.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, AeadInPlace,
    aead::generic_array::GenericArray,
};
use bytes::{BufMut, BytesMut};

use crate::Result;
use super::{FRAME_HEADER_LEN, FRAME_MAC_LEN, MAX_FRAME_PAYLOAD, length_dist::LengthDistPrng};

/// Encodes plaintext application data into obfs4 frames.
pub struct FrameEncoder {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
    length_prng: LengthDistPrng,
}

impl FrameEncoder {
    /// Create a new encoder with session key material.
    ///
    /// # Arguments
    /// * `key`          — 32-byte ChaCha20-Poly1305 key (from KDF)
    /// * `nonce_seed`   — 32-byte nonce seed (from KDF)
    /// * `length_seed`  — 16-byte SipHash PRNG seed (from KDF)
    pub fn new(key: &[u8; 32], _nonce_seed: &[u8; 32], length_seed: &[u8; 16]) -> Self {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        FrameEncoder {
            cipher,
            nonce_counter: 0,
            length_prng: LengthDistPrng::new(length_seed),
        }
    }

    /// Encode `payload` into one or more obfs4 frames, appending to `dst`.
    ///
    /// Large payloads are split across multiple frames automatically.
    pub fn encode(&mut self, payload: &[u8], dst: &mut BytesMut) -> Result<()> {
        let mut offset = 0;
        while offset < payload.len() {
            let chunk_end = (offset + MAX_FRAME_PAYLOAD).min(payload.len());
            let chunk = &payload[offset..chunk_end];

            // Choose padding to add after chunk
            let padding_len = self.length_prng.next_padding_len(MAX_FRAME_PAYLOAD - chunk.len());
            let total_payload_len = chunk.len() + padding_len;

            // Reserve space: header + payload + padding + MAC
            let frame_start = dst.len();
            dst.reserve(FRAME_HEADER_LEN + total_payload_len + FRAME_MAC_LEN);

            // Write length header (plaintext for now — TODO: encrypt with ChaCha20 keystream)
            dst.put_u16_le(total_payload_len as u16);

            // Write chunk + padding
            dst.put_slice(chunk);
            for _ in 0..padding_len {
                dst.put_u8(0);
            }

            // TODO: encrypt in-place with ChaCha20-Poly1305
            // Nonce = nonce_seed XOR little-endian(nonce_counter)
            // encrypt_in_place_detached(nonce, aad=[], buffer)
            // append 16-byte MAC tag
            dst.put_bytes(0, FRAME_MAC_LEN); // placeholder MAC

            let _ = frame_start;
            self.nonce_counter += 1;
            offset = chunk_end;
        }
        Ok(())
    }
}

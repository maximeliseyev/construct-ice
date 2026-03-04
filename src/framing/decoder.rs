//! Frame decoder: reads obfs4 wire frames and returns plaintext payload.

use bytes::{Buf, BytesMut};

use crate::{Error, Result};
use super::{FRAME_HEADER_LEN, FRAME_MAC_LEN};

/// State machine for incremental frame decoding.
pub struct FrameDecoder {
    key: [u8; 32],
    nonce_seed: [u8; 32],
    nonce_counter: u64,
    /// Accumulator for partial reads
    buf: BytesMut,
}

impl FrameDecoder {
    /// Create a new decoder with session key material.
    pub fn new(key: &[u8; 32], nonce_seed: &[u8; 32]) -> Self {
        FrameDecoder {
            key: *key,
            nonce_seed: *nonce_seed,
            nonce_counter: 0,
            buf: BytesMut::with_capacity(4096),
        }
    }

    /// Feed newly received bytes into the decoder buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode one complete frame from the internal buffer.
    ///
    /// Returns:
    /// - `Ok(Some(payload))` — a complete frame was decoded
    /// - `Ok(None)` — not enough data yet, call `feed()` with more bytes
    /// - `Err(...)` — MAC failure or protocol error (connection should be dropped)
    pub fn decode_frame(&mut self) -> Result<Option<Vec<u8>>> {
        // Need at least header to know frame size
        if self.buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // Peek at length (TODO: decrypt header first)
        let frame_len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        let total = FRAME_HEADER_LEN + frame_len + FRAME_MAC_LEN;

        if self.buf.len() < total {
            return Ok(None); // incomplete frame
        }

        // We have a full frame
        self.buf.advance(FRAME_HEADER_LEN);
        let mut payload_and_padding = self.buf.split_to(frame_len);
        let _mac = self.buf.split_to(FRAME_MAC_LEN);

        // TODO: verify MAC (Poly1305)
        //   nonce = nonce_seed XOR nonce_counter
        //   decrypt_in_place_detached(nonce, aad=[], &mut payload_and_padding, &mac_tag)
        //   → Error::FrameMacMismatch on failure

        // TODO: strip padding
        // The payload vs padding boundary is determined by the length_prng
        // For now return the whole buffer
        let payload = payload_and_padding.to_vec();

        self.nonce_counter += 1;
        Ok(Some(payload))
    }
}

//! Frame encoding/decoding for obfs4 data channel.

pub mod decoder;
pub mod encoder;
pub mod length_dist;

/// Maximum payload size per frame (obfs4 spec §3.5).
pub const MAX_FRAME_PAYLOAD: usize = 65535;
/// Frame header: 2-byte encrypted length field.
pub const FRAME_HEADER_LEN: usize = 2;
/// Poly1305 MAC appended to each frame.
pub const FRAME_MAC_LEN: usize = 16;
/// Maximum total frame size on the wire.
pub const MAX_FRAME_SIZE: usize = FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD + FRAME_MAC_LEN;

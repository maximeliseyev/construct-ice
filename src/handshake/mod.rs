//! obfs4 handshake: client and server state machines.

pub mod client;
pub mod server;

use crate::crypto::kdf::SessionKeys;

/// Maximum padding in a handshake message (obfs4 spec §3.4).
pub const MAX_HANDSHAKE_PADDING: usize = 8192;
/// Size of Elligator2 representative on the wire.
pub const REPR_LEN: usize = 32;
/// Size of HMAC-SHA256 truncated to 16 bytes in handshake.
pub const HANDSHAKE_MAC_LEN: usize = 16;

/// Result of a completed handshake — session keys ready for framing.
pub(crate) struct HandshakeResult {
    pub session_keys: SessionKeys,
}

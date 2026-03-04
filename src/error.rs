use thiserror::Error;

/// All errors produced by construct-obfs4.
#[derive(Debug, Error)]
pub enum Error {
    // ── Handshake ───────────────────────────────────────────────────────────
    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("invalid server public key: {0}")]
    InvalidServerPublicKey(String),

    #[error("handshake HMAC verification failed")]
    HandshakeMacMismatch,

    #[error("server rejected handshake")]
    HandshakeRejected,

    // ── Elligator2 ──────────────────────────────────────────────────────────
    #[error("point has no Elligator2 representative (retry required)")]
    NoElligatorRepresentative,

    // ── Framing ─────────────────────────────────────────────────────────────
    #[error("frame MAC verification failed — possible tampering")]
    FrameMacMismatch,

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    #[error("unexpected end of stream")]
    UnexpectedEof,

    // ── Key derivation ───────────────────────────────────────────────────────
    #[error("HKDF expand failed")]
    KdfError,

    // ── I/O ─────────────────────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

//! High-level transport API: Obfs4Stream and Obfs4Listener.
//!
//! These types wrap a TCP stream with the obfs4 handshake and framing,
//! presenting a standard `AsyncRead + AsyncWrite` interface to callers.
//! This means they're directly compatible with tonic and hyper.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use pin_project_lite::pin_project;
use rand::rngs::OsRng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};

use crate::{
    Result,
    crypto::keypair::StaticKeypair,
    framing::{decoder::FrameDecoder, encoder::FrameEncoder},
    handshake::{client::client_handshake, server::server_handshake},
};

// ── Client config ────────────────────────────────────────────────────────────

/// Configuration for the obfs4 client.
pub struct ClientConfig {
    /// Server's static public key (32 bytes, from bridge line or config).
    pub server_pubkey: [u8; 32],
}

impl ClientConfig {
    /// Create config from a base64-encoded server public key.
    pub fn from_pubkey_b64(b64: &str) -> Result<Self> {
        // TODO: base64 decode + validate 32 bytes
        let _ = b64;
        Ok(ClientConfig { server_pubkey: [0u8; 32] })
    }

    /// Create config directly from raw bytes.
    pub fn new(server_pubkey: [u8; 32]) -> Self {
        ClientConfig { server_pubkey }
    }
}

// ── Server config ────────────────────────────────────────────────────────────

/// Configuration for the obfs4 server.
pub struct ServerConfig {
    pub(crate) keypair: StaticKeypair,
}

impl ServerConfig {
    /// Generate a new random server identity keypair.
    pub fn generate() -> Self {
        ServerConfig {
            keypair: StaticKeypair::generate(&mut OsRng),
        }
    }

    /// Return the server's bridge line (for sharing with clients).
    /// Format: `cert=<base64>` as used in Tor bridge configuration.
    pub fn bridge_cert(&self) -> String {
        self.keypair.bridge_cert()
    }
}

// ── Obfs4Stream ──────────────────────────────────────────────────────────────

pin_project! {
    /// An obfs4-wrapped stream implementing `AsyncRead + AsyncWrite`.
    ///
    /// Obtained by calling [`Obfs4Stream::client_handshake`] or from
    /// [`Obfs4Listener::accept`]. Compatible with tonic and hyper as a
    /// custom transport.
    pub struct Obfs4Stream {
        #[pin]
        inner: TcpStream,
        encoder: FrameEncoder,
        decoder: FrameDecoder,
        read_buf: BytesMut,
    }
}

impl Obfs4Stream {
    /// Connect to an obfs4 server: performs TCP connect + handshake.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        Self::client_handshake(tcp, config).await
    }

    /// Perform client handshake over an existing TCP stream.
    pub async fn client_handshake(tcp: TcpStream, config: ClientConfig) -> Result<Self> {
        let (tcp, result) = client_handshake(tcp, &config.server_pubkey, &mut OsRng).await?;
        let keys = result.session_keys;

        Ok(Obfs4Stream {
            inner: tcp,
            encoder: FrameEncoder::new(
                &keys.client_to_server,
                &keys.client_nonce_seed,
                &keys.length_prng_seed,
            ),
            decoder: FrameDecoder::new(&keys.server_to_client, &keys.server_nonce_seed),
            read_buf: BytesMut::new(),
        })
    }
}

impl AsyncRead for Obfs4Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();

        // If we have buffered decoded data, return it first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Read raw bytes from TCP
        let mut raw = ReadBuf::new(&mut [0u8; 4096]); // TODO: avoid stack alloc
        let mut tmp = [0u8; 4096];
        let mut raw = ReadBuf::new(&mut tmp);
        match this.inner.poll_read(cx, &mut raw) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = raw.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }

                this.decoder.feed(filled);

                // Decode frames into read_buf
                loop {
                    match this.decoder.decode_frame() {
                        Ok(Some(payload)) => this.read_buf.extend_from_slice(&payload),
                        Ok(None) => break,
                        Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))),
                    }
                }

                // Return decoded data
                let n = buf.remaining().min(this.read_buf.len());
                if n > 0 {
                    buf.put_slice(&this.read_buf.split_to(n));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for Obfs4Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        let mut framed = BytesMut::new();
        if let Err(e) = this.encoder.encode(data, &mut framed) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())));
        }
        match this.inner.poll_write(cx, &framed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(data.len())),
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ── Obfs4Listener ────────────────────────────────────────────────────────────

/// An obfs4 server listener. Wraps `TcpListener` with obfs4 handshake.
pub struct Obfs4Listener {
    inner: TcpListener,
    config: ServerConfig,
}

impl Obfs4Listener {
    /// Bind to an address and start accepting obfs4 connections.
    pub async fn bind(addr: &str, config: ServerConfig) -> Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Obfs4Listener { inner, config })
    }

    /// Accept the next incoming obfs4 connection.
    ///
    /// Performs TCP accept + obfs4 server handshake.
    pub async fn accept(&self) -> Result<(Obfs4Stream, std::net::SocketAddr)> {
        let (tcp, addr) = self.inner.accept().await?;
        let (tcp, result) = server_handshake(tcp, &self.config.keypair, &mut OsRng).await?;
        let keys = result.session_keys;

        let stream = Obfs4Stream {
            inner: tcp,
            encoder: FrameEncoder::new(
                &keys.server_to_client,
                &keys.server_nonce_seed,
                &keys.length_prng_seed,
            ),
            decoder: FrameDecoder::new(&keys.client_to_server, &keys.client_nonce_seed),
            read_buf: BytesMut::new(),
        };

        Ok((stream, addr))
    }
}

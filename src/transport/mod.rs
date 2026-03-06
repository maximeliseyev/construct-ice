//! High-level transport API: Obfs4Stream and Obfs4Listener.
//!
//! These types wrap a TCP stream with the obfs4 handshake and framing,
//! presenting a standard `AsyncRead + AsyncWrite` interface to callers.
//! This means they're directly compatible with tonic and hyper.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
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
    crypto::keypair::{NodeId, StaticKeypair},
    framing::{
        decoder::{DecodedFrame, FrameDecoder},
        encoder::FrameEncoder,
    },
    handshake::{client::client_handshake, server::server_handshake},
    replay_filter::ReplayFilter,
};

// ── Client config ────────────────────────────────────────────────────────────

/// Configuration for the obfs4 client.
pub struct ClientConfig {
    /// Server's static public key B (32 bytes, from bridge cert).
    pub server_pubkey: [u8; 32],
    /// Server's Node ID (20 bytes, from bridge cert).
    pub node_id: NodeId,
}

impl ClientConfig {
    /// Create config from a base64-encoded bridge cert (pubkey || node_id).
    pub fn from_bridge_cert(cert: &str) -> Result<Self> {
        let (server_pubkey, node_id) = StaticKeypair::parse_bridge_cert(cert)?;
        Ok(ClientConfig { server_pubkey, node_id })
    }

    /// Create config directly from raw bytes.
    pub fn new(server_pubkey: [u8; 32], node_id: NodeId) -> Self {
        ClientConfig { server_pubkey, node_id }
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

    /// Create from an existing static keypair.
    pub fn from_keypair(keypair: StaticKeypair) -> Self {
        ServerConfig { keypair }
    }

    /// Return the server's bridge cert (base64-encoded pubkey || node_id).
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
        write_buf: BytesMut,
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
        let (tcp, result) = client_handshake(
            tcp,
            &config.server_pubkey,
            &config.node_id,
            &mut OsRng,
        ).await?;
        let keys = result.session_keys;

        Ok(Obfs4Stream {
            inner: tcp,
            // Client writes with C→S keys, reads with S→C keys
            encoder: FrameEncoder::new(
                &keys.c2s_key,
                &keys.c2s_nonce_prefix,
                &keys.c2s_siphash_key,
                &keys.c2s_siphash_iv,
            ),
            decoder: FrameDecoder::new(
                &keys.s2c_key,
                &keys.s2c_nonce_prefix,
                &keys.s2c_siphash_key,
                &keys.s2c_siphash_iv,
            ),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
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

        // Return buffered decoded data first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Read raw bytes from TCP
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
                        Ok(Some(DecodedFrame::Payload(payload))) => {
                            this.read_buf.extend_from_slice(&payload);
                        }
                        Ok(Some(DecodedFrame::PrngSeed(_seed))) => {
                            // TODO: update protocol polymorphism PRNG
                            continue;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )))
                        }
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
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        // Encode data into frames
        let mut framed = BytesMut::new();
        if let Err(e) = this.encoder.encode(data, &mut framed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }

        // Append to write buffer
        this.write_buf.extend_from_slice(&framed);

        // Try to flush as much as possible
        while !this.write_buf.is_empty() {
            let pinned = this.inner.as_mut();
            match pinned.poll_write(cx, this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Flush remaining write buffer
        while !this.write_buf.is_empty() {
            let pinned = this.inner.as_mut();
            match pinned.poll_write(cx, this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.inner.poll_flush(cx)
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
    replay_filter: Arc<Mutex<ReplayFilter>>,
}

impl Obfs4Listener {
    /// Bind to an address and start accepting obfs4 connections.
    pub async fn bind(addr: &str, config: ServerConfig) -> Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Obfs4Listener {
            inner,
            config,
            replay_filter: Arc::new(Mutex::new(ReplayFilter::new())),
        })
    }

    /// Accept the next incoming obfs4 connection.
    ///
    /// Performs TCP accept + obfs4 server handshake. Replayed handshakes
    /// (active probing defence) are silently rejected with a random delay.
    pub async fn accept(&self) -> Result<(Obfs4Stream, std::net::SocketAddr)> {
        let (tcp, addr) = self.inner.accept().await?;
        let (tcp, result) = server_handshake(
            tcp,
            &self.config.keypair,
            &mut OsRng,
            &self.replay_filter,
        ).await?;
        let keys = result.session_keys;

        let stream = Obfs4Stream {
            inner: tcp,
            // Server writes with S→C keys, reads with C→S keys
            encoder: FrameEncoder::new(
                &keys.s2c_key,
                &keys.s2c_nonce_prefix,
                &keys.s2c_siphash_key,
                &keys.s2c_siphash_iv,
            ),
            decoder: FrameDecoder::new(
                &keys.c2s_key,
                &keys.c2s_nonce_prefix,
                &keys.c2s_siphash_key,
                &keys.c2s_siphash_iv,
            ),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
        };

        Ok((stream, addr))
    }
}

//! # construct-ice
//!
//! obfs4 pluggable transport implementation in Rust.
//!
//! obfs4 makes traffic indistinguishable from random noise, providing
//! resistance against Deep Packet Inspection (DPI) systems.
//!
//! ## Architecture
//!
//! ```text
//! [App] ↔ [Obfs4Stream (AsyncRead+AsyncWrite)] ~~~ obfuscated TCP ~~~ [Obfs4Listener] ↔ [App]
//! ```
//!
//! ## Usage
//!
//! ### Client
//! ```rust,no_run
//! use construct_ice::{ClientConfig, Obfs4Stream};
//!
//! # async fn example() -> Result<(), construct_ice::Error> {
//! let config = ClientConfig::from_bridge_cert("base64_bridge_cert_here")?;
//! let mut stream = Obfs4Stream::connect("relay.example.com:443", config).await?;
//! // stream implements AsyncRead + AsyncWrite — pass to tonic/hyper
//! # Ok(())
//! # }
//! ```
//!
//! ### Server
//! ```rust,no_run
//! use construct_ice::{ServerConfig, Obfs4Listener};
//!
//! # async fn example() -> Result<(), construct_ice::Error> {
//! let config = ServerConfig::generate();
//! let listener = Obfs4Listener::bind("0.0.0.0:443", config).await?;
//! while let Ok((stream, addr)) = listener.accept().await {
//!     // stream implements AsyncRead + AsyncWrite
//!     tokio::spawn(async move { /* handle(stream) */ });
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod crypto;
pub mod framing;
pub mod handshake;
pub mod iat;
pub mod replay_filter;
pub mod transport;

mod error;

pub use error::Error;
pub use iat::IatMode;
pub use transport::{ClientConfig, Obfs4Listener, Obfs4Stream, ServerConfig};

/// Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

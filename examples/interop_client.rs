//! Minimal obfs4 client for local interop testing.
//! Usage: cargo run --example interop_client -- <addr> <server_pubkey_hex>

use construct_obfs4::{ClientConfig, Obfs4Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:54321".to_string());
    println!("Connecting to obfs4 server at {addr}...");

    // TODO: parse server pubkey from args
    let config = ClientConfig::new([0u8; 32]);
    let mut stream = Obfs4Stream::connect(&addr, config).await?;

    stream.write_all(b"hello from construct-obfs4").await?;

    let mut response = [0u8; 64];
    let n = stream.read(&mut response).await?;
    println!("Server echoed: {:?}", &response[..n]);

    Ok(())
}

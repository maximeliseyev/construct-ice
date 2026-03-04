//! Client-side obfs4 handshake.
//!
//! ## Wire format
//! ```text
//! ClientHandshake = epk_repr[32] || padding[0..8192] || MAC[16]
//! ```
//! - `epk_repr` — ephemeral public key encoded via Elligator2
//! - `padding`  — random bytes, length chosen by SipHash PRNG seeded from server pubkey
//! - `MAC`      — HMAC-SHA256(key=server_pubkey, msg=epk_repr || epoch_hours)[0..16]
//!                epoch_hours = Unix time / 3600, encoded as ASCII decimal

use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    Result,
    crypto::{
        keypair::EphemeralKeypair,
        kdf::{SessionKeys, derive_mac_key},
    },
    handshake::{HANDSHAKE_MAC_LEN, MAX_HANDSHAKE_PADDING, REPR_LEN, HandshakeResult},
};

type HmacSha256 = Hmac<Sha256>;

/// Perform the client side of the obfs4 handshake.
///
/// # Arguments
/// * `stream`      — underlying TCP stream (raw, no TLS)
/// * `server_pubkey` — server's static Ed25519/X25519 public key (32 bytes)
/// * `rng`         — cryptographic RNG
///
/// # Returns
/// `HandshakeResult` containing session keys for framing.
pub(crate) async fn client_handshake<S, R>(
    mut stream: S,
    server_pubkey: &[u8; 32],
    rng: &mut R,
) -> Result<(S, HandshakeResult)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RngCore + CryptoRng,
{
    // 1. Generate ephemeral keypair (guaranteed Elligator2-representable)
    let epk = EphemeralKeypair::generate(rng);

    // 2. Build padding — random length, seeded from server pubkey
    let padding_len = choose_padding_length(server_pubkey, rng);
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);

    // 3. Compute MAC = HMAC-SHA256(server_pubkey)[0..16]
    //    over: epk_repr || epoch_hours_ascii
    let epoch_hours = epoch_hours_str();
    let mac_key = derive_mac_key(server_pubkey);
    let mac = compute_handshake_mac(&mac_key, &epk.representative, epoch_hours.as_bytes());

    // 4. Send: epk_repr || padding || mac
    let mut msg = Vec::with_capacity(REPR_LEN + padding_len + HANDSHAKE_MAC_LEN);
    msg.extend_from_slice(&epk.representative);
    msg.extend_from_slice(&padding);
    msg.extend_from_slice(&mac);
    stream.write_all(&msg).await?;

    // 5. Read server response: server_repr[32] || MAC[16] || padding[...]
    let mut server_repr = [0u8; REPR_LEN];
    stream.read_exact(&mut server_repr).await?;

    let mut server_mac = [0u8; HANDSHAKE_MAC_LEN];
    stream.read_exact(&mut server_mac).await?;

    // 6. TODO: verify server MAC

    // 7. DH: scalar_mult(our_secret, server_repr → decode → point)
    // TODO: elligator2::decode(server_repr) → server_point
    // TODO: dh_output = x25519(epk.secret, server_point)
    let dh_output = [0u8; 32]; // placeholder

    // 8. Derive session keys
    let session_keys = SessionKeys::derive(&dh_output, &epk.representative, &server_repr)?;

    Ok((stream, HandshakeResult { session_keys }))
}

fn compute_handshake_mac(key: &[u8; 32], repr: &[u8; 32], epoch_hours: &[u8]) -> [u8; HANDSHAKE_MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length ok");
    mac.update(repr);
    mac.update(epoch_hours);
    let full = mac.finalize().into_bytes();
    full[..HANDSHAKE_MAC_LEN].try_into().unwrap()
}

fn epoch_hours_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (secs / 3600).to_string()
}

/// Choose padding length using a deterministic distribution seeded from
/// server pubkey — this makes padding length unpredictable to an observer
/// who doesn't know the server key, while both sides agree on parameters.
fn choose_padding_length<R: RngCore>(server_pubkey: &[u8; 32], rng: &mut R) -> usize {
    // TODO: use SipHash PRNG seeded from server_pubkey for deterministic distribution
    // For now: uniform random in [0, MAX_HANDSHAKE_PADDING]
    let _ = server_pubkey;
    (rng.next_u32() as usize) % MAX_HANDSHAKE_PADDING
}

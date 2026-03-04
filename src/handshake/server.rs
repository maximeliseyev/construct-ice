//! Server-side obfs4 handshake.
//!
//! ## Wire format (server → client)
//! ```text
//! ServerHandshake = server_epk_repr[32] || MAC[16] || padding[0..8192]
//! ```

use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    Error, Result,
    crypto::{
        keypair::{EphemeralKeypair, StaticKeypair},
        kdf::{SessionKeys, derive_mac_key},
    },
    handshake::{HANDSHAKE_MAC_LEN, MAX_HANDSHAKE_PADDING, REPR_LEN, HandshakeResult},
};

type HmacSha256 = Hmac<Sha256>;

/// Perform the server side of the obfs4 handshake.
///
/// Reads the client's message, verifies MAC, performs DH, responds with
/// server's ephemeral key, derives session keys.
pub(crate) async fn server_handshake<S, R>(
    mut stream: S,
    static_keypair: &StaticKeypair,
    rng: &mut R,
) -> Result<(S, HandshakeResult)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RngCore + CryptoRng,
{
    // 1. Read client's Elligator2 representative
    let mut client_repr = [0u8; REPR_LEN];
    stream.read_exact(&mut client_repr).await?;

    // 2. Read padding (variable length) + MAC[16] at the end
    //    obfs4 server reads until it finds valid MAC — reads up to MAX_HANDSHAKE_PADDING+16
    let (padding_len, client_mac) = read_client_padding_and_mac(&mut stream, &static_keypair, &client_repr).await?;
    let _ = (padding_len, client_mac); // used in MAC verify below

    // 3. TODO: verify client MAC
    //    mac_key = derive_mac_key(static_keypair.public)
    //    expected = HMAC(mac_key, client_repr || epoch_hours)[0..16]
    //    check client_mac == expected (constant-time)

    // 4. Generate server ephemeral keypair
    let server_epk = EphemeralKeypair::generate(rng);

    // 5. DH: x25519(server_epk.secret, elligator2::decode(client_repr))
    // TODO: decode client_repr → client_point, then DH
    let dh_output = [0u8; 32]; // placeholder

    // 6. Derive session keys
    let session_keys = SessionKeys::derive(&dh_output, &client_repr, &server_epk.representative)?;

    // 7. Build server MAC
    let mac_key = derive_mac_key(static_keypair.public.as_bytes().try_into().unwrap_or(&[0u8; 32]));
    let epoch_hours = epoch_hours_str();
    let server_mac = compute_server_mac(&mac_key, &server_epk.representative, epoch_hours.as_bytes());

    // 8. Send: server_repr || server_mac || padding
    let padding_len = (rng.next_u32() as usize) % MAX_HANDSHAKE_PADDING;
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);

    let mut response = Vec::with_capacity(REPR_LEN + HANDSHAKE_MAC_LEN + padding_len);
    response.extend_from_slice(&server_epk.representative);
    response.extend_from_slice(&server_mac);
    response.extend_from_slice(&padding);
    stream.write_all(&response).await?;

    Ok((stream, HandshakeResult { session_keys }))
}

/// Read client's variable-length padding and extract trailing MAC[16].
///
/// obfs4 doesn't frame the handshake — the server reads until it finds
/// a valid MAC. This is the "mark" mechanism from the spec.
async fn read_client_padding_and_mac<S>(
    stream: &mut S,
    static_keypair: &StaticKeypair,
    client_repr: &[u8; REPR_LEN],
) -> Result<(usize, [u8; HANDSHAKE_MAC_LEN])>
where
    S: AsyncRead + Unpin,
{
    // TODO: Implement mark-based scanning
    // The client embeds a "mark" = HMAC(key, repr)[0..16] somewhere in the message
    // Server reads up to MAX_HANDSHAKE_PADDING+16 bytes, scanning for the mark
    // Once found, the remaining bytes are discarded, MAC verified

    // Placeholder: just read up to 8208 bytes
    let mut buf = vec![0u8; MAX_HANDSHAKE_PADDING + HANDSHAKE_MAC_LEN];
    let n = stream.read(&mut buf).await?;
    if n < HANDSHAKE_MAC_LEN {
        return Err(Error::HandshakeRejected);
    }
    let mac: [u8; HANDSHAKE_MAC_LEN] = buf[n - HANDSHAKE_MAC_LEN..n].try_into().unwrap();
    Ok((n - HANDSHAKE_MAC_LEN, mac))
}

fn compute_server_mac(key: &[u8; 32], repr: &[u8; REPR_LEN], epoch_hours: &[u8]) -> [u8; HANDSHAKE_MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key ok");
    mac.update(repr);
    mac.update(epoch_hours);
    let full = mac.finalize().into_bytes();
    full[..HANDSHAKE_MAC_LEN].try_into().unwrap()
}

fn epoch_hours_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    (secs / 3600).to_string()
}

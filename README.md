# construct-ice

obfs4 pluggable transport implementation in Rust for Construct messenger.

Makes gRPC traffic indistinguishable from random noise — resistance against DPI systems
used in censorship (Iran, China, Russia).

## Status

| Component | Status |
|-----------|--------|
| Elligator2 encode/decode | ✅ Randomized variant, Go cross-tested (10 vectors) |
| Keypair generation | ✅ Dirty pubkey from representative |
| ntor handshake crypto | ✅ Go cross-tested (KEY_SEED, AUTH) |
| KDF (HKDF-SHA256) | ✅ Go cross-tested (144-byte session keys) |
| Handshake (client + server) | ✅ Mark scanning, MAC with clock skew |
| Frame encoder/decoder | ✅ NaCl secretbox + SipHash OFB length obfuscation |
| Protocol polymorphism (PRNG seed) | ✅ Full re-key on every PrngSeed frame (IAT + length obf) |
| AsyncRead/AsyncWrite transport | ✅ Obfs4Stream, Obfs4Listener |
| WebTunnel v2 transport | ✅ HTTP UPGRADE, path auth token, TLS SNI domain-fronting |
| Prometheus metrics | ✅ Relay stats + replay eviction counter (feature = "metrics") |
| E2E tests | ✅ Echo, multi-round-trip, large payload, multi-session |
| tonic/hyper integration | ⏳ planned (Obfs4Stream is compatible) |
| iOS interop | ✅ FFI bindings via construct-core (UniFFI) |

## Protocol Polymorphism

Every construct-ice connection is cryptographically distinct from every other connection —
including connections from the same client to the same relay.

This is achieved through **PRNG seed re-keying**: during and after the handshake, both sides
exchange a `PrngSeed` frame containing 24 random bytes. On receipt, both sides independently
re-derive:

1. **IAT RNG state** — controls inter-arrival timing jitter. New seed = `ChaCha8(prng_seed)`.
2. **Length obfuscator key** — SipHash-2-4 OFB mode. New key+IV derived from `SHA-256(prng_seed)[0..24]`.

Because both sides apply the re-key to the same seed in the same order, they stay in sync
without any additional round-trip.

**Effect on DPI classifiers:** a machine learning classifier trained on one session's frame
length distribution will fail on any subsequent session — even from the same device to the
same relay — because the SipHash key changes every time.

### PrngSeed re-key sites

| Site | When | Who sends |
|------|------|-----------|
| Client handshake trailing bytes | After ntor KDF, before first data frame | Client |
| Server `accept_with_cert()` | After server sends seed, before first data frame | Server |
| `poll_read()` mid-stream | Any time the other side wishes to rotate | Either |

Both IAT RNG and length obfuscator are re-keyed at every site — the original Go obfs4
implementation only re-seeded the IAT RNG.

---

## Known Deviations from obfs4 Spec

These are intentional changes made for compatibility or security reasons. They do not
affect wire compatibility with the Go reference implementation unless noted.

### 1. Minimum client padding: 77 bytes (spec: 85)

The Go reference implementation sends a minimum of 85 bytes of client random padding.
construct-ice sends a minimum of **77 bytes** (`MAC_LENGTH(32) + MIN_HANDSHAKE_LENGTH(45)`).

**Reason:** Earlier iOS versions of the client relied on 77-byte minimum for packet
alignment. The deviation is safe — both values provide adequate padding to prevent
fingerprinting the handshake length. Go servers accept any padding ≥ 0.

**Wire compatibility:** ✅ Go server accepts construct-ice clients. Go clients accepted by
construct-ice server (Go sends ≥ 85, which is > 77 minimum).

### 2. Nonce wraparound: connection termination (spec: undefined)

The obfs4 spec does not define behavior when the 64-bit frame counter (nonce) wraps around.
construct-ice uses `u64::checked_add` for the nonce — if it would overflow, the encode/decode
returns an error and the connection is torn down cleanly.

**Practical impact:** 2⁶⁴ frames × minimum frame size ≈ **18 exabytes** of data per session.
A connection will not live long enough to encounter wraparound under any realistic usage.
The check is a defence-in-depth measure against potential counter-manipulation exploits.

### 3. Length obfuscator re-keying on PrngSeed (spec: IAT only)

The original obfs4 spec says PrngSeed updates the IAT RNG only. construct-ice also re-keys
the SipHash-2-4 length obfuscator. See [Protocol Polymorphism](#protocol-polymorphism) above.

**Wire compatibility:** ✅ Both sides use the same seed, so they derive the same new key.
Go clients connecting to a construct-ice server will **not** re-key their length obfuscator —
this is safe because the server re-keys only its encoder, which the Go client's decoder does
not need to know about.

---

## Architecture

```
[iOS gRPC] ↔ [obfs4 client] ~~~ obfuscated TCP ~~~ [obfs4 server] ↔ [Traefik/Envoy]
```

```
src/
  crypto/
    elligator2.rs    ← Curve25519 ↔ random bytes (Randomized variant)
    keypair.rs       ← ephemeral keypair with Elligator2 retry loop
    ntor.rs          ← ntor handshake key exchange (double DH)
    kdf.rs           ← HKDF-SHA256 → 144-byte session key block
  handshake/
    client.rs        ← client handshake state machine
    server.rs        ← server handshake + mark scanning + anti-probing
  framing/
    encoder.rs       ← NaCl secretbox frame encryption
    decoder.rs       ← frame decryption + MAC verification
    length_dist.rs   ← SipHash-2-4 OFB length obfuscation
  transport/
    mod.rs           ← Obfs4Stream (AsyncRead+AsyncWrite), Obfs4Listener
```

## Usage

### Client
```rust
use construct_obfs4::{ClientConfig, Obfs4Stream};

let config = ClientConfig::from_bridge_cert("base64_bridge_cert")?;
let mut stream = Obfs4Stream::connect("relay.example.com:443", config).await?;
// stream implements AsyncRead + AsyncWrite — pass to tonic/hyper
```

### Server
```rust
use construct_obfs4::{ServerConfig, Obfs4Listener};

let config = ServerConfig::generate();
println!("Bridge cert: {}", config.bridge_cert()); // distribute to clients
let listener = Obfs4Listener::bind("0.0.0.0:443", config).await?;
while let Ok((stream, addr)) = listener.accept().await {
    tokio::spawn(async move { /* handle(stream) */ });
}
```

## Testing

```bash
# Run all tests (unit + E2E + doctests)
cargo test

# Run only Go cross-reference vector tests
cargo test go_reference

# Run E2E integration tests
cargo test --test e2e
```

## References

- [obfs4 spec](https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt)
- [Elligator2 paper](https://elligator.cr.yp.to/elligator-20130828.pdf)
- [Go reference implementation](https://gitlab.com/yawning/obfs4)
- [curve25519-elligator2](https://docs.rs/curve25519-elligator2)

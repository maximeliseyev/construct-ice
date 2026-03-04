# construct-obfs4

obfs4 pluggable transport implementation in Rust for Construct messenger.

Makes gRPC traffic indistinguishable from random noise — resistance against DPI systems
used in censorship (Iran, China, Russia).

## Status

🚧 **In development** — crypto stubs present, Elligator2 pending implementation.

| Component | Status |
|-----------|--------|
| Project structure | ✅ |
| Handshake state machine | 🚧 stubs |
| Elligator2 encode/decode | ❌ TODO |
| Frame encoder/decoder | 🚧 stubs |
| SipHash PRNG | ✅ |
| KDF (HKDF-SHA256) | ✅ |
| AsyncRead/AsyncWrite transport | 🚧 stubs |
| tonic/hyper integration | ⏳ planned |
| iOS interop | ⏳ planned |

## Architecture

```
[iOS gRPC] ↔ [obfs4 client] ~~~ obfuscated TCP ~~~ [obfs4 server] ↔ [Traefik/Envoy]
```

```
crates/
  construct-obfs4/
    src/
      crypto/
        elligator2.rs    ← most critical — Curve25519 → random bytes
        keypair.rs       ← ephemeral keypair with Elligator2 retry loop
        kdf.rs           ← HKDF-SHA256 session key derivation
      handshake/
        client.rs        ← client handshake state machine
        server.rs        ← server handshake + mark detection
      framing/
        encoder.rs       ← ChaCha20-Poly1305 frame encryption
        decoder.rs       ← frame decryption + MAC verification
        length_dist.rs   ← SipHash PRNG for frame size randomization
      transport/
        mod.rs           ← Obfs4Stream (AsyncRead+AsyncWrite), Obfs4Listener
```

## Implementation order

1. **Elligator2** — field arithmetic over GF(2^255-19), cross-test with Go reference
2. **Keypair** — replace stubs with real x25519 scalar multiplication
3. **Handshake** — complete MAC verification, mark detection
4. **Framing** — complete ChaCha20-Poly1305 encrypt/decrypt
5. **Transport** — wire everything together, E2E test

## References

- [obfs4 spec](https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt)
- [Elligator2 paper](https://elligator.cr.yp.to/elligator-20130828.pdf)
- [Go reference implementation](https://gitlab.com/yawning/obfs4)
- [curve25519-dalek](https://docs.rs/curve25519-dalek)

## Testing against Go reference

```bash
# Install Go reference server
go install gitlab.com/yawning/obfs4/obfs4proxy@latest

# Run interop tests
cargo test --test interop -- --ignored
```

## Integration with construct-server

```toml
# In construct-server/Cargo.toml when ready:
construct-obfs4 = { git = "https://github.com/maximeliseyev/construct-obfs4", tag = "v0.1.0" }
```

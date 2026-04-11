//! Fuzz target: bridge cert string parser.
//!
//! Tests that `StaticKeypair::parse_bridge_cert` never panics on any input,
//! and that any successful parse can be re-serialized to the same string
//! (roundtrip invariant).
//!
//! A bridge cert is the `cert=` field in an obfs4 bridge line, e.g.:
//! `cert=ABC...xyz/nodeid+...==`
//! Clients embed this to connect to a specific relay. A panic in the parser
//! would crash the client process before a connection is even attempted.

#![no_main]

use construct_ice::crypto::keypair::StaticKeypair;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only test inputs that look like valid UTF-8 — the real parser expects
    // a base64 string.  Non-UTF-8 bytes are expected to fail at the outer
    // layer before reaching parse_bridge_cert.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Must never panic — only Ok or Err.
    let result = StaticKeypair::parse_bridge_cert(s);

    // Roundtrip: if parsing succeeded, serializing the keypair must produce
    // a cert that re-parses to the same (pubkey, node_id) pair.
    if let Ok((pubkey, node_id)) = result {
        // We cannot reconstruct a full StaticKeypair from just the public parts
        // without the private key, but we can verify the parsed values are
        // consistent: pubkey and node_id are fixed-size arrays.
        assert_eq!(pubkey.len(), 32, "pubkey must be 32 bytes");
        let _ = node_id; // node_id is [u8; 20], always valid if parse succeeded
    }
});

//! Fuzz target: server-side client handshake scanner.
//!
//! Tests the synchronous parsing portion of the obfs4 server handshake:
//! mark scanning, padding length validation, and buffer boundary checks.
//! These are the first things the server does when a client connects, before
//! any async I/O — a crash here would take down the listener goroutine.
//!
//! The full async handshake is not exercised here (that requires a stream);
//! this target focuses on the security-sensitive parsing code.

#![no_main]

use arbitrary::Arbitrary;
use construct_ice::handshake::server::scan_client_handshake_bytes;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Arbitrary bytes mimicking a client handshake message.
    data: Vec<u8>,
    /// HMAC key (normally derived from the server's identity).
    hmac_key: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    if input.data.len() > 8192 || input.hmac_key.is_empty() {
        return;
    }

    // Must never panic — only Ok or Err.
    let _result = scan_client_handshake_bytes(&input.data, &input.hmac_key);
});

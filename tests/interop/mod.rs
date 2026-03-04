//! Interoperability tests against the Go reference obfs4 implementation.
//!
//! These tests require a running Go obfs4 server. See README.md for setup.
//!
//! Run with: `cargo test --test interop -- --ignored`

/// Test that our client can complete a handshake with the Go reference server.
#[tokio::test]
#[ignore = "requires Go reference server running on localhost:54321"]
async fn test_handshake_with_go_server() {
    // TODO: start Go server as subprocess
    // let server = GoObfs4Server::start("54321").await;
    //
    // let stream = construct_obfs4::Obfs4Stream::connect(
    //     "127.0.0.1:54321",
    //     construct_obfs4::ClientConfig::from_pubkey_b64(&server.bridge_cert()).unwrap(),
    // ).await.unwrap();
    //
    // // Send test payload
    // stream.write_all(b"hello obfs4").await.unwrap();
    // let mut resp = [0u8; 11];
    // stream.read_exact(&mut resp).await.unwrap();
    // assert_eq!(&resp, b"hello obfs4");
    todo!("implement Go server subprocess helper")
}

/// Test Elligator2 encode/decode round-trip against Go reference vectors.
#[test]
fn test_elligator2_round_trip_vectors() {
    // TODO: add known-good test vectors from Go reference implementation
    // Format: (secret_key_hex, expected_repr_hex)
    let _vectors: &[(&str, &str)] = &[
        // ("deadbeef...", "cafebabe..."),
    ];
    todo!("add test vectors from Go obfs4 source: transports/obfs4/obfs4_test.go")
}

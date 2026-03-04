use criterion::{Criterion, criterion_group, criterion_main};
use bytes::BytesMut;
use construct_obfs4::framing::encoder::FrameEncoder;

fn bench_frame_encode(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce_seed = [0u8; 32];
    let length_seed = [0u8; 16];
    let payload = vec![0xab_u8; 4096];

    c.bench_function("encode 4KB frame", |b| {
        b.iter(|| {
            let mut encoder = FrameEncoder::new(&key, &nonce_seed, &length_seed);
            let mut dst = BytesMut::new();
            encoder.encode(&payload, &mut dst).unwrap();
        });
    });

    c.bench_function("encode 64KB frame", |b| {
        let large = vec![0xab_u8; 65535];
        b.iter(|| {
            let mut encoder = FrameEncoder::new(&key, &nonce_seed, &length_seed);
            let mut dst = BytesMut::new();
            encoder.encode(&large, &mut dst).unwrap();
        });
    });
}

criterion_group!(benches, bench_frame_encode);
criterion_main!(benches);

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gobble::{
    aarch64::{get_permute_bit, index_to_tweak, xor128},
    traits::GarblingInstance,
    *,
};
use std::arch::aarch64::*;

fn bench_garble_xor_gate(c: &mut Criterion) {
    c.bench_function("garble_xor_gate", |b| unsafe {
        // Setup once: create instance and working space
        let seed = 0x0123456789ABCDEF_FEDCBA9876543210u128;
        let delta_bytes = [0xFFu8; 16];
        let delta = vld1q_u8(&delta_bytes as *const u8);

        let mut instance = GarbEngine::new(10, delta);

        // Measure: just the XOR gate garbling
        b.iter(|| {
            instance.feed_xor_gate(black_box(0), black_box(1), black_box(2));
            black_box(&instance);
        });
    });
}

fn bench_garble_and_gate(c: &mut Criterion) {
    c.bench_function("garble_and_gate", |b| unsafe {
        // Setup once: create instance and working space
        let seed = 0x0123456789ABCDEF_FEDCBA9876543210u128;
        let delta_bytes = [0xFFu8; 16];
        let delta = vld1q_u8(&delta_bytes as *const u8);

        let mut instance = GarbEngine::new(10, delta);

        // Measure: just the AND gate garbling
        b.iter(|| {
            let ciphertext = instance.feed_and_gate(black_box(0), black_box(1), black_box(2));
            black_box(ciphertext);
        });
    });
}

fn bench_garble_mixed_gates(c: &mut Criterion) {
    c.bench_function("garble_mixed_100_gates", |b| unsafe {
        // Setup once: create instance with enough space for 100 gates
        let seed = 0x0123456789ABCDEF_FEDCBA9876543210u128;
        let delta_bytes = [0xFFu8; 16];
        let delta = vld1q_u8(&delta_bytes as *const u8);
        let round_key = vld1q_u8(&seed.to_le_bytes() as *const u8);

        let mut instance = GarbEngine::new(200, delta);

        // Measure: 50 XOR + 50 AND gates
        b.iter(|| {
            let mut ciphertexts = Vec::with_capacity(50);

            for i in 0..50 {
                let in1 = black_box(i * 2);
                let in2 = black_box(i * 2 + 1);
                let out = black_box(100 + i);

                // XOR gate
                instance.feed_xor_gate(in1, in2, out);

                // AND gate
                let ct = instance.feed_and_gate(in1, in2, out + 50);
                ciphertexts.push(ct);
            }

            black_box(ciphertexts);
        });
    });
}

fn bench_xor128(c: &mut Criterion) {
    c.bench_function("xor128", |bencher| unsafe {
        let a_bytes = [0x42u8; 16];
        let b_bytes = [0x99u8; 16];
        let a = vld1q_u8(&a_bytes as *const u8);
        let b = vld1q_u8(&b_bytes as *const u8);

        bencher.iter(|| {
            let result = xor128(black_box(a), black_box(b));
            black_box(result)
        });
    });
}

fn bench_get_permute_bit(c: &mut Criterion) {
    c.bench_function("get_permute_bit", |b| unsafe {
        let label_bytes = [0x42u8; 16];
        let label = vld1q_u8(&label_bytes as *const u8);

        b.iter(|| {
            let result = get_permute_bit(black_box(label));
            black_box(result)
        });
    });
}

fn bench_index_to_tweak(c: &mut Criterion) {
    c.bench_function("index_to_tweak", |b| {
        b.iter(|| unsafe {
            let result = index_to_tweak(black_box(123456));
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_garble_xor_gate,
    bench_garble_and_gate,
    bench_garble_mixed_gates,
    bench_xor128,
    bench_get_permute_bit,
    bench_index_to_tweak
);

criterion_main!(benches);

//! Benchmarks for gobble garbling and evaluation operations
#![expect(missing_docs)]
#![allow(unused_crate_dependencies)]

use std::mem::transmute;

#[cfg(target_arch = "x86_64")]
type Vector128 = std::arch::x86_64::__m128i;
#[cfg(target_arch = "aarch64")]
type Vector128 = std::arch::aarch64::uint8x16_t;

use bitvec::vec::BitVec;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gobble::{
    Engine,
    traits::{
        EvaluationInstance, EvaluationInstanceConfig, GarblingInstance, GarblingInstanceConfig,
        GobbleEngine,
    },
};

#[cfg(target_arch = "aarch64")]
use gobble::aarch64::{Ciphertext, get_permute_bit, index_to_tweak, xor128};

#[cfg(target_arch = "x86_64")]
use gobble::x86_64::{Ciphertext, get_permute_bit, index_to_tweak, xor128};

fn bench_garble_xor_gate(c: &mut Criterion) {
    c.bench_function("garble_xor_gate", |b| {
        // Setup once: create instance and working space
        let delta_bytes = [0xFFu8; 16];
        let primary_input_false_labels = vec![];

        let config = GarblingInstanceConfig {
            scratch_space: 10,
            delta: delta_bytes,
            primary_input_false_labels: &primary_input_false_labels,
        };

        let engine = Engine::new();
        let mut instance = engine.new_garbling_instance(config);

        // Measure: just the XOR gate garbling
        b.iter(|| {
            instance.feed_xor_gate(black_box(0), black_box(1), black_box(2));
            black_box(&instance);
        });
    });
}

fn bench_garble_and_gate(c: &mut Criterion) {
    c.bench_function("garble_and_gate", |b| {
        // Setup once: create instance and working space
        let delta_bytes = [0xFFu8; 16];
        let primary_input_false_labels = vec![];

        let config = GarblingInstanceConfig {
            scratch_space: 10,
            delta: delta_bytes,
            primary_input_false_labels: &primary_input_false_labels,
        };

        let engine = Engine::new();
        let mut instance = engine.new_garbling_instance(config);

        // Measure: just the AND gate garbling
        b.iter(|| {
            let ciphertext = instance.feed_and_gate(black_box(0), black_box(1), black_box(2));
            black_box(ciphertext);
        });
    });
}

fn bench_garble_mixed_gates(c: &mut Criterion) {
    c.bench_function("garble_mixed_100_gates", |b| {
        // Setup once: create instance with enough space for 100 gates
        let delta_bytes = [0xFFu8; 16];
        let primary_input_false_labels = vec![];

        let config = GarblingInstanceConfig {
            scratch_space: 200,
            delta: delta_bytes,
            primary_input_false_labels: &primary_input_false_labels,
        };

        let engine = Engine::new();
        let mut instance = engine.new_garbling_instance(config);

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

fn bench_eval_xor_gate(c: &mut Criterion) {
    c.bench_function("eval_xor_gate", |b| {
        // Setup once: create instance with dummy labels
        let selected_primary_input_labels = vec![];
        let selected_primary_input_values = BitVec::repeat(false, 0);

        let config = EvaluationInstanceConfig {
            scratch_space: 10,
            selected_primary_input_labels: &selected_primary_input_labels,
            selected_primary_input_values: &selected_primary_input_values,
        };

        let engine = Engine::new();
        let mut instance = engine.new_evaluation_instance(config);

        // Measure: just the XOR gate evaluation
        b.iter(|| {
            instance.feed_xor_gate(black_box(0), black_box(1), black_box(2));
            black_box(&instance);
        });
    });
}

fn bench_eval_and_gate(c: &mut Criterion) {
    c.bench_function("eval_and_gate", |b| {
        // Setup once: create instance with dummy labels
        let selected_primary_input_labels = vec![];
        let selected_primary_input_values = BitVec::repeat(false, 0);

        let config = EvaluationInstanceConfig {
            scratch_space: 10,
            selected_primary_input_labels: &selected_primary_input_labels,
            selected_primary_input_values: &selected_primary_input_values,
        };

        let engine = Engine::new();
        let mut instance = engine.new_evaluation_instance(config);

        // Create dummy ciphertext
        let ct_bytes = [0xAAu8; 16];
        let ciphertext = Ciphertext::from(ct_bytes);

        // Measure: just the AND gate evaluation
        b.iter(|| {
            instance.feed_and_gate(
                black_box(0),
                black_box(1),
                black_box(2),
                black_box(ciphertext),
            );
            black_box(&instance);
        });
    });
}

fn bench_eval_mixed_gates(c: &mut Criterion) {
    c.bench_function("eval_mixed_100_gates", |b| {
        // Setup once: create instance with enough space for 100 gates
        let selected_primary_input_labels = vec![];
        let selected_primary_input_values = BitVec::repeat(false, 0);

        let config = EvaluationInstanceConfig {
            scratch_space: 200,
            selected_primary_input_labels: &selected_primary_input_labels,
            selected_primary_input_values: &selected_primary_input_values,
        };

        let engine = Engine::new();
        let mut instance = engine.new_evaluation_instance(config);

        // Create dummy ciphertexts
        let ct_bytes = [0xAAu8; 16];
        let ciphertext = Ciphertext::from(ct_bytes);

        // Measure: 50 XOR + 50 AND gates
        b.iter(|| {
            for i in 0..50 {
                let in1 = black_box(i * 2);
                let in2 = black_box(i * 2 + 1);
                let out = black_box(100 + i);

                // XOR gate
                instance.feed_xor_gate(in1, in2, out);

                // AND gate
                instance.feed_and_gate(in1, in2, out + 50, black_box(ciphertext));
            }

            black_box(&instance);
        });
    });
}

fn bench_xor128(c: &mut Criterion) {
    c.bench_function("xor128", |bencher| unsafe {
        let a_bytes = [0x42u8; 16];
        let b_bytes = [0x99u8; 16];
        let a = transmute::<[u8; 16], Vector128>(a_bytes);
        let b = transmute::<[u8; 16], Vector128>(b_bytes);

        bencher.iter(|| {
            let result = xor128(black_box(a), black_box(b));
            black_box(result)
        });
    });
}

fn bench_get_permute_bit(c: &mut Criterion) {
    c.bench_function("get_permute_bit", |b| unsafe {
        let label_bytes = [0x42u8; 16];
        let label = transmute::<[u8; 16], Vector128>(label_bytes);

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
    bench_eval_xor_gate,
    bench_eval_and_gate,
    bench_eval_mixed_gates,
    bench_xor128,
    bench_get_permute_bit,
    bench_index_to_tweak
);

criterion_main!(benches);

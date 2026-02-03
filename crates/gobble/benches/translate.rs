//! Benchmarks for translation operations
// This benchmark uses fixed, rather than variable inputs.
// For some reason, the numbers obtain this way are, on extrapolating, more representative of the e2e timings.
#![expect(missing_docs)]
#![allow(unused_crate_dependencies)]

use ckt_gobble::{
    BitLabel,
    ByteLabel,
    Label,
    expand_seed,
    // Input translation
    generate_input_translation_material,
    // Output translation
    generate_output_translation_material,
    translate_input,
    translate_output,
    wide_hash_2x,
    wide_hash_8x,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_wide_hash_8x(c: &mut Criterion) {
    c.bench_function("wide_hash_8x", |b| {
        let label = Label::from([0x42u8; 16]);
        let index = 12345u64;

        b.iter(|| {
            let result = wide_hash_8x(black_box(label), black_box(index));
            black_box(result)
        });
    });
}

fn bench_generate_input_translation_material(c: &mut Criterion) {
    c.bench_function("generate_input_translation_material", |b| {
        // Setup: generate byte label and bit labels
        let seed = [42u8; 32];
        let (byte_labels, _) = expand_seed(seed, 256);
        let byte_label = ByteLabel::new(byte_labels.try_into().unwrap());

        let seed2 = [43u8; 32];
        let (bit_labels_flat, _) = expand_seed(seed2, 16);
        let default_label = Label::default();
        let mut bit_labels = [BitLabel::new([default_label, default_label]); 8];
        for i in 0..8 {
            bit_labels[i] = BitLabel::new([bit_labels_flat[i * 2], bit_labels_flat[i * 2 + 1]]);
        }

        b.iter(|| {
            let result = generate_input_translation_material(
                black_box(0),
                black_box(byte_label),
                black_box(bit_labels),
            );
            black_box(result)
        });
    });
}

fn bench_translate_input(c: &mut Criterion) {
    c.bench_function("translate_input", |b| {
        // Setup: generate translation material
        let seed = [42u8; 32];
        let (byte_labels, _) = expand_seed(seed, 256);
        let byte_label = ByteLabel::new(byte_labels.try_into().unwrap());

        let seed2 = [43u8; 32];
        let (bit_labels_flat, _) = expand_seed(seed2, 16);
        let default_label = Label::default();
        let mut bit_labels = [BitLabel::new([default_label, default_label]); 8];
        for i in 0..8 {
            bit_labels[i] = BitLabel::new([bit_labels_flat[i * 2], bit_labels_flat[i * 2 + 1]]);
        }

        let translation_material = generate_input_translation_material(0, byte_label, bit_labels);
        let test_value = 42u8;
        let byte_label_component = byte_label.get_label(test_value);

        b.iter(|| {
            let result = translate_input(
                black_box(0),
                black_box(byte_label_component),
                black_box(test_value),
                black_box(translation_material),
            );
            black_box(result)
        });
    });
}

fn bench_wide_hash_2x(c: &mut Criterion) {
    c.bench_function("wide_hash_2x", |b| {
        let label = Label::from([0x42u8; 16]);
        let index = 12345u64;

        b.iter(|| {
            let result = wide_hash_2x(black_box(label), black_box(index));
            black_box(result)
        });
    });
}

fn bench_generate_output_translation_material(c: &mut Criterion) {
    c.bench_function("generate_output_translation_material", |b| {
        // Setup: generate output labels for 10 outputs
        let seed = [55u8; 32];
        let (labels, _) = expand_seed(seed, 20); // 10 outputs * 2 labels each

        let output_labels: Vec<BitLabel> = (0..10)
            .map(|i| BitLabel::new([labels[i * 2], labels[i * 2 + 1]]))
            .collect();

        let secrets: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut s = [0u8; 32];
                s.fill(i as u8);
                s
            })
            .collect();

        b.iter(|| {
            let result = generate_output_translation_material(
                black_box(&output_labels),
                black_box(&secrets),
            );
            black_box(result)
        });
    });
}

fn bench_translate_output(c: &mut Criterion) {
    c.bench_function("translate_output", |b| {
        // Setup: generate output translation material for 10 outputs
        let seed = [55u8; 32];
        let (labels, _) = expand_seed(seed, 20);

        let output_labels: Vec<BitLabel> = (0..10)
            .map(|i| BitLabel::new([labels[i * 2], labels[i * 2 + 1]]))
            .collect();

        let secrets: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut s = [0u8; 32];
                s.fill(i as u8);
                s
            })
            .collect();

        let material = generate_output_translation_material(&output_labels, &secrets);

        // Simulate evaluator having labels (mix of true/false)
        let output_values = vec![
            false, true, false, true, false, true, false, true, false, true,
        ];
        let eval_labels: Vec<Label> = output_labels
            .iter()
            .zip(output_values.iter())
            .map(|(bl, &val)| bl.get_label(val))
            .collect();

        b.iter(|| {
            let result = translate_output(
                black_box(&eval_labels),
                black_box(&output_values),
                black_box(&material),
            );
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_wide_hash_8x,
    bench_generate_input_translation_material,
    bench_translate_input,
    bench_wide_hash_2x,
    bench_generate_output_translation_material,
    bench_translate_output
);

criterion_main!(benches);

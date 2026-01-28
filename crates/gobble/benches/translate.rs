//! Benchmarks for translation operations
#![expect(missing_docs)]
#![allow(unused_crate_dependencies)]

use ckt_gobble::{BitLabel, ByteLabel, Label, generate_translation_material, translate, wide_hash};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[cfg(target_arch = "aarch64")]
use ckt_gobble::aarch64::expand_seed;

#[cfg(target_arch = "x86_64")]
use ckt_gobble::x86_64::expand_seed;

fn bench_wide_hash(c: &mut Criterion) {
    c.bench_function("wide_hash", |b| {
        let label = Label::from([0x42u8; 16]);
        let index = 12345u64;

        b.iter(|| {
            let result = wide_hash(black_box(label), black_box(index));
            black_box(result)
        });
    });
}

fn bench_generate_translation_material(c: &mut Criterion) {
    c.bench_function("generate_translation_material", |b| {
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
            let result = generate_translation_material(
                black_box(0),
                black_box(byte_label),
                black_box(bit_labels),
            );
            black_box(result)
        });
    });
}

fn bench_translate(c: &mut Criterion) {
    c.bench_function("translate", |b| {
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

        let translation_material = generate_translation_material(0, byte_label, bit_labels);
        let test_value = 42u8;
        let byte_label_component = byte_label.get_label(test_value);

        b.iter(|| {
            let result = translate(
                black_box(0),
                black_box(byte_label_component),
                black_box(test_value),
                black_box(translation_material),
            );
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_wide_hash,
    bench_generate_translation_material,
    bench_translate
);

criterion_main!(benches);

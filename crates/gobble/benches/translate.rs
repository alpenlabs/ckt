//! Benchmarks for wide_hash function
#![expect(missing_docs)]
#![allow(unused_crate_dependencies)]

use ckt_gobble::{wide_hash, wide_hash_blake3};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[cfg(target_arch = "aarch64")]
use ckt_gobble::aarch64::expand_seed;

#[cfg(target_arch = "x86_64")]
use ckt_gobble::x86_64::expand_seed;

fn bench_wide_hash(c: &mut Criterion) {
    c.bench_function("wide_hash", |b| unsafe {
        let seed = [77u8; 32];
        let (labels, _) = expand_seed(seed, 1);
        let label = labels[0];

        b.iter(|| {
            let _result = wide_hash(black_box(label), black_box(42));
            black_box(_result);
        });
    });
}

fn bench_wide_hash_blake3(c: &mut Criterion) {
    c.bench_function("wide_hash_blake3", |b| {
        let seed = [77u8; 32];
        let (labels, _) = expand_seed(seed, 1);
        let label = labels[0];

        b.iter(|| {
            let _result = wide_hash_blake3(black_box(label), black_box(42));
            black_box(_result);
        });
    });
}

criterion_group!(benches, bench_wide_hash, bench_wide_hash_blake3);
criterion_main!(benches);

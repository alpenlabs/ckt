//! Benchmark for the MITCCRH hash function.

#![allow(unused_crate_dependencies)]

#[cfg(target_arch = "x86_64")]
mod bench {
    use criterion::{Criterion, black_box, criterion_group};
    use std::arch::x86_64::*;

    use ckt_gobble::x86_64::mitccrh::{block, hash_with_rk};

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn make_block(high: u64, low: u64) -> block {
        _mm_set_epi64x(high as i64, low as i64)
    }

    fn bench_hash_with_rk(c: &mut Criterion) {
        if !(std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("ssse3")) {
            eprintln!("Skipping: AES/SSSE3 not detected");
            return;
        }

        unsafe {
            // Benchmark hash_with_rk: key scheduling + sigma + hash (the full operation)
            c.bench_function("mitccrh/hash_with_rk", |b| {
                let mut key = make_block(0xdead_beef_dead_beefu64, 0x0123_4567_89ab_cdef);
                let mut input = make_block(1, 2);

                b.iter(|| {
                    // Vary inputs to prevent constant folding
                    key = _mm_xor_si128(key, black_box(make_block(3, 4)));
                    input = _mm_xor_si128(input, black_box(make_block(5, 6)));

                    let result = hash_with_rk(black_box(key), black_box(input));

                    black_box(result)
                });
            });
        }
    }

    criterion_group!(benches, bench_hash_with_rk);

    pub(crate) fn main() {
        benches();
        criterion::Criterion::default()
            .configure_from_args()
            .final_summary();
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod bench {
    pub(crate) fn main() {
        eprintln!("mitccrh benchmark is only supported on x86_64");
    }
}

fn main() {
    bench::main();
}

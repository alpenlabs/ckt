//! x86_64-specific intrinsics and AES implementation.
//!
//! This module contains architecture-specific low-level operations.

use std::arch::x86_64::*;
use std::mem::transmute;

mod expand;

use expand::aes128 as expand_aes128;
type Aes128RoundKeys = expand::Aes128RoundKeys;

use crate::{AES128_KEY_BYTES, AES128_ROUND_KEY_BYTES, S_BYTES};

// Re-export the unified types
pub use crate::types::{Ciphertext, Label};

const AES128_KEY: __m128i = unsafe { transmute::<[u8; 16], __m128i>(AES128_KEY_BYTES) };
const AES128_ROUND_KEYS: [__m128i; 11] = [
    AES128_KEY,
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[0]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[1]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[2]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[3]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[4]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[5]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[6]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[7]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[8]) },
    unsafe { transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[9]) },
];

const S: __m128i = unsafe { transmute(S_BYTES) };

/// AES-128 key expansion using AES-NI instructions.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` target feature.
#[allow(dead_code)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn expand_aes128_key(key: &[u8; 16]) -> Aes128RoundKeys {
    unsafe { expand_aes128::expand_key(key) }
}

/// Extract the point-and-permute bit (LSB) from a label.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `sse2` target feature.
/// - The `label` parameter contains initialized data (not uninitialized memory).
#[inline]
pub unsafe fn get_permute_bit(label: __m128i) -> bool {
    let bytes: [u8; 16] = unsafe { transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `sse2` target feature.
/// - The `a` and `b` parameters contain initialized data (not uninitialized memory).
#[inline]
pub unsafe fn xor128(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, b) }
}

/// Convert gate index to tweak value.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `sse2` target feature.
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> __m128i {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { transmute(bytes) }
}

/// AES-128 encryption using x86 AES-NI instructions.
///
/// This follows the x86 AES-NI instruction pattern:
/// - Initial whitening: XOR with round key 0
/// - Rounds 1-9: AESENC (full round with MixColumns)
/// - Round 10: AESENCLAST (final round without MixColumns)
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `sse2` target features.
/// - The `block` parameter contains initialized data (not uninitialized memory).
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn aes_encrypt(block: __m128i) -> __m128i {
    unsafe { aes_encrypt_with_round_keys(block, &AES128_ROUND_KEYS) }
}

/// AES-128 encryption using caller-provided round keys.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `sse2` target features.
/// - The `block` parameter contains initialized data (not uninitialized memory).
/// - The `round_keys` are a valid AES-128 key schedule.
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn aes_encrypt_with_round_keys(block: __m128i, round_keys: &Aes128RoundKeys) -> __m128i {
    // Initial whitening: XOR with first round key
    let mut state = _mm_xor_si128(block, round_keys[0]);

    // Rounds 1-9: Full rounds with MixColumns
    for &key in &round_keys[1..10] {
        state = _mm_aesenc_si128(state, key);
    }

    // Round 10: Final round without MixColumns
    state = _mm_aesenclast_si128(state, round_keys[10]);

    state
}

/// TCCR hash function via fixed-key AES: H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x).
///
/// Tweakable circular correlation robust (TCCR) hash function.
/// Referenced from Section 7.4 of GKWY20 <https://eprint.iacr.org/2019/074>.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `sse2` target features.
/// - The `x` and `tweak` parameters contain initialized data (not uninitialized memory).
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn hash(x: __m128i, tweak: __m128i) -> __m128i {
    unsafe { hash_with_round_keys(x, tweak, &AES128_ROUND_KEYS) }
}

/// TCCR hash function using caller-provided round keys.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `sse2` target features.
/// - The `x` and `tweak` parameters contain initialized data (not uninitialized memory).
/// - The `round_keys` are a valid AES-128 key schedule.
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn hash_with_round_keys(
    x: __m128i,
    tweak: __m128i,
    round_keys: &Aes128RoundKeys,
) -> __m128i {
    let aes_x = unsafe { aes_encrypt_with_round_keys(x, round_keys) };
    unsafe {
        xor128(
            aes_encrypt_with_round_keys(xor128(aes_x, tweak), round_keys),
            aes_x,
        )
    }
}

/// Linear orthomorphism: L || R -> (L ⊕ R) || L, taken from https://eprint.iacr.org/2019/074.pdf Section 7.3
///
/// Optimized implementation using `_mm_shuffle_epi32` as described in the paper:
/// σ(a) = mm_shuffle_epi32(a, 78) ⊕ and_si128(a, mask)
/// where mask selects the appropriate bits for the linear orthomorphism.
///
/// The shuffle with 78 (0x4E) rearranges words as [2, 3, 1, 0], which swaps the halves.
/// Combined with the mask and XOR, this implements L || R -> (L ⊕ R) || L.
///
/// # Safety
/// - The caller must ensure that the CPU supports the `sse2` target feature
/// - `x` must be a valid 128-bit value
#[inline]
#[target_feature(enable = "sse2")]
pub unsafe fn sigma(x: __m128i) -> __m128i {
    // Mask: 0xFFFFFFFFFFFFFFFF0000000000000000
    // This mask selects the first 64 bits (the L half: words 0 and 1)
    // Using -1i32 for 0xFFFFFFFF (all bits set in two's complement)
    let mask = _mm_set_epi32(0x00000000i32, 0x00000000i32, -1i32, -1i32);
    // Shuffle with 78 (0x4E): rearranges words as [x[2], x[3], x[1], x[0]]
    // This effectively swaps the halves: [R|L] = [R0, R1, L1, L0]
    let shuffled = _mm_shuffle_epi32(x, 78);
    // XOR the shuffled result [R|L] with the masked L [L|0] to get [(R⊕L)|L] = [(L⊕R)|L]
    _mm_xor_si128(shuffled, _mm_and_si128(x, mask))
}
/// ccrnd hash function using one AES call and one linear orthomorphism, taken from https://eprint.iacr.org/2019/074.pdf Section 5
///
/// # Safety
/// - The caller must ensure that the CPU supports the `aes` and `neon` target features
/// - `x` and `tweak` must be valid 128-bit values
#[inline]
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn ccrnd(x: __m128i, tweak: __m128i) -> __m128i {
    unsafe { ccrnd_with_round_keys(x, tweak, &AES128_ROUND_KEYS) }
}

/// CCRND hash function using caller-provided round keys.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `sse2` target features.
/// - `x` and `tweak` are valid 128-bit values.
/// - The `round_keys` are a valid AES-128 key schedule.
#[inline]
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn ccrnd_with_round_keys(
    x: __m128i,
    tweak: __m128i,
    round_keys: &Aes128RoundKeys,
) -> __m128i {
    let input = unsafe { xor128(xor128(x, S), tweak) };
    let lin_orth_input = unsafe { sigma(input) };
    unsafe {
        xor128(
            aes_encrypt_with_round_keys(lin_orth_input, round_keys),
            lin_orth_input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use rand::RngCore;

    #[test]
    fn test_aes_encrypt() {
        let num_tests = 1000;
        for i in 0..num_tests {
            let mut plaintext = [0u8; 16];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut plaintext);

            let ciphertext: [u8; 16] =
                unsafe { transmute(aes_encrypt(transmute::<[u8; 16], __m128i>(plaintext))) };

            let cipher = Aes128::new(&AES128_KEY_BYTES.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }

    #[test]
    fn test_aes_encrypt_with_round_keys() {
        let num_tests = 1000;
        for i in 0..num_tests {
            let mut key_bytes = [0u8; 16];
            let mut plaintext = [0u8; 16];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key_bytes);
            rng.fill_bytes(&mut plaintext);

            let round_keys = unsafe { expand_aes128_key(&key_bytes) };
            let ciphertext: [u8; 16] = unsafe {
                transmute(aes_encrypt_with_round_keys(
                    transmute::<[u8; 16], __m128i>(plaintext),
                    &round_keys,
                ))
            };

            let cipher = Aes128::new(&key_bytes.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }

    #[test]
    fn test_ccrnd_output_bytes() {
        // Test vectors: fixed inputs to ensure reproducible outputs
        // Run this test and compare outputs with aarch64 version
        let test_cases = vec![
            ([0u8; 16], [0u8; 16]),
            ([0xFFu8; 16], [0u8; 16]),
            ([0u8; 16], [0xFFu8; 16]),
            ([0x42u8; 16], [0x99u8; 16]),
            (
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
                [
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0xEF, 0xCD, 0xAB, 0x89, 0x67,
                    0x45, 0x23, 0x01,
                ],
            ),
        ];

        println!("\n=== x86_64 ccrnd test outputs (compare with aarch64) ===");
        for (i, (x_bytes, tweak_bytes)) in test_cases.iter().enumerate() {
            let x = unsafe { transmute::<[u8; 16], __m128i>(*x_bytes) };
            let tweak = unsafe { transmute::<[u8; 16], __m128i>(*tweak_bytes) };

            let result = unsafe { ccrnd(x, tweak) };
            let result_bytes: [u8; 16] = unsafe { transmute(result) };

            // Output in hex format for easy comparison
            let x_hex: String = x_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let tweak_hex: String = tweak_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let output_hex: String = result_bytes.iter().map(|b| format!("{:02x}", b)).collect();

            println!(
                "Test {}: x={} tweak={} -> output={}",
                i, x_hex, tweak_hex, output_hex
            );
        }
    }
}

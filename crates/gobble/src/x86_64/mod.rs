//! x86_64-specific intrinsics and AES implementation.
//!
//! This module contains architecture-specific low-level operations.

use std::arch::x86_64::*;
use std::mem::transmute;

use crate::{AES128_KEY_BYTES, AES128_ROUND_KEY_BYTES};

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

/// Extract the point-and-permute bit (LSB) from a label.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `sse2` target feature.
#[inline]
pub unsafe fn get_permute_bit(label: __m128i) -> bool {
    let bytes: [u8; 16] = transmute(label);
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `sse2` target feature.
#[inline]
pub unsafe fn xor128(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
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
    transmute(bytes)
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
/// The caller must ensure that the CPU supports the `aes` and `sse2` target features.
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn aes_encrypt(block: __m128i) -> __m128i {
    // Initial whitening: XOR with first round key
    let mut state = _mm_xor_si128(block, AES128_ROUND_KEYS[0]);

    // Rounds 1-9: Full rounds with MixColumns
    for &key in &AES128_ROUND_KEYS[1..10] {
        state = _mm_aesenc_si128(state, key);
    }

    // Round 10: Final round without MixColumns
    state = _mm_aesenclast_si128(state, AES128_ROUND_KEYS[10]);

    state
}

/// TCCR hash function via fixed-key AES: H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x).
///
/// Tweakable circular correlation robust (TCCR) hash function.
/// Referenced from Section 7.4 of GKWY20 <https://eprint.iacr.org/2019/074>.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `aes` and `sse2` target features.
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn hash(x: __m128i, tweak: __m128i) -> __m128i {
    let aes_x = aes_encrypt(x);
    xor128(aes_encrypt(xor128(aes_x, tweak)), aes_x)
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
}

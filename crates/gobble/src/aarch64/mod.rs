//! Aarch64-specific intrinsics and AES implementation.
//!
//! This module contains only the architecture-specific low-level operations.
//! All higher-level logic (garbling, evaluation, execution) is in the unified modules.

use std::arch::aarch64::*;
use std::mem::transmute;

use crate::{AES128_KEY_BYTES, AES128_ROUND_KEY_BYTES};

// Re-export the unified types
pub use crate::types::{Ciphertext, Label};

const AES128_KEY: uint8x16_t = unsafe { transmute(AES128_KEY_BYTES) };
const AES128_ROUND_KEYS: [uint8x16_t; 11] = [
    AES128_KEY,
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[0]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[1]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[2]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[3]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[4]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[5]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[6]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[7]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[8]) },
    unsafe { transmute::<[u8; 16], uint8x16_t>(AES128_ROUND_KEY_BYTES[9]) },
];

/// Extract the point-and-permute bit (LSB) from a label.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `neon` target feature.
#[inline]
pub unsafe fn get_permute_bit(label: uint8x16_t) -> bool {
    let bytes: [u8; 16] = unsafe { transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `neon` target feature.
#[inline]
pub unsafe fn xor128(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(a, b) }
}

/// Convert gate index to tweak value.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `neon` target feature.
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> uint8x16_t {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { transmute(bytes) }
}

/// AES-128 encryption using ARM NEON crypto extensions.
///
/// This follows the reference implementation pattern:
/// - Rounds 0-8: AESE (SubBytes + ShiftRows + AddRoundKey) + AESMC (MixColumns)
/// - Round 9: AESE only (no MixColumns)
/// - Round 10: Final XOR with last round key
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `aes` and `neon` target features.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn aes_encrypt(block: uint8x16_t) -> uint8x16_t {
    let mut state = block;

    // Rounds 0-8: AES single round encryption + Mix columns
    for key in AES128_ROUND_KEYS.iter().take(9) {
        state = vaeseq_u8(state, *key);
        state = vaesmcq_u8(state);
    }

    // Round 9: AES single round encryption (no MixColumns)
    let key9: uint8x16_t = AES128_ROUND_KEYS[9];
    state = vaeseq_u8(state, key9);

    // Round 10: Final add (bitwise XOR with last round key)
    let key10: uint8x16_t = AES128_ROUND_KEYS[10];
    state = veorq_u8(state, key10);

    state
}

/// TCCR hash function via fixed-key AES: H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x).
///
/// Tweakable circular correlation robust (TCCR) hash function.
/// Referenced from Section 7.4 of GKWY20 <https://eprint.iacr.org/2019/074>.
///
/// # Safety
///
/// The caller must ensure that the CPU supports the `aes` and `neon` target features.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn hash(x: uint8x16_t, tweak: uint8x16_t) -> uint8x16_t {
    let aes_x = unsafe { aes_encrypt(x) };
    unsafe { xor128(aes_encrypt(xor128(aes_x, tweak)), aes_x) }
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
                unsafe { transmute(aes_encrypt(transmute::<[u8; 16], uint8x16_t>(plaintext))) };

            let cipher = Aes128::new(&AES128_KEY_BYTES.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }
}

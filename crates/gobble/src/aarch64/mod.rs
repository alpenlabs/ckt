//! Aarch64-specific intrinsics and AES implementation.
//!
//! This module contains architecture-specific low-level operations.

use std::arch::aarch64::*;
use std::mem::transmute;

mod expand;

use expand::expand_key;

/// AES-128 round keys type.
pub type Aes128RoundKeys = expand::Aes128RoundKeys;

// Re-export the unified types
pub use crate::types::{Ciphertext, Label};

/// AES-128 key expansion using ARM AES instructions.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` target feature.
#[target_feature(enable = "aes")]
pub unsafe fn expand_aes128_key(key: &[u8; 16]) -> Aes128RoundKeys {
    unsafe { expand_key::<16, 11>(key) }
}

/// Extract the point-and-permute bit (LSB) from a label.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `neon` target feature.
/// - The `label` parameter contains initialized data (not uninitialized memory).
#[inline]
pub unsafe fn get_permute_bit(label: uint8x16_t) -> bool {
    let bytes: [u8; 16] = unsafe { transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `neon` target feature.
/// - The `a` and `b` parameters contain initialized data (not uninitialized memory).
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

/// AES-128 encryption using caller-provided round keys.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `neon` target features.
/// - The `block` parameter contains initialized data (not uninitialized memory).
/// - The `round_keys` are a valid AES-128 key schedule.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn aes_encrypt_with_round_keys(
    block: uint8x16_t,
    round_keys: &Aes128RoundKeys,
) -> uint8x16_t {
    let mut state = block;

    // Rounds 0-8: AES single round encryption + Mix columns
    for key in round_keys.iter().take(9) {
        state = vaeseq_u8(state, *key);
        state = vaesmcq_u8(state);
    }

    // Round 9: AES single round encryption (no MixColumns)
    let key9: uint8x16_t = round_keys[9];
    state = vaeseq_u8(state, key9);

    // Round 10: Final add (bitwise XOR with last round key)
    let key10: uint8x16_t = round_keys[10];
    state = veorq_u8(state, key10);

    state
}

/// Linear orthomorphism: L || R -> (L ⊕ R) || L, taken from <https://eprint.iacr.org/2019/074.pdf> Section 7.3
///
/// # Safety
/// - The caller must ensure that the CPU supports the `neon` target feature
/// - `x` must be a valid 128-bit value
#[inline]
#[target_feature(enable = "neon")]
pub unsafe fn sigma(x: uint8x16_t) -> uint8x16_t {
    let swapped = vextq_u8(x, x, 8); // swap halves: [R|L]
    let swapped_xor = veorq_u8(x, swapped); // (L xor R) || (L xor R)
    vextq_u8(swapped_xor, x, 8) // (L xor R)||L
}

/// CCRND hash function using caller-provided round keys and public S.
///
/// This is the CCRND hash function from Section 5 of <https://eprint.iacr.org/2019/074.pdf>,
/// using one AES call and one linear orthomorphism.
///
/// # Safety
///
/// The caller must ensure that:
/// - The CPU supports the `aes` and `neon` target features.
/// - `x`, `tweak`, and `public_s` are valid 128-bit values.
/// - The `round_keys` are a valid AES-128 key schedule.
#[inline]
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn ccrnd_with_round_keys(
    x: uint8x16_t,
    tweak: uint8x16_t,
    round_keys: &Aes128RoundKeys,
    public_s: uint8x16_t,
) -> uint8x16_t {
    let input = unsafe { xor128(xor128(x, public_s), tweak) };
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
                    transmute::<[u8; 16], uint8x16_t>(plaintext),
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
        // These must match the test vectors in x86_64/mod.rs
        let test_cases = [
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

        // Use fixed key and public_s for testing
        let key_bytes = [0x2Bu8; 16];
        let public_s_bytes = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
            0xBA, 0xBE,
        ];
        let public_s = unsafe { transmute::<[u8; 16], uint8x16_t>(public_s_bytes) };
        let round_keys = unsafe { expand_aes128_key(&key_bytes) };

        println!("\n=== aarch64 ccrnd test outputs (compare with x86_64) ===");
        for (i, (x_bytes, tweak_bytes)) in test_cases.iter().enumerate() {
            let x = unsafe { transmute::<[u8; 16], uint8x16_t>(*x_bytes) };
            let tweak = unsafe { transmute::<[u8; 16], uint8x16_t>(*tweak_bytes) };

            let result = unsafe { ccrnd_with_round_keys(x, tweak, &round_keys, public_s) };
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

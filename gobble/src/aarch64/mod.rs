//! Aarch64-specific implementation of the GobbleEngine trait.

pub mod eval;
pub mod exec;
pub mod garb;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use std::arch::aarch64::uint8x16_t;
use std::arch::aarch64::*;
use std::mem::transmute;

use crate::aarch64::eval::Aarch64EvaluationInstance;
use crate::aarch64::exec::Aarch64ExecutionInstance;
use crate::aarch64::garb::Aarch64GarblingInstance;
use crate::traits::EvaluationInstanceConfig;
use crate::traits::ExecutionInstanceConfig;
use crate::traits::GarblingInstanceConfig;
use crate::traits::GobbleEngine;

use crate::{S_BYTES, AES128_KEY_BYTES, AES128_ROUND_KEY_BYTES};

const LABEL_ZERO_BYTES: [u8; 16] = [98u8; 16];
const LABEL_ZERO: Label = Label(unsafe { transmute::<[u8; 16], uint8x16_t>(LABEL_ZERO_BYTES) });

const LABEL_ONE_BYTES: [u8; 16] = [25u8; 16];
const LABEL_ONE: Label = Label(unsafe { transmute::<[u8; 16], uint8x16_t>(LABEL_ONE_BYTES) });

/// Aarch64-specific label type.
#[derive(Debug, Clone, Copy)]
pub struct Label(pub uint8x16_t);

impl Label {
    /// Returns public constant label for zero
    pub const fn zero() -> Self {
        LABEL_ZERO
    }
    /// Returns public constant label for one
    pub const fn one() -> Self {
        LABEL_ONE
    }
}

/// Aarch64-specific ciphertext type.
#[derive(Debug, Clone, Copy)]
pub struct Ciphertext(pub uint8x16_t);

impl From<[u8; 16]> for Ciphertext {
    fn from(bytes: [u8; 16]) -> Self {
        Ciphertext(unsafe { transmute::<[u8; 16], uint8x16_t>(bytes) })
    }
}

impl From<Ciphertext> for [u8; 16] {
    fn from(val: Ciphertext) -> Self {
        unsafe { transmute::<uint8x16_t, [u8; 16]>(val.0) }
    }
}

/// Aarch64-specific implementation of the GobbleEngine trait.
#[derive(Debug)]
pub struct Aarch64GobbleEngine;

impl GobbleEngine for Aarch64GobbleEngine {
    fn new() -> Self {
        Self
    }

    type GarblingInstance = Aarch64GarblingInstance;

    type EvaluationInstance = Aarch64EvaluationInstance;

    type ExecutionInstance = Aarch64ExecutionInstance;

    fn new_garbling_instance<'labels>(
        &self,
        config: GarblingInstanceConfig<'labels>,
    ) -> Self::GarblingInstance {
        Aarch64GarblingInstance::new(config)
    }

    fn new_execution_instance<'labels>(
        &self,
        config: ExecutionInstanceConfig<'labels>,
    ) -> Self::ExecutionInstance {
        Aarch64ExecutionInstance::new(config)
    }

    fn new_evaluation_instance<'labels>(
        &self,
        config: EvaluationInstanceConfig<'labels>,
    ) -> Self::EvaluationInstance {
        Aarch64EvaluationInstance::new(config)
    }
}

const S: uint8x16_t = unsafe { transmute(S_BYTES) };
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

/// Extract the point-and-permute bit (LSB) from a label
///
/// # Safety
/// - The caller must ensure that the CPU supports the `neon` target feature
///   before calling this function.
/// - `label` must be a valid, initialized 128-bit value representing a label.
/// - This function uses `transmute` to convert the NEON vector to bytes,
///   which may lead to undefined behavior if `label` is invalid or uninitialized.
/// - Do not call this function on unsupported architectures or with uninitialized data.
#[inline]
pub unsafe fn get_permute_bit(label: uint8x16_t) -> bool {
    let bytes: [u8; 16] = unsafe { transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values
///
/// # Safety
/// - The caller must ensure that the CPU supports the `neon` target feature
///   before calling this function.
/// - Using this function on hardware without NEON support may
///   lead to undefined behavior.
#[inline]
pub unsafe fn xor128(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(a, b) }
}

/// Convert gate index to tweak value
///
/// # Safety
/// - The caller must ensure that the CPU supports the `neon` target feature
///   before calling this function.
/// - Using the returned `uint8x16_t` on hardware without NEON support may
///   lead to undefined behavior.
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> uint8x16_t {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { transmute(bytes) }
}

/// AES-128 encryption using ARM NEON crypto extensions
///
/// This follows the reference implementation pattern:
/// - Rounds 0-8: AESE (SubBytes + ShiftRows + AddRoundKey) + AESMC (MixColumns)
/// - Round 9: AESE only (no MixColumns)
/// - Round 10: Final XOR with last round key
///
/// # Safety
/// - The caller must ensure that the CPU supports the `aes` and `neon` target features
///   before invoking this function.
/// - `block` must be a valid, initialized 128-bit value.
/// - This function uses unsafe ARM NEON AES intrinsics (`vaeseq_u8`, `vaesmcq_u8`, `veorq_u8`)
///   which may lead to undefined behavior on unsupported hardware or with uninitialized data.
/// - Do not call this function on unsupported architectures or with invalid data.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn aes_encrypt(block: uint8x16_t) -> uint8x16_t {
    let mut state = block;

    // Rounds 0-8: AES single round encryption + Mix columns
    for key in AES128_ROUND_KEYS.iter().take(9) {
        // AESE: SubBytes + ShiftRows + AddRoundKey
        state = vaeseq_u8(state, *key);
        // AESMC: MixColumns
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

/// Expand a seed into a vector of labels and a delta label
pub fn expand_seed(seed: [u8; 32], num_inputs: u32) -> (Vec<Label>, Label) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);
    let delta = Label(unsafe { transmute::<[u8; 16], uint8x16_t>(delta) });
    let mut labels = Vec::with_capacity(num_inputs as usize);
    for _ in 0..num_inputs {
        let mut input = [0u8; 16];
        rng.fill_bytes(&mut input);
        labels.push(Label(unsafe { transmute::<[u8; 16], uint8x16_t>(input) }));
    }
    (labels, delta)
}

/// Select input labels based on the input bits
pub fn encode(input: Vec<bool>, false_input_labels: Vec<Label>, delta: Label) -> Vec<Label> {
    let mut selected_input_labels: Vec<Label> = Vec::with_capacity(input.len());
    for (i, bit) in input.iter().enumerate() {
        if *bit {
            selected_input_labels.push(unsafe { Label(xor128(false_input_labels[i].0, delta.0)) });
        } else {
            selected_input_labels.push(false_input_labels[i]);
        }
    }
    selected_input_labels
}

/// H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x)
///
/// # Safety
/// - The caller must ensure that the CPU supports the `aes` and `neon` target features
///   before invoking this function.
/// - `x` and `tweak` must be valid 128-bit values; no further validation is performed.
/// - This function uses unsafe ARM NEON AES intrinsics (`vaeseq_u8`, `vaesmcq_u8`, `veorq_u8`)
///   and untyped transmute operations internally. Improper use may lead to undefined behavior.
/// - Do not call this function on unsupported hardware or with uninitialized data.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn hash(x: uint8x16_t, tweak: uint8x16_t) -> uint8x16_t {
    let aes_x = unsafe { aes_encrypt(x) };
    unsafe { xor128(aes_encrypt(xor128(aes_x, tweak)), aes_x) }
}

/// Linear orthomorphism: L || R -> (L ⊕ R) || L, taken from https://eprint.iacr.org/2019/074.pdf Section 7.3
///
/// # Safety
/// - The caller must ensure that the CPU supports the `neon` target feature
/// - `x` must be a valid 128-bit value
#[inline]
#[target_feature(enable = "neon")]
pub unsafe fn sigma(x: uint8x16_t) -> uint8x16_t {
    let swapped =  vextq_u8(x, x, 8);   // swap halves: [R|L]
    let swapped_xor = veorq_u8(x, swapped); // (L xor R) || (L xor R)
    vextq_u8(swapped_xor, x, 8) // (L xor R)||L
}
/// ccrnd hash function using one AES call and one linear orthomorphism, taken from https://eprint.iacr.org/2019/074.pdf Section 5
///
/// # Safety
/// - The caller must ensure that the CPU supports the `aes` and `neon` target features
/// - `x` and `tweak` must be valid 128-bit values
#[inline]
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn ccrnd(x: uint8x16_t, tweak: uint8x16_t) -> uint8x16_t {
    let input = unsafe { xor128(xor128(x, S), tweak) };
    let lin_orth_input = unsafe { sigma(input) };
    unsafe { xor128(aes_encrypt(lin_orth_input), lin_orth_input) }
}

mod tests {
    // Test custom AES encryption against the reference implementation from the aes crate
    #[test]
    fn test_aes_encrypt() {
        use super::*;
        use aes::Aes128;
        use aes::cipher::{BlockEncrypt, KeyInit};
        use rand::RngCore;

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

//! x86_64-specific implementation of the GobbleEngine trait.

pub mod eval;
pub mod exec;
pub mod garb;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use std::arch::x86_64::*;
use std::mem::transmute;

use crate::traits::EvaluationInstanceConfig;
use crate::traits::ExecutionInstanceConfig;
use crate::traits::GarblingInstanceConfig;
use crate::traits::GobbleEngine;
use crate::x86_64::eval::X86_64EvaluationInstance;
use crate::x86_64::exec::X86_64ExecutionInstance;
use crate::x86_64::garb::X86_64GarblingInstance;

use crate::{AES128_KEY_BYTES, AES128_ROUND_KEY_BYTES};

/// x86_64-specific label type.
#[derive(Debug, Clone, Copy)]
pub struct Label(pub __m128i);

/// x86_64-specific ciphertext type.
#[derive(Debug, Clone, Copy)]
pub struct Ciphertext(pub __m128i);

impl From<[u8; 16]> for Ciphertext {
    fn from(bytes: [u8; 16]) -> Self {
        Self(unsafe { transmute::<[u8; 16], __m128i>(bytes) })
    }
}

impl From<Ciphertext> for [u8; 16] {
    fn from(ciphertext: Ciphertext) -> Self {
        unsafe { transmute::<__m128i, [u8; 16]>(ciphertext.0) }
    }
}

/// x86_64-specific implementation of the GobbleEngine trait.
#[derive(Debug)]
pub struct X86_64GobbleEngine;

impl GobbleEngine for X86_64GobbleEngine {
    fn new() -> Self {
        Self
    }

    type GarblingInstance = X86_64GarblingInstance;

    type EvaluationInstance = X86_64EvaluationInstance;

    type ExecutionInstance = X86_64ExecutionInstance;

    fn new_garbling_instance<'labels>(
        &self,
        config: GarblingInstanceConfig<'labels>,
    ) -> Self::GarblingInstance {
        X86_64GarblingInstance::new(config)
    }

    fn new_execution_instance<'labels>(
        &self,
        config: ExecutionInstanceConfig<'labels>,
    ) -> Self::ExecutionInstance {
        X86_64ExecutionInstance::new(config)
    }

    fn new_evaluation_instance<'labels>(
        &self,
        config: EvaluationInstanceConfig<'labels>,
    ) -> Self::EvaluationInstance {
        X86_64EvaluationInstance::new(config)
    }
}

const AES128_KEY: __m128i = unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_KEY_BYTES) };
const AES128_ROUND_KEYS: [__m128i; 11] = [
    AES128_KEY,
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[0]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[1]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[2]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[3]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[4]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[5]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[6]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[7]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[8]) },
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(AES128_ROUND_KEY_BYTES[9]) },
];

/// Extract the point-and-permute bit (LSB) from a label
///
/// # Safety
/// This function is safe to call without additional preconditions as it uses standard intrinsics and transmutes that are always valid for __m128i types.
#[inline]
pub unsafe fn get_permute_bit(label: __m128i) -> bool {
    let bytes: [u8; 16] = unsafe { std::mem::transmute::<__m128i, [u8; 16]>(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values
///
/// # Safety
/// This function is safe to call without additional preconditions as it uses standard intrinsics and transmutes that are always valid for __m128i types.
#[inline]
pub unsafe fn xor128(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, b) }
}

/// Convert gate index to tweak value
///
/// # Safety
/// This function is safe to call without additional preconditions as it uses standard intrinsics and transmutes that are always valid for __m128i types.
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> __m128i {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { std::mem::transmute::<[u8; 16], __m128i>(bytes) }
}

/// AES-128 encryption using x86 AES-NI instructions
///
/// This follows the x86 AES-NI instruction pattern:
/// - Initial whitening: XOR with round key 0
/// - Rounds 1-9: AESENC (full round with MixColumns)
/// - Round 10: AESENCLAST (final round without MixColumns)
///
/// # Safety
/// This function is safe to call without additional preconditions as it uses standard intrinsics and transmutes that are always valid for __m128i types.
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

/// Expand a seed into a vector of labels and a delta label
pub fn expand_seed(seed: [u8; 32], num_inputs: u32) -> (Vec<Label>, Label) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);
    let delta = Label(unsafe { std::mem::transmute::<[u8; 16], __m128i>(delta) });
    let mut labels = Vec::with_capacity(num_inputs as usize);
    for _ in 0..num_inputs {
        let mut input = [0u8; 16];
        rng.fill_bytes(&mut input);
        labels.push(Label(unsafe {
            std::mem::transmute::<[u8; 16], __m128i>(input)
        }));
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

/// Tweakable circular correlation robust (TCCR) hash function instantiated via fixed-key AES as H(x, tweak) = AES(AES(x) ⊕ tweak) ⊕ AES(x) 
/// Referenced from Section 7.4 of [GKWY20] <https://eprint.iacr.org/2019/074>.
///
/// # Safety
/// - The caller must ensure that the CPU supports the `aes` and `sse2` target features
///   before invoking this function.
/// - `x` and `tweak` must be valid 128-bit values; no further validation is performed.
/// - This function uses unsafe x86 AES-NI intrinsics (`_mm_aesenc_si128`, `_mm_aesenclast_si128`, `_mm_xor_si128`)
///   and untyped transmute operations internally. Improper use may lead to undefined behavior.
/// - Do not call this function on unsupported hardware or with uninitialized data.
#[target_feature(enable = "aes")]
#[target_feature(enable = "sse2")]
pub unsafe fn hash(x: __m128i, tweak: __m128i) -> __m128i {
    let aes_x = unsafe { aes_encrypt(x) };
    unsafe { xor128(aes_encrypt(xor128(aes_x, tweak)), aes_x) }
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

            let ciphertext: [u8; 16] = unsafe {
                std::mem::transmute(aes_encrypt(std::mem::transmute::<[u8; 16], __m128i>(
                    plaintext,
                )))
            };

            let cipher = Aes128::new(&AES128_KEY_BYTES.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }
}

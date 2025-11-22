//! Aarch64-specific implementation of the GobbleEngine trait.

pub mod eval;
pub mod exec;
pub mod garb;
pub mod label;

use hex_literal::hex;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use std::arch::aarch64::*;

use crate::aarch64::eval::Aarch64EvaluationInstance;
use crate::aarch64::exec::Aarch64ExecutionInstance;
use crate::aarch64::garb::Aarch64GarblingInstance;
use crate::traits::EvaluationInstanceConfig;
use crate::traits::ExecutionInstanceConfig;
use crate::traits::GarblingInstanceConfig;
use crate::traits::GobbleEngine;

const LABEL_ZERO_BYTES: [u8; 16] = [98u8; 16];
const LABEL_ZERO: Label = Label(unsafe { std::mem::transmute(LABEL_ZERO_BYTES) });

const LABEL_ONE_BYTES: [u8; 16] = [25u8; 16];
const LABEL_ONE: Label = Label(unsafe { std::mem::transmute(LABEL_ONE_BYTES) });

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

// Taken from https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/armv8/test_expand.rs
// Corresponding to FIPS 197 Appendix A.1
const AES128_KEY_BYTES: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const AES128_KEY: uint8x16_t = unsafe { std::mem::transmute(AES128_KEY_BYTES) };
const AES128_ROUND_KEYS: [uint8x16_t; 11] = [
    AES128_KEY,
    unsafe { std::mem::transmute(hex!("a0fafe1788542cb123a339392a6c7605")) },
    unsafe { std::mem::transmute(hex!("f2c295f27a96b9435935807a7359f67f")) },
    unsafe { std::mem::transmute(hex!("3d80477d4716fe3e1e237e446d7a883b")) },
    unsafe { std::mem::transmute(hex!("ef44a541a8525b7fb671253bdb0bad00")) },
    unsafe { std::mem::transmute(hex!("d4d1c6f87c839d87caf2b8bc11f915bc")) },
    unsafe { std::mem::transmute(hex!("6d88a37a110b3efddbf98641ca0093fd")) },
    unsafe { std::mem::transmute(hex!("4e54f70e5f5fc9f384a64fb24ea6dc4f")) },
    unsafe { std::mem::transmute(hex!("ead27321b58dbad2312bf5607f8d292f")) },
    unsafe { std::mem::transmute(hex!("ac7766f319fadc2128d12941575c006e")) },
    unsafe { std::mem::transmute(hex!("d014f9a8c9ee2589e13f0cc8b6630ca6")) },
];

/// Extract the point-and-permute bit (LSB) from a label
#[inline]
pub unsafe fn get_permute_bit(label: uint8x16_t) -> bool {
    let bytes: [u8; 16] = unsafe { std::mem::transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values
#[inline]
pub unsafe fn xor128(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(a, b) }
}

/// Convert gate index to tweak value
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> uint8x16_t {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { std::mem::transmute(bytes) }
}

/// AES-128 encryption using ARM NEON crypto extensions
///
/// This follows the reference implementation pattern:
/// - Rounds 0-8: AESE (SubBytes + ShiftRows + AddRoundKey) + AESMC (MixColumns)
/// - Round 9: AESE only (no MixColumns)
/// - Round 10: Final XOR with last round key
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn aes_encrypt(block: uint8x16_t) -> uint8x16_t {
    let mut state = block;

    // Rounds 0-8: AES single round encryption + Mix columns
    for i in 0..9 {
        let key: uint8x16_t = AES128_ROUND_KEYS[i];
        // AESE: SubBytes + ShiftRows + AddRoundKey
        state = vaeseq_u8(state, key);
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
    let delta = Label(unsafe { std::mem::transmute(delta) });
    let mut labels = Vec::with_capacity(num_inputs as usize);
    for _ in 0..num_inputs {
        let mut input = [0u8; 16];
        rng.fill_bytes(&mut input);
        labels.push(Label(unsafe { std::mem::transmute(input) }));
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
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub unsafe fn hash(x: uint8x16_t, tweak: uint8x16_t) -> uint8x16_t {
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

            let ciphertext: [u8; 16] =
                unsafe { std::mem::transmute(aes_encrypt(std::mem::transmute(plaintext))) };

            let cipher = Aes128::new(&AES128_KEY_BYTES.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }
}

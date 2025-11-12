use std::{arch::aarch64::*, ptr};
use hex_literal::hex;

#[derive(Debug, Clone, Copy)]
pub struct Label(pub uint8x16_t);

#[derive(Debug, Clone, Copy)]
pub struct Ciphertext(pub uint8x16_t);

pub struct WorkingSpace(pub Vec<Label>);

impl std::ops::DerefMut for WorkingSpace {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for WorkingSpace {
    type Target = Vec<Label>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct GarblingInstance {
    pub gate_ctr: u64,
    pub working_space: WorkingSpace,
    pub delta: uint8x16_t,
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

impl GarblingInstance {
    pub fn new(scratch_space: u32, delta: uint8x16_t) -> Self {
        let bytes = [0u8; 16];
        let empty_label = unsafe { std::mem::transmute(bytes) };

        GarblingInstance {
            gate_ctr: 0,
            working_space: WorkingSpace(vec![Label(empty_label); scratch_space as usize]),
            delta,
        }
    }

    #[inline]
    pub fn garble_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];
        self.working_space[out_addr] = Label(unsafe { xor128(in1.0, in2.0) });
        self.gate_ctr += 1;
    }

    /// Garbles an AND gate.
    #[inline]
    pub fn garble_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
    ) -> Ciphertext {
        // Retrieve input labels for in1_0 and in2_0
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];

        let t = unsafe { index_to_tweak(self.gate_ctr) };
        let xor_in1_delta = unsafe { xor128(in1.0, self.delta) };

        let h_in1_t = unsafe {
            hash(in1.0, t)
        };

        let h_in1_delta_t = unsafe {
            hash(xor_in1_delta, t)
        };

        let ciphertext = unsafe { xor128(xor128(h_in1_t, h_in1_delta_t), in2.0) };

        // Write output label to working space
        self.working_space[out_addr] = Label(h_in1_t);

        // Increment gate counter to enforce uniqueness
        self.gate_ctr += 1;

        Ciphertext(ciphertext)
    }
}

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

            let ciphertext: [u8; 16] = unsafe { std::mem::transmute(aes_encrypt(std::mem::transmute(plaintext) ))};

            let cipher = Aes128::new(&AES128_KEY_BYTES.into());
            let mut expected_ciphertext = plaintext.into();
            cipher.encrypt_block(&mut expected_ciphertext);

            assert_eq!(ciphertext, &expected_ciphertext[..], "failed at test {}", i);
        }
    }
}
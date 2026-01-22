#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_arch = "aarch64")]
use gobble::aarch64::{aes_encrypt_with_round_keys, expand_aes128_key};
#[cfg(target_arch = "x86_64")]
use gobble::x86_64::{aes_encrypt_with_round_keys, expand_aes128_key};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

/// Fixed test key for fuzzing (any arbitrary key works)
const TEST_KEY: [u8; 16] = [0x2Bu8; 16];

// Test AES block encryption against reference
fuzz_target!(|data: [u8; 16]| {
    let round_keys = unsafe { expand_aes128_key(&TEST_KEY) };
    let ciphertext: [u8; 16] = unsafe {
        std::mem::transmute(aes_encrypt_with_round_keys(
            std::mem::transmute(data),
            &round_keys,
        ))
    };

    let reference_cipher = Aes128::new(&TEST_KEY.into());
    let mut reference_ciphertext = data.into();
    reference_cipher.encrypt_block(&mut reference_ciphertext);

    assert_eq!(ciphertext, &reference_ciphertext[..]);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_arch = "aarch64")]
use gobble::aarch64::aes_encrypt;
#[cfg(target_arch = "x86_64")]
use gobble::x86_64::aes_encrypt;

use gobble::AES128_KEY_BYTES;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

// Test AES block encryption against reference
fuzz_target!(|data: [u8; 16]| {
    let ciphertext: [u8; 16] = unsafe { std::mem::transmute(aes_encrypt(std::mem::transmute(data))) };
    
    let reference_cipher = Aes128::new(&AES128_KEY_BYTES.into());
    let mut reference_ciphertext = data.into();
    reference_cipher.encrypt_block(&mut reference_ciphertext);
    
    assert_eq!(ciphertext, &reference_ciphertext[..]);
});

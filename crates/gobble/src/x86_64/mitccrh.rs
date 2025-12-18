//! MITCCRH: Multi-Instance Tweakable Circular Correlation Robust Hash
//!
//! Simplified API for AES-based hashing with fresh key scheduling.
//! Refactored port of EMP Toolkit: https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/utils/mitccrh.h

#![allow(non_camel_case_types)]

#[cfg(target_arch = "x86_64")]
pub use mitccrh_x86::{block, hash_with_rk};

#[cfg(target_arch = "x86_64")]
mod mitccrh_x86 {
    use core::arch::x86_64::*;

    use crate::x86_64::key_schedule::aes_opt_x86::{aes_opt_key_schedule, para_enc, AESKey};

    /// A 128-bit block (AES block size).
    pub type block = __m128i;

    /// Sigma permutation: swap 64-bit halves and mask.
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn sigma(a: block) -> block {
        let shuffled = _mm_shuffle_epi32(a, 78);
        let mask = _mm_set_epi64x(-1, 0); // high = 0xFFFF..., low = 0
        _mm_xor_si128(shuffled, _mm_and_si128(a, mask))
    }

    /// Hash a single block with fresh key scheduling.
    ///
    /// Computes: `sigma(input) ^ AES_key(sigma(input))`
    ///
    /// This performs:
    /// 1. Key scheduling for the provided key
    /// 2. Applies sigma permutation to the input
    /// 3. AES encrypts the permuted input
    /// 4. XORs the encrypted result with the permuted input
    ///
    /// # Safety
    /// Requires x86_64 with AES-NI and SSE2 support.
    #[inline]
    #[target_feature(enable = "aes,ssse3,sse2")]
    pub unsafe fn hash_with_rk(key: block, input: block) -> block {
        unsafe {
            // Schedule the key
            let user_keys: [block; 1] = [key];
            let mut scheduled: [AESKey; 1] = [AESKey::default()];
            aes_opt_key_schedule::<1>(&user_keys, &mut scheduled);

            // Apply sigma
            let sigma_input = sigma(input);

            // Encrypt: tmp = AES(sigma_input)
            let mut tmp = [sigma_input];
            para_enc::<1, 1>(&mut tmp, &scheduled);

            // Return sigma_input ^ AES(sigma_input)
            _mm_xor_si128(sigma_input, tmp[0])
        }
    }
}

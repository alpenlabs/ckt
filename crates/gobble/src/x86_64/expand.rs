//! AES key expansion support.
//! Taken verbatim from https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/x86/ni/test_expand.rs
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;
use core::mem::zeroed;

pub(super) type Aes128RoundKeys = [__m128i; 11];

pub(crate) mod aes128 {
    use super::*;

    #[target_feature(enable = "aes")]
    pub(crate) unsafe fn expand_key(key: &[u8; 16]) -> Aes128RoundKeys {
        unsafe fn expand_round<const RK: i32>(keys: &mut Aes128RoundKeys, pos: usize) {
            let mut t1 = keys[pos - 1];
            let mut t2;
            let mut t3;

            t2 = _mm_aeskeygenassist_si128(t1, RK);
            t2 = _mm_shuffle_epi32(t2, 0xff);
            t3 = _mm_slli_si128(t1, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t3 = _mm_slli_si128(t3, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t3 = _mm_slli_si128(t3, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t1 = _mm_xor_si128(t1, t2);

            keys[pos] = t1;
        }

        let mut keys: Aes128RoundKeys = zeroed();
        let k = _mm_loadu_si128(key.as_ptr().cast());
        keys[0] = k;

        let kr = &mut keys;
        expand_round::<0x01>(kr, 1);
        expand_round::<0x02>(kr, 2);
        expand_round::<0x04>(kr, 3);
        expand_round::<0x08>(kr, 4);
        expand_round::<0x10>(kr, 5);
        expand_round::<0x20>(kr, 6);
        expand_round::<0x40>(kr, 7);
        expand_round::<0x80>(kr, 8);
        expand_round::<0x1B>(kr, 9);
        expand_round::<0x36>(kr, 10);

        keys
    }
}

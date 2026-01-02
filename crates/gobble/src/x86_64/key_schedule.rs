//! AES key scheduling for NUM_KEYS AES-128 keys.
//!
//! Port of EMP Toolkit: <https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/utils/aes_opt.h>

#![allow(non_camel_case_types)]

#[cfg(target_arch = "x86_64")]
pub(crate) mod aes_opt_x86 {
    use core::arch::x86_64::*;

    pub(crate) type block = __m128i;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub(crate) struct AESKey {
        pub(crate) rounds: u32,
        pub(crate) rd_key: [block; 11], // AES-128: 0..10
    }

    impl Default for AESKey {
        fn default() -> Self {
            unsafe {
                Self {
                    rounds: 10,
                    rd_key: [_mm_setzero_si128(); 11],
                }
            }
        }
    }

    #[inline]
    #[target_feature(enable = "aes,ssse3,sse2")]
    unsafe fn ks_rounds<const NUM_KEYS: usize>(
        keys: &mut [AESKey; NUM_KEYS],
        con: block,
        con3: block,
        mask: block,
        r: usize,
    ) {
        debug_assert!((1..=10).contains(&r));

        for aes_key in keys.iter_mut() {
            let mut key = aes_key.rd_key[r - 1];

            // x2 = shuffle(key, mask)
            let x2 = _mm_shuffle_epi8(key, mask);

            // aux = aesenclast(x2, con)
            let aux = _mm_aesenclast_si128(x2, con);

            // globAux = key << 32 (per 64-bit lane), then key ^= globAux
            let mut glob_aux = _mm_slli_epi64(key, 32);
            key = _mm_xor_si128(glob_aux, key);

            // globAux = shuffle(key, con3), then key ^= globAux
            glob_aux = _mm_shuffle_epi8(key, con3);
            key = _mm_xor_si128(glob_aux, key);

            // rd_key[r] = aux ^ key
            aes_key.rd_key[r] = _mm_xor_si128(aux, key);
        }
    }

    /// AES key scheduling for NUM_KEYS AES-128 keys.
    #[inline]
    #[target_feature(enable = "aes,ssse3,sse2")]
    pub(crate) unsafe fn aes_opt_key_schedule<const NUM_KEYS: usize>(
        user_key: &[block; NUM_KEYS],
        keys: &mut [AESKey; NUM_KEYS],
    ) {
        unsafe {
            let mut con = _mm_set_epi32(1, 1, 1, 1);
            let mut con2 = _mm_set_epi32(0x1b, 0x1b, 0x1b, 0x1b);
            let con3 = _mm_set_epi32(
                0x07060504,
                0x07060504,
                0x0ffffffffu32 as i32,
                0x0ffffffffu32 as i32,
            );
            let mask = _mm_set_epi32(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d);

            for (aes_key, &ukey) in keys.iter_mut().zip(user_key.iter()) {
                aes_key.rounds = 10;
                aes_key.rd_key[0] = ukey;
            }

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 1);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 2);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 3);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 4);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 5);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 6);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 7);
            con = _mm_slli_epi32(con, 1);

            ks_rounds::<NUM_KEYS>(keys, con, con3, mask, 8);

            // round 9 uses con2
            ks_rounds::<NUM_KEYS>(keys, con2, con3, mask, 9);
            con2 = _mm_slli_epi32(con2, 1);

            ks_rounds::<NUM_KEYS>(keys, con2, con3, mask, 10);
        }
    }

    /// With num_keys keys, use each key to encrypt num_encs blocks (in-place),
    /// in the same layout as the C version:
    /// blocks are grouped by key, i.e. [K0..K0], [K1..K1], ...
    ///
    /// `blks.len()` must equal `NUM_KEYS * NUM_ENCS`.
    #[inline]
    #[target_feature(enable = "aes,ssse3,sse2")]
    pub(crate) unsafe fn para_enc<const NUM_KEYS: usize, const NUM_ENCS: usize>(
        blks: &mut [block],
        keys: &[AESKey; NUM_KEYS],
    ) {
        debug_assert_eq!(blks.len(), NUM_KEYS * NUM_ENCS);

        // Initial AddRoundKey for each key's block batch
        {
            let mut idx = 0usize;
            for key in keys {
                let k0 = key.rd_key[0];
                for _j in 0..NUM_ENCS {
                    blks[idx] = _mm_xor_si128(blks[idx], k0);
                    idx += 1;
                }
            }
        }

        // Rounds 1..9: aesenc
        for r in 1..10 {
            let mut idx = 0usize;
            for key in keys {
                let kr = key.rd_key[r];
                for _j in 0..NUM_ENCS {
                    blks[idx] = _mm_aesenc_si128(blks[idx], kr);
                    idx += 1;
                }
            }
        }

        // Final round: aesenclast with round key 10
        {
            let mut idx = 0usize;
            for key in keys {
                let k10 = key.rd_key[10];
                for _j in 0..NUM_ENCS {
                    blks[idx] = _mm_aesenclast_si128(blks[idx], k10);
                    idx += 1;
                }
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::aes_opt_x86::*;
    use core::arch::x86_64::*;

    #[test]
    fn test_aes128_known_vector_single() {
        // skip if host CPU can't run AES-NI (important if you run x86 under Rosetta on weird setups)
        if !(std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("ssse3")) {
            eprintln!("Skipping: AES/SSSE3 not detected");
            return;
        }

        unsafe {
            // NIST FIPS-197 example: (Appendix C.1 https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
            // key:        000102030405060708090a0b0c0d0e0f
            // plaintext:  00112233445566778899aabbccddeeff
            // ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
            let key_bytes: [u8; 16] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ];
            let pt_bytes: [u8; 16] = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ];
            let expected: [u8; 16] = [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a,
            ];

            let user_key = [loadu(&key_bytes)];
            let mut keys = [AESKey::default()];
            aes_opt_key_schedule::<1>(&user_key, &mut keys);

            let mut blks = vec![loadu(&pt_bytes)];
            para_enc::<1, 1>(&mut blks, &keys);

            let ct = storeu(blks[0]);
            assert_eq!(ct, expected);
        }
    }

    // Helpers
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn loadu(b: &[u8; 16]) -> block {
        unsafe { _mm_loadu_si128(b.as_ptr() as *const __m128i) }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn storeu(x: block) -> [u8; 16] {
        unsafe {
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
            out
        }
    }
}

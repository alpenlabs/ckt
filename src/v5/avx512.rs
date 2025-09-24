use std::arch::x86_64::*;

pub struct BlockV5a {
    pub in1_packed: [u8; 1088],
    pub in2_packed: [u8; 1088],
    pub out_packed: [u8; 1088],
    pub credits_packed: [u8; 768],
    pub gate_types: [u8; 32],
}

// Expand 34-bit little-endian fields to u64, and 24-bit little-endian to u32.
// - num_gates: how many gates to decode (<= 256)
// - Outputs are written to the first num_gates entries of the destination slices.
#[target_feature(enable = "avx512f")]
pub unsafe fn decode_block_v5a_avx512(
    blk: &BlockV5a,
    num_gates: usize,
    in1_out: &mut [u64],         // len >= 256
    in2_out: &mut [u64],         // len >= 256
    out_out: &mut [u64],         // len >= 256
    credits_out: &mut [u32],     // len >= 256
    gate_types_out: &mut [bool], // len >= 256
) {
    let n = num_gates.min(256);

    // Pad each stream with 8 zero bytes so gathers that read 8/4 bytes can’t go OOB.
    let mut in1_pad = [0u8; 1088 + 8];
    in1_pad[..1088].copy_from_slice(&blk.in1_packed);

    let mut in2_pad = [0u8; 1088 + 8];
    in2_pad[..1088].copy_from_slice(&blk.in2_packed);

    let mut out_pad = [0u8; 1088 + 8];
    out_pad[..1088].copy_from_slice(&blk.out_packed);

    let mut credits_pad = [0u8; 768 + 8];
    credits_pad[..768].copy_from_slice(&blk.credits_packed);

    unsafe {
        // Unpack 34->u64
        unpack_bits_34_to_u64_gather(&in1_pad, n, in1_out);
        unpack_bits_34_to_u64_gather(&in2_pad, n, in2_out);
        unpack_bits_34_to_u64_gather(&out_pad, n, out_out);
        // Unpack 24->u32 (vectorized 32-bit lanes; uses gathers of dwords)
        unpack_bits_24_to_u32_gather(&credits_pad, n, credits_out);
    }

    // Gate types (scalar, bit-per-gate)
    for i in 0..n {
        let b = blk.gate_types[i >> 3];
        gate_types_out[i] = ((b >> (i & 7)) & 1) != 0;
    }
}

pub struct BlockV5b {
    pub in1_stream: [u8; 1512], // 504 × 24 bits
    pub in2_stream: [u8; 1512], // 504 × 24 bits
    pub out_stream: [u8; 1512], // 504 × 24 bits
}

// Decode 3×24-bit streams into u32 outputs.
// - num_gates: how many gates to decode (<= 504).
// - Only the first num_gates entries of each destination slice are written.
#[target_feature(enable = "avx512f")]
pub unsafe fn decode_block_v5b_avx512(
    blk: &BlockV5b,
    num_gates: usize,
    in1_out: &mut [u32], // len >= 504
    in2_out: &mut [u32], // len >= 504
    out_out: &mut [u32], // len >= 504
) {
    let n = num_gates.min(504);

    debug_assert!(in1_out.len() >= n);
    debug_assert!(in2_out.len() >= n);
    debug_assert!(out_out.len() >= n);

    // Pad inputs with 8 zero bytes to keep 4-byte gathers in-bounds near the end.
    let mut in1_pad = [0u8; 1512 + 8];
    in1_pad[..1512].copy_from_slice(&blk.in1_stream);

    let mut in2_pad = [0u8; 1512 + 8];
    in2_pad[..1512].copy_from_slice(&blk.in2_stream);

    let mut out_pad = [0u8; 1512 + 8];
    out_pad[..1512].copy_from_slice(&blk.out_stream);

    unsafe {
        unpack_bits_24_to_u32_gather(&in1_pad, n, in1_out);
        unpack_bits_24_to_u32_gather(&in2_pad, n, in2_out);
        unpack_bits_24_to_u32_gather(&out_pad, n, out_out);
    }
}

// ========== Helpers ==========

// Unpack consecutive 34-bit little-endian fields into u64s using AVX-512F gathers.
// Processes 8 outputs per iteration (64-bit lanes).
#[inline]
#[target_feature(enable = "avx512f")]
pub unsafe fn unpack_bits_34_to_u64_gather(src_padded: &[u8], n: usize, dst: &mut [u64]) {
    debug_assert!(src_padded.len() >= 1088 + 8);
    let base = src_padded.as_ptr(); // padded with 8 trailing zeros

    let offs_bits = _mm512_setr_epi64(0, 34, 68, 102, 136, 170, 204, 238);
    let mask34 = _mm512_set1_epi64(0x3_FFFF_FFFF);
    let seven = _mm512_set1_epi64(7);

    let mut g = 0usize;
    while g + 8 <= n {
        let base_bits = (g as u64) * 34;
        let base_vec = _mm512_set1_epi64(base_bits as i64);
        let offs = _mm512_add_epi64(base_vec, offs_bits); // bit offsets
        let byte_idx = _mm512_srli_epi64(offs, 3); // /8
        let bit_shift = _mm512_and_si512(offs, seven); // &7

        // SCALE=1 (byte addressing), base typed to *const i64 (element type)
        let words = unsafe { _mm512_i64gather_epi64::<1>(byte_idx, base as *const i64) };
        let shifted = _mm512_srlv_epi64(words, bit_shift);
        let vals = _mm512_and_si512(shifted, mask34);

        unsafe { _mm512_storeu_si512(dst[g..].as_mut_ptr() as *mut __m512i, vals) };
        g += 8;
    }

    if g < n {
        let rem = n - g;
        let base_bits = (g as u64) * 34;
        let base_vec = _mm512_set1_epi64(base_bits as i64);
        let offs = _mm512_add_epi64(base_vec, offs_bits);
        let byte_idx = _mm512_srli_epi64(offs, 3);
        let bit_shift = _mm512_and_si512(offs, seven);
        let words = unsafe { _mm512_i64gather_epi64::<1>(byte_idx, base as *const i64) };
        let shifted = _mm512_srlv_epi64(words, bit_shift);
        let vals = _mm512_and_si512(shifted, _mm512_set1_epi64(0x3_FFFF_FFFF));

        let mut tmp = [0u64; 8];
        unsafe { _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, vals) };
        dst[g..g + rem].copy_from_slice(&tmp[..rem]);
    }
}

// Unpack consecutive 24-bit little-endian fields into u32s using AVX-512F gathers.
// Processes 16 outputs per iteration (32-bit lanes).
#[inline]
#[target_feature(enable = "avx512f")]
pub unsafe fn unpack_bits_24_to_u32_gather(src_padded: &[u8], n: usize, dst: &mut [u32]) {
    debug_assert!(src_padded.len() >= 768 + 8);
    let base = src_padded.as_ptr();

    let offs_bits = _mm512_setr_epi32(
        0, 24, 48, 72, 96, 120, 144, 168, 192, 216, 240, 264, 288, 312, 336, 360,
    );
    let mask24 = _mm512_set1_epi32(0x00FF_FFFF);
    let seven = _mm512_set1_epi32(7);

    let mut g = 0usize;
    while g + 16 <= n {
        let base_bits = (g as u32) * 24;
        let base_vec = _mm512_set1_epi32(base_bits as i32);
        let offs = _mm512_add_epi32(base_vec, offs_bits);
        let byte_idx = _mm512_srli_epi32(offs, 3);
        let bit_shift = _mm512_and_si512(offs, seven);

        // SCALE=1 (byte addressing), base typed to *const i32 (element type)
        let dwords = unsafe { _mm512_i32gather_epi32::<1>(byte_idx, base as *const i32) };
        let shifted = _mm512_srlv_epi32(dwords, bit_shift);
        let vals = _mm512_and_si512(shifted, mask24);

        unsafe { _mm512_storeu_si512(dst[g..].as_mut_ptr() as *mut __m512i, vals) };
        g += 16;
    }

    if g < n {
        let rem = n - g;
        let base_bits = (g as u32) * 24;
        let base_vec = _mm512_set1_epi32(base_bits as i32);
        let offs = _mm512_add_epi32(base_vec, offs_bits);
        let byte_idx = _mm512_srli_epi32(offs, 3);
        let bit_shift = _mm512_and_si512(offs, seven);

        let dwords = unsafe { _mm512_i32gather_epi32::<1>(byte_idx, base as *const i32) };
        let shifted = _mm512_srlv_epi32(dwords, bit_shift);
        let vals = _mm512_and_si512(shifted, _mm512_set1_epi32(0x00FF_FFFF));

        let mut tmp = [0u32; 16];
        unsafe { _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, vals) };
        dst[g..g + rem].copy_from_slice(&tmp[..rem]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --------- Utilities ---------

    // Simple deterministic PRNG (LCG) for reproducible fuzzing
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed)
        }
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.0 >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            let hi = self.next_u32() as u64;
            let lo = self.next_u32() as u64;
            (hi << 32) | lo
        }
    }

    // Pack `width` LSBs of `value` into `dst` at little-endian bit position `bit_offset`.
    fn pack_bits_le(dst: &mut [u8], bit_offset: usize, width: usize, value: u64) {
        let mut v = value;
        for k in 0..width {
            let bit = (v & 1) != 0;
            v >>= 1;
            let pos = bit_offset + k;
            let byte = pos >> 3;
            let bit_in_byte = pos & 7;
            if byte < dst.len() && bit {
                dst[byte] |= 1u8 << bit_in_byte;
            }
        }
    }

    // Scalar reference extractor for up to 64-bit wide fields.
    fn ref_extract_bits_le(src: &[u8], bit_offset: usize, width: usize) -> u64 {
        debug_assert!(width <= 64);
        let byte_offset = bit_offset >> 3;
        let bit_in_byte = (bit_offset & 7) as u32;
        let mut buf = [0u8; 9];
        let max_need = ((width + (bit_in_byte as usize) + 7) >> 3).min(9);
        if byte_offset < src.len() {
            let available = src.len() - byte_offset;
            let to_copy = max_need.min(available);
            buf[..to_copy].copy_from_slice(&src[byte_offset..byte_offset + to_copy]);
        }
        let mut acc = 0u128;
        for i in (0..max_need).rev() {
            acc <<= 8;
            acc |= buf[i] as u128;
        }
        let acc = acc >> bit_in_byte;
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        (acc as u64) & mask
    }

    fn ref_unpack_34_to_u64(src: &[u8], n: usize, out: &mut [u64]) {
        for i in 0..n {
            out[i] = ref_extract_bits_le(src, i * 34, 34);
        }
    }
    fn ref_unpack_24_to_u32(src: &[u8], n: usize, out: &mut [u32]) {
        for i in 0..n {
            out[i] = ref_extract_bits_le(src, i * 24, 24) as u32;
        }
    }

    fn pack_stream_34(vals: &[u64]) -> [u8; 1088] {
        let mut buf = [0u8; 1088];
        for (i, &v) in vals.iter().enumerate() {
            pack_bits_le(&mut buf, i * 34, 34, v & 0x3FFFF_FFFF);
        }
        buf
    }
    fn pack_stream_24(vals: &[u32]) -> [u8; 768] {
        let mut buf = [0u8; 768];
        for (i, &v) in vals.iter().enumerate() {
            pack_bits_le(&mut buf, i * 24, 24, (v & 0x00FF_FFFF) as u64);
        }
        buf
    }

    // Stable-friendly padding: return a Vec with 8 zero bytes appended.
    fn pad8_bytes(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(src.len() + 8);
        out.extend_from_slice(src);
        out.resize(src.len() + 8, 0);
        out
    }

    // Build a full block from streams and type bits
    fn make_block(
        in1: &[u64; 256],
        in2: &[u64; 256],
        out_vals: &[u64; 256],
        credits: &[u32; 256],
        gate_types_bits: &[bool; 256],
    ) -> BlockV5a {
        let in1_packed = pack_stream_34(in1);
        let in2_packed = pack_stream_34(in2);
        let out_packed = pack_stream_34(out_vals);
        let credits_packed = pack_stream_24(credits);

        let mut gate_types = [0u8; 32];
        for i in 0..256 {
            if gate_types_bits[i] {
                let byte = i >> 3;
                let bit = i & 7;
                gate_types[byte] |= 1u8 << bit;
            }
        }

        BlockV5a {
            in1_packed,
            in2_packed,
            out_packed,
            credits_packed,
            gate_types,
        }
    }

    // --------- AVX-512 feature check ---------

    #[cfg(target_arch = "x86_64")]
    fn avx512_available() -> bool {
        is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn avx512_available() -> bool {
        false
    }

    // ---- Helper tests: unpack_bits_34_to_u64_gather and unpack_bits_24_to_u32_gather ----

    #[test]
    fn unpack_34_zeroes_and_max() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            // Zeroes
            let zeros = [0u64; 256];
            let packed = pack_stream_34(&zeros);
            let padded = pad8_bytes(&packed);

            let mut out = [0u64; 256];
            unpack_bits_34_to_u64_gather(&padded, 256, &mut out);
            assert!(out.iter().all(|&v| v == 0));

            // Max values
            let max = [0x3FFFF_FFFFu64; 256];
            let packed = pack_stream_34(&max);
            let padded = pad8_bytes(&packed);
            let mut out = [0u64; 256];
            unpack_bits_34_to_u64_gather(&padded, 256, &mut out);
            assert!(out.iter().all(|&v| v == 0x3FFFF_FFFF));
        }
    }

    #[test]
    fn unpack_24_zeroes_and_max() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            // Zeroes
            let zeros = [0u32; 256];
            let packed = pack_stream_24(&zeros);
            let padded = pad8_bytes(&packed);

            let mut out = [0u32; 256];
            unpack_bits_24_to_u32_gather(&padded, 256, &mut out);
            assert!(out.iter().all(|&v| v == 0));

            // Max values
            let max = [0x00FF_FFFFu32; 256];
            let packed = pack_stream_24(&max);
            let padded = pad8_bytes(&packed);
            let mut out = [0u32; 256];
            unpack_bits_24_to_u32_gather(&padded, 256, &mut out);
            assert!(out.iter().all(|&v| v == 0x00FF_FFFF));
        }
    }

    #[test]
    fn unpack_34_tails_various_n() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let ns = [
                0usize, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256,
            ];
            let mut vals = [0u64; 256];
            for i in 0..256 {
                vals[i] = ((i as u64) * 0x1F_0003) & 0x3FFFF_FFFF;
            }
            let packed = pack_stream_34(&vals);
            let padded = pad8_bytes(&packed);

            for &n in &ns {
                let mut simd = [0u64; 256];
                let mut refv = [0u64; 256];
                unpack_bits_34_to_u64_gather(&padded, n, &mut simd);
                ref_unpack_34_to_u64(&packed, n, &mut refv);
                assert_eq!(&simd[..n], &refv[..n], "mismatch at n={}", n);
            }
        }
    }

    #[test]
    fn unpack_24_tails_various_n() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let ns = [
                0usize, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256,
            ];
            let mut vals = [0u32; 256];
            for i in 0..256 {
                vals[i] = (((i as u32) * 65537) ^ 0x0055_AA55) & 0x00FF_FFFF;
            }
            let packed = pack_stream_24(&vals);
            let padded = pad8_bytes(&packed);

            for &n in &ns {
                let mut simd = [0u32; 256];
                let mut refv = [0u32; 256];
                unpack_bits_24_to_u32_gather(&padded, n, &mut simd);
                ref_unpack_24_to_u32(&packed, n, &mut refv);
                assert_eq!(&simd[..n], &refv[..n], "mismatch at n={}", n);
            }
        }
    }

    #[test]
    fn unpack_34_boundary_last_field_crosses_end() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let mut vals = [0u64; 256];
            vals.fill(0);
            vals[255] = 0x0123_4567u64 & 0x3FFFF_FFFF;
            let packed = pack_stream_34(&vals);
            let padded = pad8_bytes(&packed);

            let mut simd = [0u64; 256];
            let mut refv = [0u64; 256];
            unpack_bits_34_to_u64_gather(&padded, 256, &mut simd);
            ref_unpack_34_to_u64(&packed, 256, &mut refv);

            assert_eq!(simd[255], 0x0123_4567);
            assert_eq!(simd, refv);
        }
    }

    #[test]
    fn unpack_24_boundary_last_field_crosses_end() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let mut vals = [0u32; 256];
            vals.fill(0);
            vals[255] = 0x00AB_CDEF;
            let packed = pack_stream_24(&vals);
            let padded = pad8_bytes(&packed);

            let mut simd = [0u32; 256];
            let mut refv = [0u32; 256];
            unpack_bits_24_to_u32_gather(&padded, 256, &mut simd);
            ref_unpack_24_to_u32(&packed, 256, &mut refv);

            assert_eq!(simd[255], 0x00AB_CDEF);
            assert_eq!(simd, refv);
        }
    }

    #[test]
    fn unpack_fuzz_randomized_compare_scalar() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
            for iter in 0..200 {
                let n = (rng.next_u32() as usize % 257).min(256);

                let mut v34 = [0u64; 256];
                for i in 0..256 {
                    v34[i] = rng.next_u64() & 0x3FFFF_FFFF;
                }
                let mut v24 = [0u32; 256];
                for i in 0..256 {
                    v24[i] = rng.next_u32() & 0x00FF_FFFF;
                }

                let p34 = pack_stream_34(&v34);
                let p24 = pack_stream_24(&v24);
                let p34_pad = pad8_bytes(&p34);
                let p24_pad = pad8_bytes(&p24);

                let mut simd34 = [0u64; 256];
                let mut ref34 = [0u64; 256];
                unpack_bits_34_to_u64_gather(&p34_pad, n, &mut simd34);
                ref_unpack_34_to_u64(&p34, n, &mut ref34);
                assert_eq!(
                    &simd34[..n],
                    &ref34[..n],
                    "iter={}, n={}, 34-bit mismatch",
                    iter,
                    n
                );

                let mut simd24 = [0u32; 256];
                let mut ref24 = [0u32; 256];
                unpack_bits_24_to_u32_gather(&p24_pad, n, &mut simd24);
                ref_unpack_24_to_u32(&p24, n, &mut ref24);
                assert_eq!(
                    &simd24[..n],
                    &ref24[..n],
                    "iter={}, n={}, 24-bit mismatch",
                    iter,
                    n
                );
            }
        }
    }

    // ---- Full block decoder tests ----

    #[test]
    fn decode_block_full_basic_patterns() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let mut in1 = [0u64; 256];
            let mut in2 = [0u64; 256];
            let mut out_vals = [0u64; 256];
            let mut credits = [0u32; 256];
            let mut types = [false; 256];

            for i in 0..256 {
                in1[i] = ((i as u64) * 7 + 2) & 0x3FFFF_FFFF;
                in2[i] = ((i as u64) * 5 + 3) & 0x3FFFF_FFFF;
                out_vals[i] = ((i as u64) * 11 + 1) & 0x3FFFF_FFFF;
                credits[i] = (((i as u32) * 3 + 1) % 1_000_000) & 0x00FF_FFFF;
                types[i] = (i % 3) == 1;
            }

            let blk = make_block(&in1, &in2, &out_vals, &credits, &types);

            let mut out_in1 = [0u64; 256];
            let mut out_in2 = [0u64; 256];
            let mut out_out = [0u64; 256];
            let mut out_cred = [0u32; 256];
            let mut out_types = [false; 256];

            decode_block_v5a_avx512(
                &blk,
                256,
                &mut out_in1,
                &mut out_in2,
                &mut out_out,
                &mut out_cred,
                &mut out_types,
            );

            assert_eq!(out_in1, in1);
            assert_eq!(out_in2, in2);
            assert_eq!(out_out, out_vals);
            assert_eq!(out_cred, credits);
            assert_eq!(out_types, types);
        }
    }

    #[test]
    fn decode_block_various_n_and_edges() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let ns = [
                1usize, 2, 7, 8, 9, 15, 16, 17, 63, 64, 127, 128, 129, 255, 256,
            ];

            let mut in1 = [0u64; 256];
            let mut in2 = [0u64; 256];
            let mut out_vals = [0u64; 256];
            let mut credits = [0u32; 256];
            let mut types = [false; 256];

            for i in 0..256 {
                in1[i] = if i % 2 == 0 {
                    0x3FFFF_FFFF
                } else {
                    (i as u64) & 0x3FFFF_FFFF
                };
                in2[i] = if i % 3 == 0 {
                    (i as u64) * 0x1_0001 & 0x3FFFF_FFFF
                } else {
                    0
                };
                out_vals[i] = (0x3AA55AA5u64.wrapping_mul(i as u64)) & 0x3FFFF_FFFF;
                credits[i] = if i % 5 == 0 {
                    0x00FF_FFFF
                } else {
                    (i as u32) ^ 0x0055_AA55
                } & 0x00FF_FFFF;
                types[i] = (i & 1) != 0;
            }

            let blk = make_block(&in1, &in2, &out_vals, &credits, &types);

            for &n in &ns {
                let mut out_in1 = [0u64; 256];
                let mut out_in2 = [0u64; 256];
                let mut out_out = [0u64; 256];
                let mut out_cred = [0u32; 256];
                let mut out_types = [false; 256];

                decode_block_v5a_avx512(
                    &blk,
                    n,
                    &mut out_in1,
                    &mut out_in2,
                    &mut out_out,
                    &mut out_cred,
                    &mut out_types,
                );

                assert_eq!(&out_in1[..n], &in1[..n], "in1 mismatch at n={}", n);
                assert_eq!(&out_in2[..n], &in2[..n], "in2 mismatch at n={}", n);
                assert_eq!(&out_out[..n], &out_vals[..n], "out mismatch at n={}", n);
                assert_eq!(&out_cred[..n], &credits[..n], "credits mismatch at n={}", n);
                assert_eq!(&out_types[..n], &types[..n], "types mismatch at n={}", n);
            }
        }
    }

    #[test]
    fn decode_block_randomized_compare_scalar_per_stream() {
        if !avx512_available() {
            eprintln!("Skipping: AVX-512F not available");
            return;
        }
        unsafe {
            let mut rng = Rng::new(0xCAFEBABE_D00D_F00D);
            for iter in 0..100 {
                let n = (rng.next_u32() as usize % 257).min(256);

                let mut in1 = [0u64; 256];
                let mut in2 = [0u64; 256];
                let mut out_vals = [0u64; 256];
                let mut credits = [0u32; 256];
                let mut types = [false; 256];

                for i in 0..256 {
                    in1[i] = rng.next_u64() & 0x3FFFF_FFFF;
                    in2[i] = rng.next_u64() & 0x3FFFF_FFFF;
                    out_vals[i] = rng.next_u64() & 0x3FFFF_FFFF;
                    credits[i] = rng.next_u32() & 0x00FF_FFFF;
                    types[i] = (rng.next_u32() & 1) != 0;
                }

                let blk = make_block(&in1, &in2, &out_vals, &credits, &types);

                let mut out_in1 = [0u64; 256];
                let mut out_in2 = [0u64; 256];
                let mut out_out = [0u64; 256];
                let mut out_cred = [0u32; 256];
                let mut out_types = [false; 256];

                decode_block_v5a_avx512(
                    &blk,
                    n,
                    &mut out_in1,
                    &mut out_in2,
                    &mut out_out,
                    &mut out_cred,
                    &mut out_types,
                );

                // Also validate streams against scalar references
                let mut ref_in1 = [0u64; 256];
                let mut ref_in2 = [0u64; 256];
                let mut ref_out = [0u64; 256];
                let mut ref_cr = [0u32; 256];

                ref_unpack_34_to_u64(&blk.in1_packed, n, &mut ref_in1);
                ref_unpack_34_to_u64(&blk.in2_packed, n, &mut ref_in2);
                ref_unpack_34_to_u64(&blk.out_packed, n, &mut ref_out);
                ref_unpack_24_to_u32(&blk.credits_packed, n, &mut ref_cr);

                assert_eq!(&out_in1[..n], &ref_in1[..n], "iter {}: in1 mismatch", iter);
                assert_eq!(&out_in2[..n], &ref_in2[..n], "iter {}: in2 mismatch", iter);
                assert_eq!(&out_out[..n], &ref_out[..n], "iter {}: out mismatch", iter);
                assert_eq!(
                    &out_cred[..n],
                    &ref_cr[..n],
                    "iter {}: credits mismatch",
                    iter
                );

                // Gate types bit extraction cross-check
                for i in 0..n {
                    let b = blk.gate_types[i >> 3];
                    let bit = ((b >> (i & 7)) & 1) != 0;
                    assert_eq!(
                        out_types[i], bit,
                        "iter {} gate_types mismatch at {}",
                        iter, i
                    );
                }
            }
        }
    }

    use std::hint::black_box;
    use std::time::{Duration, Instant};

    // Simple timed loop: run `f` until `target` duration is reached.
    fn time_loop(mut f: impl FnMut(), target: Duration) -> (u64, Duration) {
        // Warm-up
        for _ in 0..10 {
            f();
        }
        let start = Instant::now();
        let mut iters = 0u64;
        while start.elapsed() < target {
            f();
            iters += 1;
        }
        (iters, start.elapsed())
    }

    fn fmt_rate(gates: f64, secs: f64, bytes_per_gate: f64) -> String {
        let gps = gates / secs;
        let mbps = (gates * bytes_per_gate) / secs / 1e6;
        format!("{:.2} M gates/s, {:.2} MB/s", gps / 1e6, mbps)
    }

    #[test]
    #[ignore]
    fn bench_unpack_streams_scalar_vs_avx512() {
        let n = 256;

        // Inputs
        let mut rng = Rng::new(0xBEEFFEED12345678);
        let mut v34 = [0u64; 256];
        let mut v24 = [0u32; 256];
        for i in 0..256 {
            v34[i] = rng.next_u64() & 0x3FFFF_FFFF;
            v24[i] = rng.next_u32() & 0x00FF_FFFF;
        }
        let p34 = pack_stream_34(&v34);
        let p24 = pack_stream_24(&v24);
        let p34_pad = pad8_bytes(&p34);
        let p24_pad = pad8_bytes(&p24);

        // Correctness check
        let mut ref34 = [0u64; 256];
        let mut ref24 = [0u32; 256];
        ref_unpack_34_to_u64(&p34, n, &mut ref34);
        ref_unpack_24_to_u32(&p24, n, &mut ref24);

        if avx512_available() {
            unsafe {
                let mut simd34 = [0u64; 256];
                let mut simd24 = [0u32; 256];
                unpack_bits_34_to_u64_gather(&p34_pad, n, &mut simd34);
                unpack_bits_24_to_u32_gather(&p24_pad, n, &mut simd24);
                assert_eq!(
                    &simd34[..n],
                    &ref34[..n],
                    "AVX512 34-bit mismatch before bench"
                );
                assert_eq!(
                    &simd24[..n],
                    &ref24[..n],
                    "AVX512 24-bit mismatch before bench"
                );
            }
        }

        // Scalar 34
        let target = Duration::from_millis(400);
        let mut out34 = [0u64; 256];
        let (iters_s34, dur_s34) = time_loop(
            || {
                ref_unpack_34_to_u64(black_box(&p34), n, &mut out34);
                black_box(out34[0]); // keep live
            },
            target,
        );

        // Scalar 24
        let mut out24 = [0u32; 256];
        let (iters_s24, dur_s24) = time_loop(
            || {
                ref_unpack_24_to_u32(black_box(&p24), n, &mut out24);
                black_box(out24[0]);
            },
            target,
        );

        println!(
            "Scalar 34→u64: {} (n={}, iters={}, time={:?})",
            fmt_rate(
                (iters_s34 as f64) * (n as f64),
                dur_s34.as_secs_f64(),
                34.0 / 8.0
            ),
            n,
            iters_s34,
            dur_s34
        );
        println!(
            "Scalar 24→u32: {} (n={}, iters={}, time={:?})",
            fmt_rate(
                (iters_s24 as f64) * (n as f64),
                dur_s24.as_secs_f64(),
                24.0 / 8.0
            ),
            n,
            iters_s24,
            dur_s24
        );

        // AVX-512 (if available)
        if avx512_available() {
            unsafe {
                // AVX 34
                let mut out34v = [0u64; 256];
                let (iters_v34, dur_v34) = time_loop(
                    || {
                        unpack_bits_34_to_u64_gather(black_box(&p34_pad), n, &mut out34v);
                        black_box(out34v[0]);
                    },
                    target,
                );

                // AVX 24
                let mut out24v = [0u32; 256];
                let (iters_v24, dur_v24) = time_loop(
                    || {
                        unpack_bits_24_to_u32_gather(black_box(&p24_pad), n, &mut out24v);
                        black_box(out24v[0]);
                    },
                    target,
                );

                println!(
                    "AVX512 34→u64: {} (n={}, iters={}, time={:?})",
                    fmt_rate(
                        (iters_v34 as f64) * (n as f64),
                        dur_v34.as_secs_f64(),
                        34.0 / 8.0
                    ),
                    n,
                    iters_v34,
                    dur_v34
                );
                println!(
                    "AVX512 24→u32: {} (n={}, iters={}, time={:?})",
                    fmt_rate(
                        (iters_v24 as f64) * (n as f64),
                        dur_v24.as_secs_f64(),
                        24.0 / 8.0
                    ),
                    n,
                    iters_v24,
                    dur_v24
                );
            }
        } else {
            println!("AVX-512F not available: skipping AVX gather benchmarks.");
        }
    }

    #[test]
    #[ignore]
    fn bench_full_block_decode_scalar_vs_avx512() {
        let n = 256;

        // Build randomized block
        let mut rng = Rng::new(0xF00D_BABE_C0FFEE01);
        let mut in1 = [0u64; 256];
        let mut in2 = [0u64; 256];
        let mut out_vals = [0u64; 256];
        let mut credits = [0u32; 256];
        let mut types = [false; 256];
        for i in 0..256 {
            in1[i] = rng.next_u64() & 0x3FFFF_FFFF;
            in2[i] = rng.next_u64() & 0x3FFFF_FFFF;
            out_vals[i] = rng.next_u64() & 0x3FFFF_FFFF;
            credits[i] = rng.next_u32() & 0x00FF_FFFF;
            types[i] = (rng.next_u32() & 1) != 0;
        }
        let blk = make_block(&in1, &in2, &out_vals, &credits, &types);

        // Outputs
        let mut out_in1 = [0u64; 256];
        let mut out_in2 = [0u64; 256];
        let mut out_out = [0u64; 256];
        let mut out_cred = [0u32; 256];
        let mut out_types = [false; 256];

        // Scalar reference (used for correctness and timing)
        fn decode_scalar(
            blk: &BlockV5a,
            n: usize,
            o1: &mut [u64],
            o2: &mut [u64],
            oo: &mut [u64],
            oc: &mut [u32],
            gt: &mut [bool],
        ) {
            ref_unpack_34_to_u64(&blk.in1_packed, n, o1);
            ref_unpack_34_to_u64(&blk.in2_packed, n, o2);
            ref_unpack_34_to_u64(&blk.out_packed, n, oo);
            ref_unpack_24_to_u32(&blk.credits_packed, n, oc);
            for i in 0..n {
                let b = blk.gate_types[i >> 3];
                gt[i] = ((b >> (i & 7)) & 1) != 0;
            }
        }

        // Correctness check for AVX path
        if avx512_available() {
            unsafe {
                let mut v1 = [0u64; 256];
                let mut v2 = [0u64; 256];
                let mut vo = [0u64; 256];
                let mut vc = [0u32; 256];
                let mut vt = [false; 256];
                decode_block_v5a_avx512(&blk, n, &mut v1, &mut v2, &mut vo, &mut vc, &mut vt);

                let mut r1 = [0u64; 256];
                let mut r2 = [0u64; 256];
                let mut ro = [0u64; 256];
                let mut rc = [0u32; 256];
                let mut rt = [false; 256];
                decode_scalar(&blk, n, &mut r1, &mut r2, &mut ro, &mut rc, &mut rt);

                assert_eq!(v1, r1);
                assert_eq!(v2, r2);
                assert_eq!(vo, ro);
                assert_eq!(vc, rc);
                assert_eq!(vt, rt);
            }
        }

        // Benchmark scalar
        let target = Duration::from_millis(400);
        let (iters_s, dur_s) = time_loop(
            || {
                decode_scalar(
                    black_box(&blk),
                    n,
                    &mut out_in1,
                    &mut out_in2,
                    &mut out_out,
                    &mut out_cred,
                    &mut out_types,
                );
                black_box(out_in1[0]);
            },
            target,
        );

        // Logical bytes per gate for full block (including gate_types): 4064 / 256 = 15.875
        let bytes_per_gate_full = 15.875_f64;

        println!(
            "Scalar full decode: {} (n={}, iters={}, time={:?})",
            fmt_rate(
                (iters_s as f64) * (n as f64),
                dur_s.as_secs_f64(),
                bytes_per_gate_full
            ),
            n,
            iters_s,
            dur_s
        );

        // Benchmark AVX-512 if available
        if avx512_available() {
            unsafe {
                let (iters_v, dur_v) = time_loop(
                    || {
                        decode_block_v5a_avx512(
                            black_box(&blk),
                            n,
                            &mut out_in1,
                            &mut out_in2,
                            &mut out_out,
                            &mut out_cred,
                            &mut out_types,
                        );
                        black_box(out_in1[0]);
                    },
                    target,
                );

                println!(
                    "AVX512 full decode: {} (n={}, iters={}, time={:?})",
                    fmt_rate(
                        (iters_v as f64) * (n as f64),
                        dur_v.as_secs_f64(),
                        bytes_per_gate_full
                    ),
                    n,
                    iters_v,
                    dur_v
                );
            }
        } else {
            println!("AVX-512F not available: skipping AVX full decode benchmark.");
        }
    }

    fn fmt_gps(gates: f64, secs: f64) -> String {
        let gps = gates / secs;
        format!("{:.2} M gates/s", gps / 1e6)
    }

    #[test]
    #[ignore]
    fn bench_gates_per_sec_v5a_scalar_vs_avx512() {
        let n = 256;

        // Build randomized v5a block
        let mut rng = Rng::new(0xA11CE5EED1234567);
        let mut in1 = [0u64; 256];
        let mut in2 = [0u64; 256];
        let mut out_vals = [0u64; 256];
        let mut credits = [0u32; 256];
        let mut types = [false; 256];
        for i in 0..256 {
            in1[i] = rng.next_u64() & 0x3FFFF_FFFF;
            in2[i] = rng.next_u64() & 0x3FFFF_FFFF;
            out_vals[i] = rng.next_u64() & 0x3FFFF_FFFF;
            credits[i] = rng.next_u32() & 0x00FF_FFFF;
            types[i] = (rng.next_u32() & 1) != 0;
        }
        let blk = make_block(&in1, &in2, &out_vals, &credits, &types);

        // Scalar decoder (reference)
        fn decode_scalar_v5a(
            blk: &BlockV5a,
            n: usize,
            o1: &mut [u64],
            o2: &mut [u64],
            oo: &mut [u64],
            oc: &mut [u32],
            gt: &mut [bool],
        ) {
            ref_unpack_34_to_u64(&blk.in1_packed, n, o1);
            ref_unpack_34_to_u64(&blk.in2_packed, n, o2);
            ref_unpack_34_to_u64(&blk.out_packed, n, oo);
            ref_unpack_24_to_u32(&blk.credits_packed, n, oc);
            for i in 0..n {
                let b = blk.gate_types[i >> 3];
                gt[i] = ((b >> (i & 7)) & 1) != 0;
            }
        }

        // Correctness check for AVX path (if available)
        if avx512_available() {
            unsafe {
                let mut v1 = [0u64; 256];
                let mut v2 = [0u64; 256];
                let mut vo = [0u64; 256];
                let mut vc = [0u32; 256];
                let mut vt = [false; 256];
                decode_block_v5a_avx512(&blk, n, &mut v1, &mut v2, &mut vo, &mut vc, &mut vt);

                let mut r1 = [0u64; 256];
                let mut r2 = [0u64; 256];
                let mut ro = [0u64; 256];
                let mut rc = [0u32; 256];
                let mut rt = [false; 256];
                decode_scalar_v5a(&blk, n, &mut r1, &mut r2, &mut ro, &mut rc, &mut rt);

                assert_eq!(v1, r1);
                assert_eq!(v2, r2);
                assert_eq!(vo, ro);
                assert_eq!(vc, rc);
                assert_eq!(vt, rt);
            }
        }

        // Benchmark scalar
        let mut out_in1 = [0u64; 256];
        let mut out_in2 = [0u64; 256];
        let mut out_out = [0u64; 256];
        let mut out_cred = [0u32; 256];
        let mut out_types = [false; 256];
        let target = Duration::from_millis(500);
        let (iters_s, dur_s) = time_loop(
            || {
                decode_scalar_v5a(
                    black_box(&blk),
                    n,
                    &mut out_in1,
                    &mut out_in2,
                    &mut out_out,
                    &mut out_cred,
                    &mut out_types,
                );
                black_box(out_in1[0]);
            },
            target,
        );
        let gates_s = (iters_s as f64) * (n as f64);
        println!(
            "v5a scalar: {} (n={}, iters={}, time={:?})",
            fmt_gps(gates_s, dur_s.as_secs_f64()),
            n,
            iters_s,
            dur_s
        );

        // Benchmark AVX-512 (if available)
        if avx512_available() {
            unsafe {
                let (iters_v, dur_v) = time_loop(
                    || {
                        decode_block_v5a_avx512(
                            black_box(&blk),
                            n,
                            &mut out_in1,
                            &mut out_in2,
                            &mut out_out,
                            &mut out_cred,
                            &mut out_types,
                        );
                        black_box(out_in1[0]);
                    },
                    target,
                );
                let gates_v = (iters_v as f64) * (n as f64);
                println!(
                    "v5a AVX-512: {} (n={}, iters={}, time={:?})",
                    fmt_gps(gates_v, dur_v.as_secs_f64()),
                    n,
                    iters_v,
                    dur_v
                );
                if gates_s > 0.0 {
                    println!(
                        "v5a speedup (AVX/scalar): {:.2}×",
                        (gates_v / dur_v.as_secs_f64()) / (gates_s / dur_s.as_secs_f64())
                    );
                }
            }
        } else {
            println!("AVX-512F not available: skipping v5a AVX benchmark.");
        }
    }

    #[test]
    #[ignore]
    fn bench_gates_per_sec_v5b_scalar_vs_avx512() {
        let n = 256;

        // v5b: 3×24-bit streams per gate (simulate structure with 3 independent streams)
        let mut rng = Rng::new(0xBADC0FFEE0DDF00D);
        let mut a = [0u32; 256];
        let mut b = [0u32; 256];
        let mut c = [0u32; 256];
        for i in 0..256 {
            a[i] = rng.next_u32() & 0x00FF_FFFF;
            b[i] = rng.next_u32() & 0x00FF_FFFF;
            c[i] = rng.next_u32() & 0x00FF_FFFF;
        }
        let pa = pack_stream_24(&a);
        let pb = pack_stream_24(&b);
        let pc = pack_stream_24(&c);
        let pa_pad = pad8_bytes(&pa);
        let pb_pad = pad8_bytes(&pb);
        let pc_pad = pad8_bytes(&pc);

        // Correctness check for AVX path (if available)
        if avx512_available() {
            unsafe {
                let mut va = [0u32; 256];
                let mut vb = [0u32; 256];
                let mut vc = [0u32; 256];
                unpack_bits_24_to_u32_gather(&pa_pad, n, &mut va);
                unpack_bits_24_to_u32_gather(&pb_pad, n, &mut vb);
                unpack_bits_24_to_u32_gather(&pc_pad, n, &mut vc);

                let mut ra = [0u32; 256];
                let mut rb = [0u32; 256];
                let mut rc = [0u32; 256];
                ref_unpack_24_to_u32(&pa, n, &mut ra);
                ref_unpack_24_to_u32(&pb, n, &mut rb);
                ref_unpack_24_to_u32(&pc, n, &mut rc);

                assert_eq!(va, ra);
                assert_eq!(vb, rb);
                assert_eq!(vc, rc);
            }
        }

        // Benchmark scalar (3×24-bit streams)
        let mut oa = [0u32; 256];
        let mut ob = [0u32; 256];
        let mut oc = [0u32; 256];
        let target = Duration::from_millis(500);
        let (iters_s, dur_s) = time_loop(
            || {
                ref_unpack_24_to_u32(black_box(&pa), n, &mut oa);
                ref_unpack_24_to_u32(black_box(&pb), n, &mut ob);
                ref_unpack_24_to_u32(black_box(&pc), n, &mut oc);
                black_box(oa[0]);
            },
            target,
        );
        let gates_s = (iters_s as f64) * (n as f64);
        println!(
            "v5b scalar: {} (n={}, iters={}, time={:?})",
            fmt_gps(gates_s, dur_s.as_secs_f64()),
            n,
            iters_s,
            dur_s
        );

        // Benchmark AVX-512 (3×24-bit streams)
        if avx512_available() {
            unsafe {
                let (iters_v, dur_v) = time_loop(
                    || {
                        unpack_bits_24_to_u32_gather(black_box(&pa_pad), n, &mut oa);
                        unpack_bits_24_to_u32_gather(black_box(&pb_pad), n, &mut ob);
                        unpack_bits_24_to_u32_gather(black_box(&pc_pad), n, &mut oc);
                        black_box(oa[0]);
                    },
                    target,
                );
                let gates_v = (iters_v as f64) * (n as f64);
                println!(
                    "v5b AVX-512: {} (n={}, iters={}, time={:?})",
                    fmt_gps(gates_v, dur_v.as_secs_f64()),
                    n,
                    iters_v,
                    dur_v
                );
                if gates_s > 0.0 {
                    println!(
                        "v5b speedup (AVX/scalar): {:.2}×",
                        (gates_v / dur_v.as_secs_f64()) / (gates_s / dur_s.as_secs_f64())
                    );
                }
            }
        } else {
            println!("AVX-512F not available: skipping v5b AVX benchmark.");
        }
    }

    #[cfg(test)]
    mod tests_v5b {
        use super::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::is_x86_feature_detected;

        // ---------- Utilities ----------

        // Simple deterministic PRNG
        struct Rng(u64);
        impl Rng {
            fn new(seed: u64) -> Self {
                Rng(seed)
            }
            fn next_u32(&mut self) -> u32 {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                (self.0 >> 32) as u32
            }
        }

        // Pack `width` LSBs of `value` into `dst` at little-endian bit position `bit_offset`.
        fn pack_bits_le(dst: &mut [u8], bit_offset: usize, width: usize, value: u64) {
            debug_assert!(width <= 64);
            let mut v = value;
            for k in 0..width {
                let bit = (v & 1) != 0;
                v >>= 1;
                let pos = bit_offset + k;
                let byte = pos >> 3;
                let bit_in_byte = pos & 7;
                if bit {
                    dst[byte] |= 1u8 << bit_in_byte;
                }
            }
        }

        // Scalar reference extractor for up to 64-bit fields, little-endian bit order.
        fn ref_extract_bits_le(src: &[u8], bit_offset: usize, width: usize) -> u64 {
            debug_assert!(width <= 64);
            let byte_offset = bit_offset >> 3;
            let bit_in_byte = (bit_offset & 7) as u32;

            // Copy up to 9 bytes locally to safely shift
            let mut buf = [0u8; 9];
            let need = ((width + bit_in_byte as usize + 7) >> 3).min(9);
            let available = src.len().saturating_sub(byte_offset);
            let to_copy = need.min(available);
            if to_copy > 0 {
                buf[..to_copy].copy_from_slice(&src[byte_offset..byte_offset + to_copy]);
            }

            // Assemble little-endian into a scalar, then shift
            let mut acc = 0u128;
            for i in (0..need).rev() {
                acc <<= 8;
                acc |= buf[i] as u128;
            }
            let acc = acc >> bit_in_byte;
            let mask = if width == 64 {
                u64::MAX
            } else {
                (1u64 << width) - 1
            };
            (acc as u64) & mask
        }

        fn ref_unpack_24_to_u32(src: &[u8], n: usize, out: &mut [u32]) {
            for i in 0..n {
                out[i] = ref_extract_bits_le(src, i * 24, 24) as u32;
            }
        }

        fn pack_stream_24_504(vals: &[u32; 504]) -> [u8; 1512] {
            let mut buf = [0u8; 1512];
            for (i, &v) in vals.iter().enumerate() {
                pack_bits_le(&mut buf, i * 24, 24, (v & 0x00FF_FFFF) as u64);
            }
            buf
        }

        fn make_block_v5b(a: &[u32; 504], b: &[u32; 504], c: &[u32; 504]) -> BlockV5b {
            BlockV5b {
                in1_stream: pack_stream_24_504(a),
                in2_stream: pack_stream_24_504(b),
                out_stream: pack_stream_24_504(c),
            }
        }

        #[cfg(target_arch = "x86_64")]
        fn avx512_available() -> bool {
            is_x86_feature_detected!("avx512f")
        }
        #[cfg(not(target_arch = "x86_64"))]
        fn avx512_available() -> bool {
            false
        }

        // ---------- Tests ----------

        #[test]
        fn v5b_decode_zeroes_and_max() {
            if !avx512_available() {
                eprintln!("Skipping v5b: AVX-512F not available");
                return;
            }
            unsafe {
                // Zeroes
                let zeros = [0u32; 504];
                let blk = make_block_v5b(&zeros, &zeros, &zeros);

                let mut a = [0u32; 504];
                let mut b = [0u32; 504];
                let mut c = [0u32; 504];
                decode_block_v5b_avx512(&blk, 504, &mut a, &mut b, &mut c);
                assert!(a.iter().all(|&x| x == 0));
                assert!(b.iter().all(|&x| x == 0));
                assert!(c.iter().all(|&x| x == 0));

                // Max values (24-bit)
                let maxs = [0x00FF_FFFFu32; 504];
                let blk = make_block_v5b(&maxs, &maxs, &maxs);
                let mut a = [0u32; 504];
                let mut b = [0u32; 504];
                let mut c = [0u32; 504];
                decode_block_v5b_avx512(&blk, 504, &mut a, &mut b, &mut c);
                assert!(a.iter().all(|&x| x == 0x00FF_FFFF));
                assert!(b.iter().all(|&x| x == 0x00FF_FFFF));
                assert!(c.iter().all(|&x| x == 0x00FF_FFFF));
            }
        }

        #[test]
        fn v5b_decode_various_n_tails() {
            if !avx512_available() {
                eprintln!("Skipping v5b: AVX-512F not available");
                return;
            }
            unsafe {
                let ns = [
                    0usize, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257,
                    503, 504,
                ];

                let mut a = [0u32; 504];
                let mut b = [0u32; 504];
                let mut c = [0u32; 504];
                for i in 0..504 {
                    a[i] = ((i as u32) * 65537) & 0x00FF_FFFF;
                    b[i] = (((i as u32) * 3) ^ 0x0055_AA55) & 0x00FF_FFFF;
                    c[i] = (0x00ABCDEFu32.wrapping_mul(i as u32)) & 0x00FF_FFFF;
                }
                let blk = make_block_v5b(&a, &b, &c);

                for &n in &ns {
                    let mut a = [0u32; 504];
                    let mut b = [0u32; 504];
                    let mut c = [0u32; 504];
                    decode_block_v5b_avx512(&blk, n, &mut a, &mut b, &mut c);

                    let mut ra = [0u32; 504];
                    let mut rb = [0u32; 504];
                    let mut rc = [0u32; 504];
                    ref_unpack_24_to_u32(&blk.in1_stream, n, &mut ra);
                    ref_unpack_24_to_u32(&blk.in2_stream, n, &mut rb);
                    ref_unpack_24_to_u32(&blk.out_stream, n, &mut rc);

                    assert_eq!(&a[..n], &ra[..n], "in1 mismatch at n={}", n);
                    assert_eq!(&b[..n], &rb[..n], "in2 mismatch at n={}", n);
                    assert_eq!(&c[..n], &rc[..n], "out mismatch at n={}", n);
                }
            }
        }

        #[test]
        fn v5b_decode_boundary_last_field_crosses_end() {
            if !avx512_available() {
                eprintln!("Skipping v5b: AVX-512F not available");
                return;
            }
            unsafe {
                let mut a = [0u32; 504];
                let mut b = [0u32; 504];
                let mut c = [0u32; 504];
                a.fill(0);
                b.fill(0);
                c.fill(0);

                // Distinctive last values
                a[503] = 0x000123u32;
                b[503] = 0x00ABCDu32;
                c[503] = 0x00FEEDu32;

                let blk = make_block_v5b(&a, &b, &c);

                let mut a = [0u32; 504];
                let mut b = [0u32; 504];
                let mut c = [0u32; 504];
                decode_block_v5b_avx512(&blk, 504, &mut a, &mut b, &mut c);

                let mut ra = [0u32; 504];
                let mut rb = [0u32; 504];
                let mut rc = [0u32; 504];
                ref_unpack_24_to_u32(&blk.in1_stream, 504, &mut ra);
                ref_unpack_24_to_u32(&blk.in2_stream, 504, &mut rb);
                ref_unpack_24_to_u32(&blk.out_stream, 504, &mut rc);

                assert_eq!(a, ra);
                assert_eq!(b, rb);
                assert_eq!(c, rc);
                assert_eq!(a[503], 0x000123);
                assert_eq!(b[503], 0x00ABCD);
                assert_eq!(c[503], 0x00FEED);
            }
        }

        #[test]
        fn v5b_decode_randomized_compare_scalar() {
            if !avx512_available() {
                eprintln!("Skipping v5b: AVX-512F not available");
                return;
            }
            unsafe {
                let mut rng = Rng::new(0xF00D_CAFE_DEAD_BEEF);
                for iter in 0..200 {
                    let n = (rng.next_u32() as usize % 505).min(504);

                    let mut a = [0u32; 504];
                    let mut b = [0u32; 504];
                    let mut c = [0u32; 504];
                    for i in 0..504 {
                        a[i] = rng.next_u32() & 0x00FF_FFFF;
                        b[i] = rng.next_u32() & 0x00FF_FFFF;
                        c[i] = rng.next_u32() & 0x00FF_FFFF;
                    }

                    let blk = make_block_v5b(&a, &b, &c);

                    let mut a = [0u32; 504];
                    let mut b = [0u32; 504];
                    let mut c = [0u32; 504];
                    decode_block_v5b_avx512(&blk, n, &mut a, &mut b, &mut c);

                    let mut ra = [0u32; 504];
                    let mut rb = [0u32; 504];
                    let mut rc = [0u32; 504];
                    ref_unpack_24_to_u32(&blk.in1_stream, n, &mut ra);
                    ref_unpack_24_to_u32(&blk.in2_stream, n, &mut rb);
                    ref_unpack_24_to_u32(&blk.out_stream, n, &mut rc);

                    assert_eq!(&a[..n], &ra[..n], "iter {}: in1 mismatch", iter);
                    assert_eq!(&b[..n], &rb[..n], "iter {}: in2 mismatch", iter);
                    assert_eq!(&c[..n], &rc[..n], "iter {}: out mismatch", iter);
                }
            }
        }
    }
}

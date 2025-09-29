use crate::v5::a::{
    BLOCK_SIZE_BYTES, CREDITS_OFFSET, CREDITS_SIZE, GATES_PER_BLOCK, IN_STREAM_SIZE, IN1_OFFSET,
    IN2_OFFSET, OUT_OFFSET, TYPES_OFFSET,
};

#[inline]
pub fn decode_block_v5a_scalar(
    block_bytes: &[u8],
    n: usize,
    in1_out: &mut [u64; GATES_PER_BLOCK],
    in2_out: &mut [u64; GATES_PER_BLOCK],
    out_out: &mut [u64; GATES_PER_BLOCK],
    credits_out: &mut [u32; GATES_PER_BLOCK],
    gate_types_out_bool: &mut [bool; GATES_PER_BLOCK],
) {
    debug_assert!(block_bytes.len() == BLOCK_SIZE_BYTES);
    let in1 = &block_bytes[IN1_OFFSET..IN1_OFFSET + IN_STREAM_SIZE];
    let in2 = &block_bytes[IN2_OFFSET..IN2_OFFSET + IN_STREAM_SIZE];
    let out = &block_bytes[OUT_OFFSET..OUT_OFFSET + IN_STREAM_SIZE];
    let credits = &block_bytes[CREDITS_OFFSET..CREDITS_OFFSET + CREDITS_SIZE];
    let types = &block_bytes[TYPES_OFFSET..TYPES_OFFSET + 32];

    unpack_bits_34_into_u64(in1, n, in1_out);
    unpack_bits_34_into_u64(in2, n, in2_out);
    unpack_bits_34_into_u64(out, n, out_out);
    unpack_bits_24_into_u32(credits, n, credits_out);

    // gate types (bit-per-gate): false=XOR, true=AND
    for i in 0..n {
        let b = types[i >> 3];
        gate_types_out_bool[i] = ((b >> (i & 7)) & 1) != 0;
    }
}

#[inline]
pub fn unpack_bits_24_into_u32(src: &[u8], n: usize, dst: &mut [u32; GATES_PER_BLOCK]) {
    for i in 0..n {
        let bit = i * 24;
        let byte = bit >> 3;
        let shift = bit & 7;
        let mut buf = [0u8; 4];
        let end = (byte + 4).min(src.len());
        let len = end - byte;
        buf[..len].copy_from_slice(&src[byte..end]);
        let v = u32::from_le_bytes(buf) >> shift;
        dst[i] = v & 0x00FF_FFFF;
    }
}

#[inline]
pub fn unpack_bits_34_into_u64(src: &[u8], n: usize, dst: &mut [u64; GATES_PER_BLOCK]) {
    for i in 0..n {
        let bit = i * 34;
        let byte = bit >> 3;
        let shift = bit & 7;
        let mut buf = [0u8; 8];
        let end = (byte + 8).min(src.len());
        let len = end - byte;
        buf[..len].copy_from_slice(&src[byte..end]);
        let v = u64::from_le_bytes(buf) >> shift;
        dst[i] = v & 0x3_FFFF_FFFF;
    }
}

//! CKT Format v5 - Fixed-width encoding with Structure-of-Arrays layout
//!
//! This module implements the v5 format specification with three variants:
//! - v5a: Intermediate format with 34-bit wire IDs and 24-bit credits
//! - v5b: Production format with 32-bit memory addresses and level organization
//! - v5c: Flat production format with 32-bit memory addresses (execution order)
//!
//! All formats use fixed-width encoding for optimal performance with
//! AVX-512 SIMD processing and io_uring I/O.

pub mod a;
pub mod b;
pub mod c;
pub mod scalar;

// Decoder module is private - callers use dispatch functions
#[cfg(target_arch = "x86_64")]
mod avx512;

/// Magic bytes for v5 format: "Zk2u" in ASCII
pub const MAGIC: [u8; 4] = [0x5A, 0x6B, 0x32, 0x75];

/// Version number for v5 format
pub const VERSION: u8 = 0x05;

/// Format type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FormatType {
    /// Type A: Intermediate format with wire IDs and credits
    TypeA = 0x00,
    /// Type B: Production format with memory addresses and levels
    TypeB = 0x01,
    /// Type C: Flat production format with memory addresses (execution order)
    TypeC = 0x02,
}

impl FormatType {
    /// Create from byte value
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(FormatType::TypeA),
            0x01 => Some(FormatType::TypeB),
            0x02 => Some(FormatType::TypeC),
            _ => None,
        }
    }

    /// Convert to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Statistics about a written circuit
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub num_outputs: u64,
    pub bytes_written: u64,
    pub checksum: [u8; 32],
}

impl CircuitStats {
    /// Calculate the average gates per block
    pub fn avg_gates_per_block(&self) -> f64 {
        let blocks = (self.total_gates as f64 / 256.0).ceil();
        if blocks > 0.0 {
            self.total_gates as f64 / blocks
        } else {
            0.0
        }
    }

    /// Calculate the file size in bytes
    pub fn file_size(&self) -> u64 {
        self.bytes_written
    }

    /// Get the compression ratio compared to a naive encoding
    pub fn compression_ratio(&self) -> f64 {
        // Naive encoding: 3 × 8 bytes per wire ID + 4 bytes credits = 28 bytes/gate
        let naive_size = self.total_gates * 28;
        if naive_size > 0 {
            self.bytes_written as f64 / naive_size as f64
        } else {
            0.0
        }
    }
}

/// Dispatch to AVX-512 or scalar implementation for v5a block decoding
///
/// This function automatically selects the best available implementation:
/// - On x86_64 with AVX-512F support: uses SIMD acceleration
/// - Otherwise: uses portable scalar code
///
/// The caller doesn't need to know which path is taken or manage any scratch space.
#[inline]
pub fn decode_block_v5a(
    block_bytes: &[u8],
    num_gates: usize,
    in1_out: &mut [u64],
    in2_out: &mut [u64],
    out_out: &mut [u64],
    credits_out: &mut [u32],
    gate_types_out: &mut [bool],
) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            use a::{
                CREDITS_OFFSET, CREDITS_SIZE, IN_STREAM_SIZE, IN1_OFFSET,
                IN2_OFFSET, OUT_OFFSET, TYPES_OFFSET,
            };

            // Create AVX block on-stack (only when AVX path is taken)
            let mut avx_block = avx512::BlockV5a::new();

            avx_block
                .in1_packed
                .copy_from_slice(&block_bytes[IN1_OFFSET..IN1_OFFSET + IN_STREAM_SIZE]);
            avx_block
                .in2_packed
                .copy_from_slice(&block_bytes[IN2_OFFSET..IN2_OFFSET + IN_STREAM_SIZE]);
            avx_block
                .out_packed
                .copy_from_slice(&block_bytes[OUT_OFFSET..OUT_OFFSET + IN_STREAM_SIZE]);
            avx_block
                .credits_packed
                .copy_from_slice(&block_bytes[CREDITS_OFFSET..CREDITS_OFFSET + CREDITS_SIZE]);
            avx_block
                .gate_types
                .copy_from_slice(&block_bytes[TYPES_OFFSET..TYPES_OFFSET + 32]);

            unsafe {
                avx512::decode_block_v5a_avx512(
                    &avx_block,
                    num_gates,
                    in1_out,
                    in2_out,
                    out_out,
                    credits_out,
                    gate_types_out,
                );
            }
            return;
        }
    }

    // Fallback to scalar on all platforms
    use a::GATES_PER_BLOCK;

    // Convert slices to fixed-size array references for scalar decoder
    debug_assert!(in1_out.len() >= GATES_PER_BLOCK);
    debug_assert!(in2_out.len() >= GATES_PER_BLOCK);
    debug_assert!(out_out.len() >= GATES_PER_BLOCK);
    debug_assert!(credits_out.len() >= GATES_PER_BLOCK);
    debug_assert!(gate_types_out.len() >= GATES_PER_BLOCK);

    // Safety: We've asserted the slices are at least GATES_PER_BLOCK elements
    let in1_arr = unsafe { &mut *(in1_out.as_mut_ptr() as *mut [u64; GATES_PER_BLOCK]) };
    let in2_arr = unsafe { &mut *(in2_out.as_mut_ptr() as *mut [u64; GATES_PER_BLOCK]) };
    let out_arr = unsafe { &mut *(out_out.as_mut_ptr() as *mut [u64; GATES_PER_BLOCK]) };
    let credits_arr = unsafe { &mut *(credits_out.as_mut_ptr() as *mut [u32; GATES_PER_BLOCK]) };
    let gate_types_arr =
        unsafe { &mut *(gate_types_out.as_mut_ptr() as *mut [bool; GATES_PER_BLOCK]) };

    scalar::decode_block_v5a_scalar(
        block_bytes,
        num_gates,
        in1_arr,
        in2_arr,
        out_arr,
        credits_arr,
        gate_types_arr,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_type() {
        assert_eq!(FormatType::TypeA.to_byte(), 0x00);
        assert_eq!(FormatType::TypeB.to_byte(), 0x01);
        assert_eq!(FormatType::TypeC.to_byte(), 0x02);

        assert_eq!(FormatType::from_byte(0x00), Some(FormatType::TypeA));
        assert_eq!(FormatType::from_byte(0x01), Some(FormatType::TypeB));
        assert_eq!(FormatType::from_byte(0x02), Some(FormatType::TypeC));
        assert_eq!(FormatType::from_byte(0xFF), None);
    }

    #[test]
    fn test_magic_bytes() {
        assert_eq!(MAGIC, [0x5A, 0x6B, 0x32, 0x75]);
        // Verify it spells "Zk2u"
        assert_eq!(MAGIC[0] as char, 'Z');
        assert_eq!(MAGIC[1] as char, 'k');
        assert_eq!(MAGIC[2] as char, '2');
        assert_eq!(MAGIC[3] as char, 'u');
    }

    #[test]
    fn test_circuit_stats() {
        let stats = CircuitStats {
            total_gates: 1000,
            xor_gates: 600,
            and_gates: 400,
            primary_inputs: 100,
            num_outputs: 10,
            bytes_written: 15875, // 1000 gates × 15.875 bytes/gate
            checksum: [0; 32],
        };

        // Test average gates per block (256 gates per block)
        let blocks = (1000.0_f64 / 256.0_f64).ceil(); // 4 blocks
        assert_eq!(stats.avg_gates_per_block(), 1000.0 / blocks);

        // Test compression ratio
        let naive_size = 1000 * 28; // 28 bytes per gate naive encoding
        let expected_ratio = 15875.0 / naive_size as f64;
        assert!((stats.compression_ratio() - expected_ratio).abs() < 0.001);
    }
}

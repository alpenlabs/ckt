//! CKT Format v5 - Fixed-width encoding with Structure-of-Arrays layout
//!
//! This module implements the v5 format specification with two variants:
//! - v5a: Intermediate format with 34-bit wire IDs and 24-bit credits
//! - v5b: Production format with 24-bit memory addresses
//!
//! Both formats use fixed-width encoding and SoA layout for optimal performance
//! with AVX-512 SIMD processing and io_uring I/O.

pub mod a;
mod avx512;
pub mod b;
mod scalar;

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
    /// Type B: Production format with memory addresses
    TypeB = 0x01,
}

impl FormatType {
    /// Create from byte value
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(FormatType::TypeA),
            0x01 => Some(FormatType::TypeB),
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

/// Check if CPU supports required AVX-512 features
#[cfg(target_arch = "x86_64")]
pub fn check_avx512_support() -> bool {
    if !is_x86_feature_detected!("avx512f") {
        return false;
    }
    if !is_x86_feature_detected!("avx512bw") {
        return false;
    }
    if !is_x86_feature_detected!("avx512vbmi") {
        return false;
    }

    true
}

#[cfg(not(target_arch = "x86_64"))]
pub fn check_avx512_support() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_type() {
        assert_eq!(FormatType::TypeA.to_byte(), 0x00);
        assert_eq!(FormatType::TypeB.to_byte(), 0x01);

        assert_eq!(FormatType::from_byte(0x00), Some(FormatType::TypeA));
        assert_eq!(FormatType::from_byte(0x01), Some(FormatType::TypeB));
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

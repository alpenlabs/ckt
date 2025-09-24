//! CKT Format v5a - Intermediate format with fixed-width encoding
//!
//! This module implements the v5a format specification with:
//! - 34-bit wire IDs for handling large circuits (up to 17B wires)
//! - 24-bit credits for memory management
//! - Structure-of-Arrays layout for optimal SIMD processing
//! - 256 gates per block

use crate::GateType;

// pub mod reader;
pub mod writer;

// #[cfg(test)]
// mod integration_tests;

// Re-export main types
// pub use reader::{CircuitReaderV5a, DecodedBlock, GateV5a, HeaderV5a};
// pub use writer::{CircuitStats, CircuitWriterV5a, verify_checksum};

/// Block size constants for v5a
pub const GATES_PER_BLOCK: usize = 256;
pub const BLOCK_SIZE_BYTES: usize = 4064;

/// Maximum values for v5a format
pub const MAX_WIRE_ID: u64 = (1 << 34) - 1; // 17,179,869,183
pub const MAX_CREDITS: u32 = (1 << 24) - 1; // 16,777,215

/// Special credit values
pub const CREDITS_OUTPUT: u32 = 0; // Wire is a circuit output
pub const CREDITS_CONSTANT: u32 = MAX_CREDITS; // Wire is constant/primary input

// v5a header constants (fixed by spec)
pub const HEADER_SIZE_V5A: usize = 72;
pub const MAGIC: [u8; 4] = *b"Zk2u";
pub const VERSION: u8 = 0x05;
pub const FORMAT_TYPE_A: u8 = 0x00;

// SoA block segment sizes (fixed by spec)
pub const IN1_OFFSET: usize = 0;
pub const IN2_OFFSET: usize = 1088;
pub const OUT_OFFSET: usize = 2176;
pub const CREDITS_OFFSET: usize = 3264;
pub const TYPES_OFFSET: usize = 4032;
pub const IN_STREAM_SIZE: usize = 1088; // 256 * 34 bits = 1088 bytes
pub const CREDITS_SIZE: usize = 768; // 256 * 24 bits = 768 bytes

/// Gate record for v5a writer
#[derive(Debug, Clone, Copy)]
pub struct GateV5a {
    pub in1: u64,            // 34-bit
    pub in2: u64,            // 34-bit
    pub out: u64,            // 34-bit
    pub credits: u32,        // 24-bit
    pub gate_type: GateType, // false = XOR, true = AND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_WIRE_ID, 0x3FFFFFFFF);
        assert_eq!(MAX_CREDITS, 0xFFFFFF);
        assert_eq!(BLOCK_SIZE_BYTES, 4064);
        assert_eq!(GATES_PER_BLOCK, 256);
    }

    #[test]
    fn test_block_size_calculation() {
        // Verify the block size calculation matches spec
        let in1_size = (256 * 34) / 8; // 1088 bytes
        let in2_size = (256 * 34) / 8; // 1088 bytes
        let out_size = (256 * 34) / 8; // 1088 bytes
        let credits_size = (256 * 24) / 8; // 768 bytes
        let types_size = 256 / 8; // 32 bytes

        let total = in1_size + in2_size + out_size + credits_size + types_size;
        assert_eq!(total, BLOCK_SIZE_BYTES);
    }
}

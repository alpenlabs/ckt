//! CKT Format v5a - Intermediate format with fixed-width encoding
//!
//! This module implements the v5a format specification with:
//! - 34-bit wire IDs for handling large circuits (up to 17B wires)
//! - 24-bit credits for memory management
//! - Structure-of-Arrays layout for optimal SIMD processing
//! - 256 gates per block

use std::io::{self, Error, ErrorKind};

use crate::GateType;
#[cfg(test)]
mod integration;
pub mod reader;
pub mod writer;

/// Block size constants for v5a
pub const GATES_PER_BLOCK: usize = 256;
pub const BLOCK_SIZE_BYTES: usize = TYPES_OFFSET + 32; // 4064

// Per-gate bit widths for v5a
const BITS_WIRE: usize = 34;
const BITS_CREDITS: usize = 24;

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
pub const IN2_OFFSET: usize = IN1_OFFSET + IN_STREAM_SIZE; // 1088
pub const OUT_OFFSET: usize = IN2_OFFSET + IN_STREAM_SIZE; // 2176
pub const CREDITS_OFFSET: usize = OUT_OFFSET + IN_STREAM_SIZE; // 3264
pub const TYPES_OFFSET: usize = CREDITS_OFFSET + CREDITS_SIZE; // 4032
pub const IN_STREAM_SIZE: usize = (GATES_PER_BLOCK * BITS_WIRE + 7) / 8; // 1088
pub const CREDITS_SIZE: usize = (GATES_PER_BLOCK * BITS_CREDITS + 7) / 8; // 768

/// Gate record for v5a writer
#[derive(Debug, Clone, Copy)]
pub struct GateV5a {
    pub in1: u64,            // 34-bit
    pub in2: u64,            // 34-bit
    pub out: u64,            // 34-bit
    pub credits: u32,        // 24-bit
    pub gate_type: GateType, // false = XOR, true = AND
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderV5a {
    pub magic: [u8; 4],      // "Zk2u"
    pub version: u8,         // 0x05
    pub format_type: u8,     // 0x00 for v5a
    pub reserved: [u8; 2],   // 0x0000
    pub checksum: [u8; 32],  // blake3
    pub xor_gates: u64,      // LE
    pub and_gates: u64,      // LE
    pub primary_inputs: u64, // LE
    pub num_outputs: u64,    // LE
}

impl HeaderV5a {
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }
}

fn parse_header(bytes: &[u8; HEADER_SIZE_V5A]) -> io::Result<HeaderV5a> {
    if &bytes[0..4] != &MAGIC {
        return Err(Error::new(ErrorKind::InvalidData, "bad magic"));
    }
    if bytes[4] != VERSION {
        return Err(Error::new(ErrorKind::InvalidData, "bad version"));
    }
    if bytes[5] != FORMAT_TYPE_A {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "bad format_type (expected 0x00 for v5a)",
        ));
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "reserved bytes not zero",
        ));
    }

    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&bytes[8..40]);

    let xor_gates = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let and_gates = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    let primary_inputs = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
    let num_outputs = u64::from_le_bytes(bytes[64..72].try_into().unwrap());

    Ok(HeaderV5a {
        magic: MAGIC,
        version: bytes[4],
        format_type: bytes[5],
        reserved: [0, 0],
        checksum,
        xor_gates,
        and_gates,
        primary_inputs,
        num_outputs,
    })
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

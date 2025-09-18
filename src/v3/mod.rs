//! CKT Format v3 - Enhanced format with two variants
//!
//! - v3a: Fixed-size 34-bit wire IDs with batching
//! - v3b: Level-based organization with implicit outputs

pub mod a;
pub mod b;

/// CKT v3 format version identifier
pub const VERSION: u8 = 3;

/// Format type identifier for v3 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FormatType {
    /// Type A: Fixed 34-bit wire IDs with batching (evolved from v1)
    TypeA = 0,
    /// Type B: Level-based with implicit outputs (evolved from v2)
    TypeB = 1,
}

impl FormatType {
    /// Create from byte value
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(FormatType::TypeA),
            1 => Some(FormatType::TypeB),
            _ => None,
        }
    }

    /// Convert to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Statistics about a written circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub total_levels: u32,
    pub bytes_written: u64,
}

impl CircuitStats {
    /// Calculate compression ratio
    pub fn compression_ratio(&self, original_size: u64) -> f64 {
        if original_size == 0 {
            0.0
        } else {
            self.bytes_written as f64 / original_size as f64
        }
    }
}

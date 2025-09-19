//! CKT Format v4 - Production format with memory management
//!
//! - v4a: Intermediate format with credits for wire garbage collection
//! - v4b: Production format with precomputed memory addresses

pub mod a;
pub mod b;

/// CKT v4 format version identifier
pub const VERSION: u8 = 4;

/// Format type identifier for v4 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FormatType {
    /// Type A: Batched format with credits for wire GC
    TypeA = 0,
    /// Type B: Level-based with precomputed memory addresses
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
    pub num_outputs: u64,
    pub total_levels: u32,
    pub bytes_written: u64,
    pub checksum: [u8; 32],
    /// Maximum scratch space size needed for v4b execution
    pub max_scratch_space: u64,
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

    /// Get average gates per level
    pub fn avg_gates_per_level(&self) -> f64 {
        if self.total_levels == 0 {
            0.0
        } else {
            self.total_gates as f64 / self.total_levels as f64
        }
    }

    /// Get memory efficiency ratio for v4b
    pub fn memory_efficiency(&self) -> f64 {
        if self.total_gates == 0 {
            0.0
        } else {
            // Ratio of max memory to total wires (lower is better)
            self.max_scratch_space as f64 / (self.primary_inputs + self.total_gates) as f64
        }
    }
}

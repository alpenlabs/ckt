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

/// Gate type enumeration shared across v3 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

/// Compact wire location for level-based encoding (v3b)
/// 7 bytes total: 4 bytes level + 3 bytes index within level
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactWireLocation {
    /// Level ID (0 = primary inputs, 1+ = computed levels)
    pub level: u32,
    /// Index within the level (supports up to 16M gates per level)
    pub index: u32,
}

impl CompactWireLocation {
    /// Create a new wire location
    pub fn new(level: u32, index: u32) -> Self {
        debug_assert!(index < (1 << 24), "Index exceeds 24 bits");
        Self { level, index }
    }

    /// Encode to 7 bytes
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut bytes = [0u8; 7];
        // Store level in first 4 bytes (little-endian)
        bytes[0..4].copy_from_slice(&self.level.to_le_bytes());
        // Store index in last 3 bytes (24 bits)
        bytes[4] = (self.index & 0xFF) as u8;
        bytes[5] = ((self.index >> 8) & 0xFF) as u8;
        bytes[6] = ((self.index >> 16) & 0xFF) as u8;
        bytes
    }

    /// Decode from 7 bytes
    pub fn from_bytes(bytes: &[u8; 7]) -> Self {
        let level = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let index = bytes[4] as u32 | ((bytes[5] as u32) << 8) | ((bytes[6] as u32) << 16);
        Self { level, index }
    }
}

/// Level structure for v3b format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    /// Level identifier
    pub id: u32,
    /// XOR gates in this level
    pub xor_gates: Vec<Gate>,
    /// AND gates in this level
    pub and_gates: Vec<Gate>,
}

impl Level {
    /// Create a new empty level
    pub fn new(id: u32) -> Self {
        Self {
            id,
            xor_gates: Vec::new(),
            and_gates: Vec::new(),
        }
    }

    /// Create a level with capacity
    pub fn with_capacity(id: u32, xor_capacity: usize, and_capacity: usize) -> Self {
        Self {
            id,
            xor_gates: Vec::with_capacity(xor_capacity),
            and_gates: Vec::with_capacity(and_capacity),
        }
    }

    /// Get total number of gates in the level
    pub fn total_gates(&self) -> usize {
        self.xor_gates.len() + self.and_gates.len()
    }

    /// Check if level is empty
    pub fn is_empty(&self) -> bool {
        self.xor_gates.is_empty() && self.and_gates.is_empty()
    }
}

/// Gate structure for v3b (with implicit output)
/// Output wire ID is implicitly the current wire counter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// First input wire location
    pub input1: CompactWireLocation,
    /// Second input wire location
    pub input2: CompactWireLocation,
}

impl Gate {
    /// Create a new gate
    pub fn new(input1: CompactWireLocation, input2: CompactWireLocation) -> Self {
        Self { input1, input2 }
    }
}

/// Circuit header for v3a format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitHeaderV3A {
    pub version: u8,        // Always 3
    pub format_type: u8,    // Always 0 (TypeA)
    pub checksum: [u8; 32], // BLAKE3 hash of all data after checksum
    pub xor_gates: u64,     // Total XOR gates
    pub and_gates: u64,     // Total AND gates
}

impl CircuitHeaderV3A {
    /// Header size in bytes: 1 + 1 + 32 + 8 + 8 = 50 bytes
    pub const SIZE: usize = 50;

    /// Create a new v3a header (checksum will be computed during write)
    pub fn new(xor_gates: u64, and_gates: u64) -> Self {
        Self {
            version: VERSION,
            format_type: FormatType::TypeA.to_byte(),
            checksum: [0; 32], // Placeholder, will be filled when writing
            xor_gates,
            and_gates,
        }
    }

    /// Get total gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }
}

/// Circuit header for v3b format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitHeaderV3B {
    pub version: u8,         // Always 3
    pub format_type: u8,     // Always 1 (TypeB)
    pub checksum: [u8; 32],  // BLAKE3 hash of all data after checksum
    pub xor_gates: u64,      // Total XOR gates
    pub and_gates: u64,      // Total AND gates
    pub primary_inputs: u64, // Number of primary inputs
}

impl CircuitHeaderV3B {
    /// Header size in bytes: 1 + 1 + 32 + 8 + 8 + 8 = 58 bytes
    pub const SIZE: usize = 58;

    /// Create a new v3b header with known counts (checksum will be computed during write)
    pub fn with_counts(xor_gates: u64, and_gates: u64, primary_inputs: u64) -> Self {
        Self {
            version: VERSION,
            format_type: FormatType::TypeB.to_byte(),
            checksum: [0; 32], // Placeholder, will be filled when writing
            xor_gates,
            and_gates,
            primary_inputs,
        }
    }

    /// Create a header with primary inputs (gate counts will be updated later)
    pub fn new(primary_inputs: u64) -> Self {
        Self {
            version: VERSION,
            format_type: FormatType::TypeB.to_byte(),
            checksum: [0; 32], // Placeholder, will be filled when writing
            xor_gates: 0,
            and_gates: 0,
            primary_inputs,
        }
    }

    /// Get total gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
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

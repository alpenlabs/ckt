//! CKT Format v3b - Production format for high-performance circuit evaluation
//!
//! This module implements the v3b format with:
//! - Implicit output wire IDs (saves ~33% wire storage)
//! - Level-based topological organization
//! - Optimized wire encoding for previous-level references
//! - BLAKE3 checksums for data integrity
//! - Structure-of-Arrays support for vectorization

pub mod reader;
pub mod varints;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

/// Wire location within a level-organized circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireLocation {
    /// Level that produced this wire (0 = primary inputs)
    pub level: u32,
    /// Index within that level
    pub index: u32,
}

impl WireLocation {
    /// Create a new wire location
    pub fn new(level: u32, index: u32) -> Self {
        Self { level, index }
    }

    /// Check if this is a primary input (level 0)
    pub fn is_primary_input(&self) -> bool {
        self.level == 0
    }
}

/// Compact wire location for memory efficiency
/// Compatible with lvl crate's CompactWireLocation
#[derive(Clone, Copy)]
#[repr(packed)]
pub struct CompactWireLocation {
    bytes: [u8; 7],
}

impl CompactWireLocation {
    /// Create a new compact wire location
    pub fn new(level: u32, index: u32) -> Self {
        debug_assert!(index < (1 << 24), "Index exceeds 24 bits");
        let mut bytes = [0u8; 7];
        // Store level in first 4 bytes (little-endian)
        bytes[0..4].copy_from_slice(&level.to_le_bytes());
        // Store index in last 3 bytes (24 bits)
        bytes[4] = (index & 0xFF) as u8;
        bytes[5] = ((index >> 8) & 0xFF) as u8;
        bytes[6] = ((index >> 16) & 0xFF) as u8;
        Self { bytes }
    }

    /// Convert to WireLocation
    pub fn to_wire_location(&self) -> WireLocation {
        let level =
            u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        let index =
            self.bytes[4] as u32 | ((self.bytes[5] as u32) << 8) | ((self.bytes[6] as u32) << 16);
        WireLocation { level, index }
    }

    /// Create from WireLocation
    pub fn from_wire_location(loc: WireLocation) -> Self {
        Self::new(loc.level, loc.index)
    }
}

/// A gate with implicit output wire ID
/// The output is always the current wire counter when the gate is processed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub input1: WireLocation,
    pub input2: WireLocation,
}

impl Gate {
    /// Create a new gate
    pub fn new(input1: WireLocation, input2: WireLocation) -> Self {
        Self { input1, input2 }
    }
}

/// A level containing XOR and AND gates that can be processed in parallel
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

    /// Add an XOR gate to the level
    pub fn add_xor_gate(&mut self, gate: Gate) {
        self.xor_gates.push(gate);
    }

    /// Add an AND gate to the level
    pub fn add_and_gate(&mut self, gate: Gate) {
        self.and_gates.push(gate);
    }
}

impl Default for Level {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Structure of Arrays representation for XOR gates - optimized for vectorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorGates<const N: usize> {
    /// First input wire locations
    pub input1s: Vec<WireLocation>,
    /// Second input wire locations
    pub input2s: Vec<WireLocation>,
    /// Number of valid gates
    pub count: usize,
}

impl<const N: usize> XorGates<N> {
    pub fn new() -> Self {
        Self {
            input1s: Vec::with_capacity(N),
            input2s: Vec::with_capacity(N),
            count: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            input1s: Vec::with_capacity(capacity),
            input2s: Vec::with_capacity(capacity),
            count: 0,
        }
    }
}

impl<const N: usize> Default for XorGates<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Structure of Arrays representation for AND gates - optimized for vectorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndGates<const N: usize> {
    /// First input wire locations
    pub input1s: Vec<WireLocation>,
    /// Second input wire locations
    pub input2s: Vec<WireLocation>,
    /// Number of valid gates
    pub count: usize,
}

impl<const N: usize> AndGates<N> {
    pub fn new() -> Self {
        Self {
            input1s: Vec::with_capacity(N),
            input2s: Vec::with_capacity(N),
            count: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            input1s: Vec::with_capacity(capacity),
            input2s: Vec::with_capacity(capacity),
            count: 0,
        }
    }
}

impl<const N: usize> Default for AndGates<N> {
    fn default() -> Self {
        Self::new()
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

    /// Get average gates per level
    pub fn avg_gates_per_level(&self) -> f64 {
        if self.total_levels == 0 {
            0.0
        } else {
            self.total_gates as f64 / self.total_levels as f64
        }
    }
}

/// Verify the BLAKE3 checksum of a v3b format file
///
/// This function reads the entire file and verifies that the stored checksum
/// matches the computed checksum of: hash(gate_data || header_fields_after_checksum)
pub fn verify_checksum<R: std::io::Read>(mut reader: R) -> std::io::Result<bool> {
    use blake3::Hasher;
    use std::io::{Error, ErrorKind};

    // Read header (58 bytes)
    let mut header_bytes = [0u8; crate::v3::CircuitHeaderV3B::SIZE];
    reader.read_exact(&mut header_bytes)?;

    // Validate version and type
    if header_bytes[0] != crate::v3::VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid version: {}", header_bytes[0]),
        ));
    }

    if header_bytes[1] != crate::v3::FormatType::TypeB.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid format type: {}", header_bytes[1]),
        ));
    }

    // Extract stored checksum
    let mut stored_checksum = [0u8; 32];
    stored_checksum.copy_from_slice(&header_bytes[2..34]);

    // Save header fields after checksum for hashing at the end
    let header_fields_after_checksum = &header_bytes[34..];

    // Hash all gate data first
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Then hash the header fields (after checksum)
    hasher.update(header_fields_after_checksum);

    // Compare checksums
    let computed_hash = hasher.finalize();
    Ok(computed_hash.as_bytes() == &stored_checksum)
}

/// Verify the checksum of a v3b file from a path
pub fn verify_checksum_file(path: &std::path::Path) -> std::io::Result<bool> {
    let file = std::fs::File::open(path)?;
    verify_checksum(std::io::BufReader::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_location() {
        let loc = WireLocation::new(5, 100);
        assert_eq!(loc.level, 5);
        assert_eq!(loc.index, 100);
        assert!(!loc.is_primary_input());

        let primary = WireLocation::new(0, 3);
        assert!(primary.is_primary_input());
    }

    #[test]
    fn test_compact_wire_location() {
        let original = WireLocation::new(12345, 67890);
        let compact = CompactWireLocation::from_wire_location(original);
        let restored = compact.to_wire_location();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_level() {
        let mut level = Level::new(1);
        assert!(level.is_empty());

        level.add_xor_gate(Gate::new(WireLocation::new(0, 0), WireLocation::new(0, 1)));

        level.add_and_gate(Gate::new(WireLocation::new(0, 2), WireLocation::new(0, 3)));

        assert_eq!(level.total_gates(), 2);
        assert!(!level.is_empty());
        assert_eq!(level.xor_gates.len(), 1);
        assert_eq!(level.and_gates.len(), 1);
    }

    #[test]
    fn test_level_capacity() {
        let level = Level::with_capacity(5, 100, 50);
        assert_eq!(level.id, 5);
        assert!(level.xor_gates.capacity() >= 100);
        assert!(level.and_gates.capacity() >= 50);
    }
}

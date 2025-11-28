//! Core types for the levelling algorithm.
//!
//! This module defines compact, memory-efficient representations for circuit elements:
//! - Wire IDs compressed to 34 bits (5 bytes)
//! - Gate dependencies packed into 12 bytes
//! - Efficient tracking of wire availability and pending dependencies

use ckt_fmtv5_types::GateType;
use indexmap::IndexSet;

use std::cmp::Ordering;

use ahash::HashSet;

/// A compact 34-bit wire identifier stored in 5 bytes.
///
/// Wire IDs are used throughout the levelling algorithm to identify circuit wires.
/// The 34-bit representation (2^34 = ~17 billion wires) is sufficient for large circuits
/// while saving memory compared to 64-bit IDs.
///
/// # Bit Layout
/// - Bytes 0-3: Lower 32 bits
/// - Byte 4 (bits 0-1): Upper 2 bits (total 34 bits)
/// - Byte 4 (bits 2-7): Unused (always zero)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactWireId([u8; 5]);

impl CompactWireId {
    /// Creates a CompactWireId from a u64, masking to 34 bits.
    ///
    /// Values exceeding 34 bits (> 0x3_FFFF_FFFF) are truncated.
    pub fn from_u64(value: u64) -> Self {
        // Mask to ensure we only use 34 bits (0x3_FFFF_FFFF)
        let masked_value = value & 0x3_FFFF_FFFF;

        let bytes = [
            (masked_value & 0xFF) as u8,
            ((masked_value >> 8) & 0xFF) as u8,
            ((masked_value >> 16) & 0xFF) as u8,
            ((masked_value >> 24) & 0xFF) as u8,
            ((masked_value >> 32) & 0x3) as u8, // Only 2 bits for the 5th byte
        ];

        Self(bytes)
    }

    /// Converts the CompactWireId back to a u64.
    ///
    /// The result is always in the range [0, 0x3_FFFF_FFFF] (34 bits).
    pub fn to_u64(&self) -> u64 {
        (self.0[0] as u64)
            | ((self.0[1] as u64) << 8)
            | ((self.0[2] as u64) << 16)
            | ((self.0[3] as u64) << 24)
            | (((self.0[4] as u64) & 0x3) << 32) // ensure only 2 bits contribute
    }

    /// Returns a reference to the raw 5-byte representation.
    ///
    /// # Layout
    /// - Bytes 0-3: Lower 32 bits of the wire ID
    /// - Byte 4: Upper 2 bits (bits 0-1), with bits 2-7 always zero
    ///
    /// # Invariant
    /// The 5th byte (index 4) is always in the range 0-3 (only lower 2 bits set).
    pub fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }
}

impl Ord for CompactWireId {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        use core::cmp::Ordering::*;
        for i in (0..5).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Equal => continue,
                non_eq => return non_eq,
            }
        }
        Equal
    }
}

impl PartialOrd for CompactWireId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for CompactWireId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WireId({})", self.to_u64())
    }
}

/// Represents a 2-input logic gate in the circuit.
///
/// # Hash and Equality
/// **Important**: Gates are considered equal if they have the same output wire,
/// regardless of their inputs. This is intentional, as the algorithm requires all
/// gates to have unique output wires. The hash and equality implementations
/// enable efficient deduplication in IndexSet/HashMap.
///
/// # Fields
/// - `in1`, `in2`: Input wire IDs
/// - `out`: Output wire ID (must be unique across all gates)
/// - `credits`: Reference count indicating how many future gates use this output
#[derive(Debug, Clone, Copy)]
pub struct IntermediateGate {
    pub in1: CompactWireId,
    pub in2: CompactWireId,
    pub out: CompactWireId,
    pub credits: Credits,
}

impl std::hash::Hash for IntermediateGate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.out.hash(state);
    }
}

impl PartialEq for IntermediateGate {
    fn eq(&self, other: &Self) -> bool {
        self.out == other.out
    }
}

impl Eq for IntermediateGate {}

/// A single level in the levelled circuit representation.
///
/// Each level contains gates that can be evaluated in parallel, as all their
/// inputs are available from previous levels or primary inputs.
///
/// Gates are separated by type (XOR vs AND) for potential optimization during
/// evaluation (e.g., different handling in MPC protocols).
pub struct Level {
    pub id: u32,
    pub xor_gates: IndexSet<IntermediateGate>,
    pub and_gates: IndexSet<IntermediateGate>,
}

/// Internal: Gates pending addition to the next level.
#[derive(Debug, Clone, Default)]
pub(crate) struct PendingLevel {
    pub xor_gates: IndexSet<IntermediateGate>,
    pub and_gates: IndexSet<IntermediateGate>,
}

/// Reference count for a wire indicating how many gates use it as input.
///
/// When a wire is used by a gate, its credits are decremented. When credits
/// reach 1 (meaning this is the last use), the wire is removed from the state
/// map to free memory.
#[derive(Debug, Clone, Copy, Hash)]
pub struct Credits(pub u32);

/// The state of a wire in the levelling algorithm.
///
/// # States
/// - `Available`: Wire has been produced and is ready for use, with a reference count
/// - `WaitingInline`: Wire is not yet available; one gate is waiting for it (optimized inline storage)
/// - `Waiting`: Wire is not yet available; multiple gates are waiting for it (heap-allocated set)
///
/// The inline optimization avoids heap allocation for the common case of a single dependency.
#[derive(Debug, Clone)]
pub enum WireAvailability {
    Available(Credits),
    Waiting(HashSet<CompactDependency>),
    WaitingInline(CompactDependency),
}

/// A gate dependency packed into 12 bytes.
///
/// When a gate is waiting for an input wire to become available, we store a compact
/// representation of that gate. This saves memory compared to storing the full
/// `IntermediateGate` structure.
///
/// # Bit Layout (96 bits total in 12 bytes)
/// - Bits 0-33: `other_in` wire ID (34 bits) - the wire that IS available
/// - Bits 34-67: `out` wire ID (34 bits) - the gate's output
/// - Bit 68: `gate_type` (1 bit: 0=XOR, 1=AND)
/// - Bits 69-71: Padding (unused)
/// - Bits 72-95: `credits` (24 bits) - reference count for the output wire
///
/// When the waiting wire becomes available, we can reconstruct the full gate by
/// combining the stored information with the newly-available wire ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactDependency {
    pub(crate) bytes: [u8; 12],
}

impl std::fmt::Debug for CompactDependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dep = self.as_dependency();
        f.debug_struct("CompactDependency")
            .field("other_in", &dep.other_in)
            .field("out", &dep.out)
            .field("gate_type", &dep.gate_type)
            .field("credits", &dep.credits)
            .finish()
    }
}

impl CompactDependency {
    /// Packs a gate dependency into 12 bytes.
    ///
    /// # Arguments
    /// - `other_in`: The input wire that IS available
    /// - `out`: The gate's output wire
    /// - `gate_type`: XOR or AND
    /// - `credits`: Reference count for the output wire
    pub fn new(
        other_in: CompactWireId,
        out: CompactWireId,
        gate_type: GateType,
        credits: Credits,
    ) -> Self {
        let other_in_u64 = other_in.to_u64();
        let out_u64 = out.to_u64();

        debug_assert!(other_in_u64 < (1u64 << 34), "other_in exceeds 34 bits");
        debug_assert!(out_u64 < (1u64 << 34), "out exceeds 34 bits");

        let mut bytes = [0u8; 12];
        // Pack: 34 bits other_in | 34 bits out | 1 bit gate_type | 24 bit credits

        // other_in: bits 0-33
        bytes[0] = (other_in_u64 & 0xFF) as u8;
        bytes[1] = ((other_in_u64 >> 8) & 0xFF) as u8;
        bytes[2] = ((other_in_u64 >> 16) & 0xFF) as u8;
        bytes[3] = ((other_in_u64 >> 24) & 0xFF) as u8;
        bytes[4] = ((other_in_u64 >> 32) & 0x3) as u8; // 2 bits

        // out: bits 34-67 (34 bits)
        bytes[4] |= ((out_u64 & 0x3F) << 2) as u8; // 6 bits of out
        bytes[5] = ((out_u64 >> 6) & 0xFF) as u8;
        bytes[6] = ((out_u64 >> 14) & 0xFF) as u8;
        bytes[7] = ((out_u64 >> 22) & 0xFF) as u8;
        bytes[8] = ((out_u64 >> 30) & 0xF) as u8; // 4 bits

        // gate_type: bit 68
        if gate_type == GateType::AND {
            bytes[8] |= 0x10; // Set bit 4
        }

        // credits: bytes 9-11 (bits 72-95, using 24 bits)
        bytes[9] = (credits.0 & 0xFF) as u8;
        bytes[10] = ((credits.0 >> 8) & 0xFF) as u8;
        bytes[11] = ((credits.0 >> 16) & 0xFF) as u8;

        Self { bytes }
    }

    /// Unpacks the compact dependency into a full structure.
    pub(crate) fn as_dependency(&self) -> Dependency {
        // Unpack other_in
        let other_in_u64 = self.bytes[0] as u64
            | ((self.bytes[1] as u64) << 8)
            | ((self.bytes[2] as u64) << 16)
            | ((self.bytes[3] as u64) << 24)
            | (((self.bytes[4] & 0x3) as u64) << 32);

        // Unpack out
        let out_u64 = ((self.bytes[4] >> 2) as u64)
            | ((self.bytes[5] as u64) << 6)
            | ((self.bytes[6] as u64) << 14)
            | ((self.bytes[7] as u64) << 22)
            | (((self.bytes[8] & 0xF) as u64) << 30);

        // Unpack gate_type
        let gate_type = if (self.bytes[8] & 0x10) != 0 {
            GateType::AND
        } else {
            GateType::XOR
        };

        // Unpack credits (24 bits)
        let credits = Credits(
            (self.bytes[9] as u32)
                | ((self.bytes[10] as u32) << 8)
                | ((self.bytes[11] as u32) << 16),
        );

        Dependency {
            other_in: CompactWireId::from_u64(other_in_u64),
            out: CompactWireId::from_u64(out_u64),
            gate_type,
            credits,
        }
    }
}

/// Internal: Unpacked representation of a gate dependency.
///
/// This is the runtime representation used when processing dependencies.
/// It's larger than `CompactDependency` but easier to work with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dependency {
    pub other_in: CompactWireId,
    pub out: CompactWireId,
    pub gate_type: GateType,
    pub credits: Credits,
}

impl Ord for Dependency {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.out.cmp(&other.out)
    }
}

impl PartialOrd for Dependency {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Dependency {
    fn eq(&self, other: &Self) -> bool {
        self.out == other.out
    }
}

impl Eq for Dependency {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_wire_id_as_bytes() {
        // Test basic values
        let wire_id = CompactWireId::from_u64(0);
        assert_eq!(wire_id.as_bytes(), &[0, 0, 0, 0, 0]);

        let wire_id = CompactWireId::from_u64(255);
        assert_eq!(wire_id.as_bytes(), &[255, 0, 0, 0, 0]);

        let wire_id = CompactWireId::from_u64(0x12345678);
        assert_eq!(wire_id.as_bytes(), &[0x78, 0x56, 0x34, 0x12, 0]);

        // Test 34-bit value
        let wire_id = CompactWireId::from_u64(0x3_FFFF_FFFF);
        assert_eq!(wire_id.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF, 0x3]);
    }

    #[test]
    fn test_compact_wire_id_byte_4_invariant() {
        // Test that byte 4 is always 0-3 for various inputs
        let test_values = vec![
            0u64,
            1,
            255,
            256,
            0xFFFF,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0x2_0000_0000,
            0x3_0000_0000,
            0x3_FFFF_FFFF, // Maximum 34-bit value
        ];

        for value in test_values {
            let wire_id = CompactWireId::from_u64(value);
            let bytes = wire_id.as_bytes();
            assert!(
                bytes[4] <= 3,
                "Byte 4 should be 0-3, got {} for input {}",
                bytes[4],
                value
            );
            // Also verify upper 6 bits are zero
            assert_eq!(
                bytes[4] & 0xFC,
                0,
                "Upper 6 bits of byte 4 should be zero, got {:#x} for input {}",
                bytes[4],
                value
            );
        }
    }

    #[test]
    fn test_compact_wire_id_byte_4_truncation() {
        // Test that values > 34 bits are truncated properly
        let wire_id = CompactWireId::from_u64(0xFFFF_FFFF_FFFF_FFFF);
        let bytes = wire_id.as_bytes();
        assert_eq!(
            bytes[4], 3,
            "Should truncate to 34 bits, byte 4 should be 3"
        );
        assert_eq!(bytes[0], 0xFF);
        assert_eq!(bytes[1], 0xFF);
        assert_eq!(bytes[2], 0xFF);
        assert_eq!(bytes[3], 0xFF);
    }

    #[test]
    fn test_compact_wire_id_round_trip_with_bytes() {
        // Test round-trip conversion using as_bytes
        let test_values = vec![
            0u64,
            1,
            42,
            255,
            256,
            0x1234,
            0x1234_5678,
            0x1_0000_0000,
            0x3_FFFF_FFFF,
        ];

        for value in test_values {
            let wire_id = CompactWireId::from_u64(value);
            let bytes = wire_id.as_bytes();
            let reconstructed = wire_id.to_u64();

            // Mask value to 34 bits for comparison
            let expected = value & 0x3_FFFF_FFFF;
            assert_eq!(
                reconstructed, expected,
                "Round-trip failed for value {:#x}",
                value
            );

            // Verify bytes representation matches expected
            assert_eq!(bytes[0], (expected & 0xFF) as u8);
            assert_eq!(bytes[1], ((expected >> 8) & 0xFF) as u8);
            assert_eq!(bytes[2], ((expected >> 16) & 0xFF) as u8);
            assert_eq!(bytes[3], ((expected >> 24) & 0xFF) as u8);
            assert_eq!(bytes[4], ((expected >> 32) & 0x3) as u8);
        }
    }

    #[test]
    fn test_compact_wire_id_different_upper_bits() {
        // Test values that differ only in upper 2 bits (for slot testing)
        let base = 0x1234_5678u64;

        let wire_id_0 = CompactWireId::from_u64(base);
        let wire_id_1 = CompactWireId::from_u64(base | (1u64 << 32));
        let wire_id_2 = CompactWireId::from_u64(base | (2u64 << 32));
        let wire_id_3 = CompactWireId::from_u64(base | (3u64 << 32));

        // All should have same lower 4 bytes
        assert_eq!(wire_id_0.as_bytes()[..4], wire_id_1.as_bytes()[..4]);
        assert_eq!(wire_id_0.as_bytes()[..4], wire_id_2.as_bytes()[..4]);
        assert_eq!(wire_id_0.as_bytes()[..4], wire_id_3.as_bytes()[..4]);

        // But different 5th byte
        assert_eq!(wire_id_0.as_bytes()[4], 0);
        assert_eq!(wire_id_1.as_bytes()[4], 1);
        assert_eq!(wire_id_2.as_bytes()[4], 2);
        assert_eq!(wire_id_3.as_bytes()[4], 3);
    }
}

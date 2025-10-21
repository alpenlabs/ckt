//! Core types for the levelling algorithm.
//!
//! This module defines compact, memory-efficient representations for circuit elements:
//! - Wire IDs compressed to 34 bits (5 bytes)
//! - Gate dependencies packed into 11 bytes
//! - Efficient tracking of wire availability and pending dependencies

use ckt::GateType;
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
pub struct Credits(pub u16);

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

/// A gate dependency packed into 11 bytes.
///
/// When a gate is waiting for an input wire to become available, we store a compact
/// representation of that gate. This saves memory compared to storing the full
/// `IntermediateGate` structure.
///
/// # Bit Layout (88 bits total in 11 bytes)
/// - Bits 0-33: `other_in` wire ID (34 bits) - the wire that IS available
/// - Bits 34-67: `out` wire ID (34 bits) - the gate's output
/// - Bit 68: `gate_type` (1 bit: 0=XOR, 1=AND)
/// - Bits 69-71: Padding (unused)
/// - Bits 72-87: `credits` (16 bits) - reference count for the output wire
///
/// When the waiting wire becomes available, we can reconstruct the full gate by
/// combining the stored information with the newly-available wire ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactDependency {
    pub(crate) bytes: [u8; 11],
}

impl std::fmt::Debug for CompactDependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dep = self.to_dependency();
        f.debug_struct("CompactDependency")
            .field("other_in", &dep.other_in)
            .field("out", &dep.out)
            .field("gate_type", &dep.gate_type)
            .field("credits", &dep.credits)
            .finish()
    }
}

impl CompactDependency {
    /// Packs a gate dependency into 11 bytes.
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

        let mut bytes = [0u8; 11];
        // Pack: 34 bits other_in | 34 bits out | 1 bit gate_type | 16 bit credits

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

        // credits: bytes 9-10 (bits 72-87)
        bytes[9] = (credits.0 & 0xFF) as u8;
        bytes[10] = ((credits.0 >> 8) & 0xFF) as u8;

        Self { bytes }
    }

    /// Unpacks the compact dependency into a full structure.
    pub fn to_dependency(&self) -> Dependency {
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

        // Unpack credits
        let credits = Credits((self.bytes[9] as u16) | ((self.bytes[10] as u16) << 8));

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

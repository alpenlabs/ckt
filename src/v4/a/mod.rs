//! CKT Format v4a - Intermediate format with credits for wire garbage collection
//!
//! This variant extends v3a with memory management via credits system,
//! enabling compile-time garbage collection for circuit evaluation.

pub mod reader;
pub mod varints;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

use crate::{
    GateType,
    v4::{FormatType, VERSION},
};

/// Circuit header for v4a format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitHeader {
    pub version: u8,         // Always 4
    pub format_type: u8,     // Always 0 (TypeA)
    pub checksum: [u8; 32],  // BLAKE3 hash of all data after checksum
    pub xor_gates: u64,      // Total XOR gates
    pub and_gates: u64,      // Total AND gates
    pub primary_inputs: u64, // Number of primary input wires
    pub num_outputs: u64,    // Number of output wires
}

impl CircuitHeader {
    /// Fixed header size in bytes: 1 + 1 + 32 + 8 + 8 + 8 + 8 = 66 bytes
    pub const FIXED_SIZE: usize = 66;

    /// Create a new v4a header (checksum will be computed during write)
    pub fn new(xor_gates: u64, and_gates: u64, primary_inputs: u64, num_outputs: u64) -> Self {
        Self {
            version: VERSION,
            format_type: FormatType::TypeA.to_byte(),
            checksum: [0; 32], // Placeholder, will be filled when writing
            xor_gates,
            and_gates,
            primary_inputs,
            num_outputs,
        }
    }

    /// Get total gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }

    /// Check if circuit has outputs
    pub fn has_outputs(&self) -> bool {
        self.num_outputs > 0
    }
}

/// A gate with wire IDs and credits for memory management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub in1: u64,     // Input 1 wire ID
    pub in2: u64,     // Input 2 wire ID
    pub out: u64,     // Output wire ID
    pub credits: u32, // Memory credits for this gate's output
}

impl Gate {
    /// Create a new gate
    pub fn new(input1: u64, input2: u64, output: u64, credits: u32) -> Self {
        Self {
            in1: input1,
            in2: input2,
            out: output,
            credits,
        }
    }

    /// Create a gate with default credits (for compatibility)
    pub fn with_default_credits(input1: u64, input2: u64, output: u64) -> Self {
        Self::new(input1, input2, output, 1) // Default to 1 credit
    }
}

/// A batch of gates with encoded wire IDs and credits
///
/// Gates are stored as a sequence of FlaggedVarInts:
/// - in1: FlaggedVarInt (absolute if flag, relative if no flag)
/// - in2: FlaggedVarInt (absolute if flag, relative if no flag)
/// - out: FlaggedVarInt (absolute if flag, relative if no flag)
/// - credits: StandardVarInt
///
/// This is followed by a single byte for gate types.
pub struct GateBatch {
    /// Buffer containing encoded gates
    pub gates_buffer: Vec<u8>,
    /// Number of valid gates in batch (0-8)
    pub gate_count: usize,
    /// Packed gate types: bit i indicates type of gate i
    /// 0 = XOR, 1 = AND
    pub gate_types: u8,
}

impl GateBatch {
    /// Maximum gates per batch
    pub const MAX_GATES: usize = 8;

    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            gates_buffer: Vec::with_capacity(256), // Reasonable initial capacity
            gate_count: 0,
            gate_types: 0,
        }
    }

    /// Create a batch with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            gates_buffer: Vec::with_capacity(capacity),
            gate_count: 0,
            gate_types: 0,
        }
    }

    /// Add a gate to the batch
    /// Returns true if gate was added, false if batch is full
    pub fn add_gate(&mut self, gate: Gate, gate_type: GateType, wire_counter: u64) -> bool {
        if self.gate_count >= Self::MAX_GATES {
            return false;
        }

        // Encode gate using FlaggedVarInts relative to wire_counter
        // This will be implemented in varints module
        // For now, we'll store the gate data

        // Set gate type bit
        match gate_type {
            GateType::XOR => self.gate_types &= !(1 << self.gate_count),
            GateType::AND => self.gate_types |= 1 << self.gate_count,
        }

        self.gate_count += 1;
        true
    }

    /// Check if batch is full
    pub fn is_full(&self) -> bool {
        self.gate_count >= Self::MAX_GATES
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.gate_count == 0
    }

    /// Clear the batch for reuse
    pub fn clear(&mut self) {
        self.gates_buffer.clear();
        self.gate_count = 0;
        self.gate_types = 0;
    }

    /// Get the serialized size of this batch
    pub fn encoded_size(&self) -> usize {
        self.gates_buffer.len() + 1 // +1 for gate_types byte
    }

    /// Serialize batch to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_size());
        bytes.extend_from_slice(&self.gates_buffer);
        bytes.push(self.gate_types);
        bytes
    }
}

impl Default for GateBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Output wire information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputWire {
    pub wire_id: u64,
}

impl OutputWire {
    pub fn new(wire_id: u64) -> Self {
        Self { wire_id }
    }
}

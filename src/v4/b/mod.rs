//! CKT Format v4b - Production format with precomputed memory addresses
//!
//! This variant is the output of the levelling and memory preallocation process,
//! optimized for maximum performance during circuit evaluation.

pub mod reader;
pub mod varints;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

use crate::{
    GateType,
    v4::{FormatType, VERSION},
};

/// Circuit header for v4b format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitHeader {
    pub version: u8,         // Always 4
    pub format_type: u8,     // Always 1 (TypeB)
    pub checksum: [u8; 32],  // BLAKE3 hash of all data after checksum
    pub xor_gates: u64,      // Total XOR gates
    pub and_gates: u64,      // Total AND gates
    pub primary_inputs: u64, // Number of primary input wires
    pub scratch_space: u64,  // Maximum scratch space entries needed
    pub num_outputs: u64,    // Number of output addresses
}

impl CircuitHeader {
    /// Fixed header size in bytes: 1 + 1 + 32 + 8 + 8 + 8 + 8 + 8 = 74 bytes
    pub const FIXED_SIZE: usize = 74;

    /// Create a new v4b header (checksum will be computed during write)
    pub fn new(
        xor_gates: u64,
        and_gates: u64,
        primary_inputs: u64,
        scratch_space: u64,
        num_outputs: u64,
    ) -> Self {
        Self {
            version: VERSION,
            format_type: FormatType::TypeB.to_byte(),
            checksum: [0; 32], // Placeholder, will be filled when writing
            xor_gates,
            and_gates,
            primary_inputs,
            scratch_space,
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

/// A gate with precomputed memory addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub in1: u64, // Scratch space index for input 1
    pub in2: u64, // Scratch space index for input 2
    pub out: u64, // Scratch space index for output
}

impl Gate {
    /// Create a new gate with memory addresses
    pub fn new(input1_addr: u64, input2_addr: u64, output_addr: u64) -> Self {
        Self {
            in1: input1_addr,
            in2: input2_addr,
            out: output_addr,
        }
    }
}

/// A level containing XOR and AND gates that can be executed in parallel
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

    /// Add a gate with its type
    pub fn add_gate(&mut self, gate: Gate, gate_type: GateType) {
        match gate_type {
            GateType::XOR => self.add_xor_gate(gate),
            GateType::AND => self.add_and_gate(gate),
        }
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
    /// First input memory addresses
    pub input1_addrs: Vec<u64>,
    /// Second input memory addresses
    pub input2_addrs: Vec<u64>,
    /// Output memory addresses
    pub output_addrs: Vec<u64>,
    /// Number of valid gates
    pub count: usize,
}

impl<const N: usize> XorGates<N> {
    pub fn new() -> Self {
        Self {
            input1_addrs: Vec::with_capacity(N),
            input2_addrs: Vec::with_capacity(N),
            output_addrs: Vec::with_capacity(N),
            count: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            input1_addrs: Vec::with_capacity(capacity),
            input2_addrs: Vec::with_capacity(capacity),
            output_addrs: Vec::with_capacity(capacity),
            count: 0,
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        self.input1_addrs.push(gate.in1);
        self.input2_addrs.push(gate.in2);
        self.output_addrs.push(gate.out);
        self.count += 1;
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
    /// First input memory addresses
    pub input1_addrs: Vec<u64>,
    /// Second input memory addresses
    pub input2_addrs: Vec<u64>,
    /// Output memory addresses
    pub output_addrs: Vec<u64>,
    /// Number of valid gates
    pub count: usize,
}

impl<const N: usize> AndGates<N> {
    pub fn new() -> Self {
        Self {
            input1_addrs: Vec::with_capacity(N),
            input2_addrs: Vec::with_capacity(N),
            output_addrs: Vec::with_capacity(N),
            count: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            input1_addrs: Vec::with_capacity(capacity),
            input2_addrs: Vec::with_capacity(capacity),
            output_addrs: Vec::with_capacity(capacity),
            count: 0,
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        self.input1_addrs.push(gate.in1);
        self.input2_addrs.push(gate.in2);
        self.output_addrs.push(gate.out);
        self.count += 1;
    }
}

impl<const N: usize> Default for AndGates<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Output memory address information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputAddress {
    pub memory_index: u64,
}

impl OutputAddress {
    pub fn new(memory_index: u64) -> Self {
        Self { memory_index }
    }
}

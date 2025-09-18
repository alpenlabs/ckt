//! CKT Format v3a - Fixed-size 34-bit wire IDs with batching
//!
//! This variant evolved from v1 with extended wire ID support (up to 2^34 wires)
//! and version/type flags for format detection.

pub mod reader;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

use crate::{
    GateType,
    v3::{FormatType, VERSION},
};

/// Circuit header for v3a format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitHeader {
    pub version: u8,        // Always 3
    pub format_type: u8,    // Always 0 (TypeA)
    pub checksum: [u8; 32], // BLAKE3 hash of all data after checksum
    pub xor_gates: u64,     // Total XOR gates
    pub and_gates: u64,     // Total AND gates
}

impl CircuitHeader {
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

/// A gate with 34-bit wire indices
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gate {
    pub in1: u64, // Only lower 34 bits used
    pub in2: u64, // Only lower 34 bits used
    pub out: u64, // Only lower 34 bits used
}

impl Gate {
    /// Maximum value for 34-bit wire IDs
    pub const MAX_WIRE_ID: u64 = (1u64 << 34) - 1;

    /// Create a new gate with validation
    pub fn new(input1: u64, input2: u64, output: u64) -> Self {
        debug_assert!(input1 <= Self::MAX_WIRE_ID, "input1 exceeds 34 bits");
        debug_assert!(input2 <= Self::MAX_WIRE_ID, "input2 exceeds 34 bits");
        debug_assert!(output <= Self::MAX_WIRE_ID, "output exceeds 34 bits");

        Self {
            in1: input1 & Self::MAX_WIRE_ID,
            in2: input2 & Self::MAX_WIRE_ID,
            out: output & Self::MAX_WIRE_ID,
        }
    }
}

/// A batch of 8 gates with 34-bit wire IDs and packed gate type bits
///
/// Memory layout:
/// - 102 bytes: 8 gates × 3 wire IDs × 34 bits = 816 bits
/// - 1 byte: gate types (bit i = type of gate i, 0=XOR, 1=AND)
///
/// Wire IDs are tightly packed across byte boundaries
#[repr(C, packed)]
pub struct GateBatch34 {
    /// Raw bytes for 8 gates with 34-bit wire IDs (102 bytes total)
    pub gates: [u8; 102],
    /// Packed gate types: bit i indicates type of gate i
    /// 0 = XOR, 1 = AND
    pub gate_types: u8,
}

const _: () = {
    const EXPECTED: usize = 103;
    const fn assert_size() {
        let _ = [(); EXPECTED - GateBatch34::SIZE];
        let _ = [(); GateBatch34::SIZE - EXPECTED];
    }
    assert_size()
};

impl GateBatch34 {
    pub const SIZE: usize = size_of::<Self>();

    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            gates: [0u8; 102],
            gate_types: 0,
        }
    }

    /// Set a gate in the batch (with 34-bit wire IDs)
    pub fn set_gate(&mut self, index: usize, gate: Gate, gate_type: GateType) {
        debug_assert!(index < 8, "Gate index must be 0-7");

        // Calculate bit position for this gate (index * 102 bits)
        let bit_offset = index * 102;

        // Pack the three 34-bit values
        self.set_34bit_value(bit_offset, gate.in1);
        self.set_34bit_value(bit_offset + 34, gate.in2);
        self.set_34bit_value(bit_offset + 68, gate.out);

        // Set gate type
        match gate_type {
            GateType::XOR => self.gate_types &= !(1 << index),
            GateType::AND => self.gate_types |= 1 << index,
        }
    }

    /// Get a gate from the batch (with 34-bit wire IDs)
    pub fn get_gate(&self, index: usize) -> (Gate, GateType) {
        debug_assert!(index < 8, "Gate index must be 0-7");

        // Calculate bit position for this gate
        let bit_offset = index * 102;

        // Unpack the three 34-bit values
        let input1 = self.get_34bit_value(bit_offset);
        let input2 = self.get_34bit_value(bit_offset + 34);
        let output = self.get_34bit_value(bit_offset + 68);

        let gate = Gate::new(input1, input2, output);
        let gate_type = self.gate_type(index);

        (gate, gate_type)
    }

    /// Get gate type for a specific index
    pub fn gate_type(&self, index: usize) -> GateType {
        debug_assert!(index < 8, "Gate index must be 0-7");
        if (self.gate_types >> index) & 1 == 0 {
            GateType::XOR
        } else {
            GateType::AND
        }
    }

    /// Helper: Set a 34-bit value at the given bit offset
    fn set_34bit_value(&mut self, bit_offset: usize, value: u64) {
        debug_assert!(value <= Gate::MAX_WIRE_ID, "Value exceeds 34 bits");

        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        // We need to write up to 5 bytes (34 bits can span 5 bytes)
        // Clear and set bits carefully to preserve surrounding data

        if bit_shift == 0 {
            // Aligned case - simpler
            self.gates[byte_offset] = (value & 0xFF) as u8;
            self.gates[byte_offset + 1] = ((value >> 8) & 0xFF) as u8;
            self.gates[byte_offset + 2] = ((value >> 16) & 0xFF) as u8;
            self.gates[byte_offset + 3] = ((value >> 24) & 0xFF) as u8;
            // Only lower 2 bits of the 5th byte
            self.gates[byte_offset + 4] =
                (self.gates[byte_offset + 4] & 0xFC) | ((value >> 32) & 0x03) as u8;
        } else {
            // Unaligned case - need to preserve bits
            let mut temp = value << bit_shift;

            // First byte (partial)
            let mask0 = (1u8 << bit_shift) - 1;
            self.gates[byte_offset] = (self.gates[byte_offset] & mask0) | (temp & 0xFF) as u8;
            temp >>= 8;

            // Middle bytes (full)
            self.gates[byte_offset + 1] = (temp & 0xFF) as u8;
            temp >>= 8;
            self.gates[byte_offset + 2] = (temp & 0xFF) as u8;
            temp >>= 8;
            self.gates[byte_offset + 3] = (temp & 0xFF) as u8;
            temp >>= 8;

            // Last byte(s) (partial) - might span into byte 5
            if bit_shift <= 6 {
                // Fits in 5 bytes total
                let remaining_bits = 34 - (32 - bit_shift);
                let mask4 = if remaining_bits >= 8 {
                    0u8 // All bits will be replaced
                } else {
                    !((1u8 << remaining_bits) - 1)
                };
                self.gates[byte_offset + 4] =
                    (self.gates[byte_offset + 4] & mask4) | (temp & 0xFF) as u8;
            } else {
                // Spans into 6th byte
                self.gates[byte_offset + 4] = (temp & 0xFF) as u8;
                temp >>= 8;
                let remaining_bits = bit_shift - 6;
                let mask5 = !((1u8 << remaining_bits) - 1);
                self.gates[byte_offset + 5] =
                    (self.gates[byte_offset + 5] & mask5) | (temp & 0xFF) as u8;
            }
        }
    }

    /// Helper: Get a 34-bit value at the given bit offset
    fn get_34bit_value(&self, bit_offset: usize) -> u64 {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            // Aligned case
            let mut value = self.gates[byte_offset] as u64;
            value |= (self.gates[byte_offset + 1] as u64) << 8;
            value |= (self.gates[byte_offset + 2] as u64) << 16;
            value |= (self.gates[byte_offset + 3] as u64) << 24;
            value |= ((self.gates[byte_offset + 4] & 0x03) as u64) << 32;
            value
        } else {
            // Unaligned case
            let mut value = 0u64;

            // Read up to 6 bytes and extract 34 bits
            value |= self.gates[byte_offset] as u64;
            value |= (self.gates[byte_offset + 1] as u64) << 8;
            value |= (self.gates[byte_offset + 2] as u64) << 16;
            value |= (self.gates[byte_offset + 3] as u64) << 24;
            value |= (self.gates[byte_offset + 4] as u64) << 32;

            if byte_offset + 5 < 102 {
                value |= (self.gates[byte_offset + 5] as u64) << 40;
            }

            // Shift and mask to get our 34 bits
            value >>= bit_shift;
            value & Gate::MAX_WIRE_ID
        }
    }

    /// Count actual gates in batch (0-8)
    pub fn gate_count(&self) -> usize {
        // Check each gate to see if it's non-zero
        for i in 0..8 {
            let (gate, _) = self.get_gate(i);
            if gate.in1 == 0 && gate.in2 == 0 && gate.out == 0 {
                return i;
            }
        }
        8
    }

    /// Serialize batch to exactly SIZE bytes
    pub fn to_bytes(&self) -> [u8; GateBatch34::SIZE] {
        let mut bytes = [0u8; GateBatch34::SIZE];
        bytes[0..102].copy_from_slice(&self.gates);
        bytes[102] = self.gate_types;
        bytes
    }

    /// Deserialize batch from exactly SIZE bytes
    pub fn from_bytes(bytes: &[u8; GateBatch34::SIZE]) -> Self {
        let mut gates = [0u8; 102];
        gates.copy_from_slice(&bytes[0..102]);

        Self {
            gates,
            gate_types: bytes[102],
        }
    }
}

impl Default for GateBatch34 {
    fn default() -> Self {
        Self::new()
    }
}

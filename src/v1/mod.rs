//! CKT Format v1 - Original format with fixed 32-bit wire IDs

pub mod reader;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

/// A compact representation of a gate with 32-bit wire indices
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompactGate {
    pub input1: u32,
    pub input2: u32,
    pub output: u32,
}

impl CompactGate {
    pub fn new(input1: u32, input2: u32, output: u32) -> Self {
        Self {
            input1,
            input2,
            output,
        }
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.input1.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.input2.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.output.to_le_bytes());
        bytes
    }

    /// Create from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 12]) -> Self {
        Self {
            input1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            input2: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            output: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        }
    }
}

/// A batch of 8 gates with packed gate type bits
///
/// Memory layout:
/// - 96 bytes: 8 gates × 12 bytes each
/// - 1 byte: gate types (bit i = type of gate i, 0=XOR, 1=AND)
#[repr(C, packed)]
pub struct GateBatch {
    /// Raw bytes for 8 gates (96 bytes total)
    pub gates: [u8; 96],
    /// Packed gate types: bit i indicates type of gate i
    /// 0 = XOR, 1 = AND
    pub gate_types: u8,
}

/// Gate type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

const _: () = {
    const EXPECTED: usize = 97;
    const fn assert_size() {
        let _ = [(); EXPECTED - GateBatch::SIZE];
        let _ = [(); GateBatch::SIZE - EXPECTED];
    }
    assert_size()
};

impl GateBatch {
    pub const SIZE: usize = size_of::<Self>();

    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            gates: [0u8; 96],
            gate_types: 0,
        }
    }

    /// Set a gate in the batch
    pub fn set_gate(&mut self, index: usize, gate: CompactGate, gate_type: GateType) {
        debug_assert!(index < 8, "Gate index must be 0-7");

        let offset = index * 12;
        let gate_bytes = gate.to_bytes();
        self.gates[offset..offset + 12].copy_from_slice(&gate_bytes);

        match gate_type {
            GateType::XOR => self.gate_types &= !(1 << index),
            GateType::AND => self.gate_types |= 1 << index,
        }
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

    /// Get a gate from the batch
    pub fn get_gate(&self, index: usize) -> (CompactGate, GateType) {
        debug_assert!(index < 8, "Gate index must be 0-7");

        let offset = index * 12;
        let mut gate_bytes = [0u8; 12];
        gate_bytes.copy_from_slice(&self.gates[offset..offset + 12]);

        (CompactGate::from_bytes(&gate_bytes), self.gate_type(index))
    }

    /// Count actual gates in batch (0-8)
    /// Gates are stored contiguously from index 0
    pub fn gate_count(&self) -> usize {
        // Check each gate to see if it's non-zero
        for i in 0..8 {
            let offset = i * 12;
            let is_zero = self.gates[offset..offset + 12].iter().all(|&b| b == 0);
            if is_zero {
                return i;
            }
        }
        8
    }

    /// Get gate count with expected value (for validation)
    pub fn gate_count_with_expected(&self, expected: usize) -> usize {
        expected.min(8)
    }

    /// Serialize batch to exactly GateBatch::SIZE bytes
    pub fn to_bytes(&self) -> [u8; GateBatch::SIZE] {
        let mut bytes = [0u8; GateBatch::SIZE];
        bytes[0..96].copy_from_slice(&self.gates);
        bytes[96] = self.gate_types;
        bytes
    }

    /// Deserialize batch from exactly GateBatch::SIZE bytes
    pub fn from_bytes(bytes: &[u8; GateBatch::SIZE]) -> Self {
        let mut gates = [0u8; 96];
        gates.copy_from_slice(&bytes[0..96]);

        Self {
            gates,
            gate_types: bytes[96],
        }
    }

    /// Cast bytes directly to a GateBatch reference (zero-copy)
    /// SAFETY: The slice must be exactly GateBatch::SIZE bytes and properly aligned
    #[inline]
    pub fn from_bytes_ref(bytes: &[u8]) -> &Self {
        debug_assert_eq!(
            bytes.len(),
            GateBatch::SIZE,
            "GateBatch requires exactly 97 bytes"
        );
        debug_assert_eq!(
            bytes.as_ptr() as usize % std::mem::align_of::<Self>(),
            0,
            "GateBatch must be properly aligned"
        );

        // SAFETY: GateBatch is repr(C) with layout [u8; 96] + u8, so we can safely cast
        // as long as the slice is exactly GateBatch::SIZE bytes and properly aligned
        unsafe { &*(bytes.as_ptr() as *const Self) }
    }
}

impl Default for GateBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GateBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateBatch")
            .field("gates", &GateBatchGatesDebug(&self.gates, self.gate_types))
            .field("gate_types", &format!("0b{:08b}", self.gate_types))
            .finish()
    }
}

/// Helper struct for debugging the gates array with their types
struct GateBatchGatesDebug<'a>(&'a [u8; 96], u8);

impl<'a> std::fmt::Debug for GateBatchGatesDebug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();

        for i in 0..8 {
            let start = i * 12;
            let end = start + 12;
            let gate_bytes: [u8; 12] = self.0[start..end].try_into().unwrap();
            let gate = CompactGate::from_bytes(&gate_bytes);

            // Check bit i of gate_types to determine gate type
            let gate_type = if (self.1 >> i) & 1 == 0 { "XOR" } else { "AND" };

            list.entry(&format!(
                "{}: {} {{ in1: {}, in2: {}, out: {} }}",
                i, gate_type, gate.input1, gate.input2, gate.output
            ));
        }

        list.finish()
    }
}

/// Circuit header structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitHeader {
    pub xor_gates: u32,
    pub and_gates: u32,
}

use super::constants::*;

/// A single gate in v5c format (Array-of-Structures layout)
///
/// This struct is #[repr(C)] to ensure consistent memory layout for zero-copy casting.
/// Each field is a 32-bit little-endian memory address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateV5c {
    pub in1: u32, // 32-bit memory address (little-endian)
    pub in2: u32, // 32-bit memory address (little-endian)
    pub out: u32, // 32-bit memory address (little-endian)
}

impl GateV5c {
    /// Create a new gate
    pub fn new(in1: u32, in2: u32, out: u32) -> Self {
        GateV5c { in1, in2, out }
    }

    /// Validate gate addresses against scratch space
    pub fn validate(&self, scratch_space: u64) -> Result<(), String> {
        if self.in1 as u64 >= scratch_space {
            return Err(format!(
                "in1 address {} exceeds scratch_space {}",
                self.in1, scratch_space
            ));
        }

        if self.in2 as u64 >= scratch_space {
            return Err(format!(
                "in2 address {} exceeds scratch_space {}",
                self.in2, scratch_space
            ));
        }

        if self.out as u64 >= scratch_space {
            return Err(format!(
                "out address {} exceeds scratch_space {}",
                self.out, scratch_space
            ));
        }

        Ok(())
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; GATE_SIZE] {
        let mut bytes = [0u8; GATE_SIZE];
        bytes[0..4].copy_from_slice(&self.in1.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.in2.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.out.to_le_bytes());
        bytes
    }

    /// Create from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= GATE_SIZE);
        let in1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let in2 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let out = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        GateV5c { in1, in2, out }
    }
}

//! CKT Format v5b - Production format with memory addresses and level organization
//!
//! This module implements the v5b variant of the CKT format specification.
//! v5b is the production format with:
//! - 32-bit memory addresses (not wire IDs)
//! - Level-based organization for parallel evaluation on CUDA GPUs
//! - Array-of-Structures (AoS) layout: 12 bytes/gate (3 × u32 LE)
//! - No credits field (memory management already resolved)
//! - Gate types inferred from position (first N are XOR, rest are AND)
//! - Zero-copy reading via direct pointer cast to &[GateV5b]

// pub mod reader;
pub mod reader;
pub mod writer;

#[cfg(test)]
pub mod integration;

/// Size of a single gate in v5b format (3 × u32 LE = 12 bytes)
pub const GATE_SIZE: usize = 12;

/// Size of the v5b header in bytes
pub const HEADER_SIZE: usize = 88;

/// Size of each output entry in bytes (32 bits, u32 LE)
pub const OUTPUT_ENTRY_SIZE: usize = 4;

/// Size of a level header in bytes
pub const LEVEL_HEADER_SIZE: usize = 8;

/// Maximum addressable memory (2^32)
pub const MAX_MEMORY_ADDRESS: u64 = 4_294_967_296;

/// Header structure for v5b format (88 bytes)
///
/// Note: This struct is padded to 88 bytes (divisible by 8) in the actual layout,
/// so all fields happen to be properly aligned. However, we mark it as `packed` and
/// use `read_unaligned` for absolute safety, as the `packed` attribute tells the
/// compiler to treat all field accesses as potentially unaligned. This prevents any
/// possibility of undefined behavior.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HeaderV5b {
    // Identification (8 bytes)
    pub magic: [u8; 4],    // "Zk2u" (0x5A6B3275)
    pub version: u8,       // Always 0x05
    pub format_type: u8,   // Always 0x01 for v5b
    pub reserved: [u8; 2], // Reserved, must be 0x0000

    // Checksum (32 bytes)
    pub checksum: [u8; 32], // BLAKE3 hash

    // Circuit metadata (48 bytes)
    pub xor_gates: u64,      // Total XOR gates (little-endian)
    pub and_gates: u64,      // Total AND gates (little-endian)
    pub primary_inputs: u64, // Number of primary inputs
    pub scratch_space: u64,  // Maximum scratch space entries needed
    pub num_outputs: u64,    // Number of outputs
    pub num_levels: u32,     // Number of levels in circuit
    pub reserved2: u32,      // Reserved for alignment
}

impl Default for HeaderV5b {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderV5b {
    /// Create a new header with default values
    pub fn new() -> Self {
        HeaderV5b {
            magic: crate::v5::MAGIC,
            version: crate::v5::VERSION,
            format_type: crate::v5::FormatType::TypeB.to_byte(),
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 0,
            and_gates: 0,
            primary_inputs: 0,
            scratch_space: 0,
            num_outputs: 0,
            num_levels: 0,
            reserved2: 0,
        }
    }

    /// Get total number of gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }

    /// Validate the header
    pub fn validate(&self) -> Result<(), String> {
        // Check magic bytes
        if self.magic != crate::v5::MAGIC {
            return Err(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                crate::v5::MAGIC,
                self.magic
            ));
        }

        // Check version
        if self.version != crate::v5::VERSION {
            return Err(format!(
                "Invalid version: expected {}, got {}",
                crate::v5::VERSION,
                self.version
            ));
        }

        // Check format type
        if self.format_type != crate::v5::FormatType::TypeB.to_byte() {
            return Err(format!(
                "Invalid format type: expected {}, got {}",
                crate::v5::FormatType::TypeB.to_byte(),
                self.format_type
            ));
        }

        // Check reserved fields
        if self.reserved != [0, 0] {
            return Err(format!(
                "Reserved field must be zero, got {:?}",
                self.reserved
            ));
        }

        // Safe: read_unaligned for packed struct field access using raw pointer.
        // Even though this struct is padded to 88 bytes and fields are aligned,
        // the `packed` attribute requires us to use unaligned reads.
        let reserved2 = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.reserved2)) };
        if reserved2 != 0 {
            return Err(format!("Reserved2 field must be zero, got {}", reserved2));
        }

        // Check for overflow
        if self.xor_gates.saturating_add(self.and_gates) == u64::MAX {
            return Err("Total gate count would overflow".to_string());
        }

        // Validate scratch space
        // Safe: read_unaligned for packed struct field access using raw pointer
        let scratch_space =
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.scratch_space)) };
        if scratch_space > MAX_MEMORY_ADDRESS {
            return Err(format!(
                "Scratch space {} exceeds maximum addressable memory {}",
                scratch_space, MAX_MEMORY_ADDRESS
            ));
        }

        // Check that we have levels if we have gates
        if self.total_gates() > 0 && self.num_levels == 0 {
            return Err("Circuit has gates but no levels".to_string());
        }

        Ok(())
    }

    /// Convert header to byte array for writing
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];

        // Copy header as raw bytes (it's packed)
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                HEADER_SIZE,
            );
        }

        bytes
    }

    /// Create header from byte array
    pub fn from_bytes(bytes: &[u8; HEADER_SIZE]) -> Self {
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Self) }
    }
}

/// Level header structure (8 bytes)
///
/// Note: This struct is exactly 8 bytes (divisible by 4), so both u32 fields
/// are properly aligned. However, we mark it as `packed` and use `read_unaligned`
/// for absolute safety, ensuring no undefined behavior regardless of how the
/// compiler chooses to lay out the struct.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LevelHeader {
    pub num_xor_gates: u32, // Number of XOR gates in this level
    pub num_and_gates: u32, // Number of AND gates in this level
}

impl LevelHeader {
    /// Create a new level header
    pub fn new(num_xor_gates: u32, num_and_gates: u32) -> Self {
        LevelHeader {
            num_xor_gates,
            num_and_gates,
        }
    }

    /// Get total number of gates
    pub fn num_gates(&self) -> u32 {
        self.num_xor_gates.saturating_add(self.num_and_gates)
    }

    /// Validate the level header
    pub fn validate(&self) -> Result<(), String> {
        // Check for overflow when adding
        // Safe: read_unaligned for packed struct field access using raw pointers.
        // Even though this 8-byte struct has naturally aligned fields, the `packed`
        // attribute requires us to use unaligned reads for absolute safety.
        let num_xor_gates =
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.num_xor_gates)) };
        let num_and_gates =
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.num_and_gates)) };
        if num_xor_gates.checked_add(num_and_gates).is_none() {
            return Err(format!(
                "Gate counts overflow: XOR {} + AND {}",
                num_xor_gates, num_and_gates
            ));
        }
        Ok(())
    }

    /// Convert to bytes for writing
    pub fn to_bytes(&self) -> [u8; LEVEL_HEADER_SIZE] {
        let mut bytes = [0u8; LEVEL_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.num_xor_gates.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.num_and_gates.to_le_bytes());
        bytes
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; LEVEL_HEADER_SIZE]) -> Self {
        let num_xor_gates = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let num_and_gates = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        LevelHeader {
            num_xor_gates,
            num_and_gates,
        }
    }
}

/// A single gate in v5b format (Array-of-Structures layout for GPU)
///
/// This struct is #[repr(C)] to ensure consistent memory layout for zero-copy casting.
/// Each field is a 32-bit little-endian memory address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateV5b {
    pub in1: u32, // 32-bit memory address (little-endian)
    pub in2: u32, // 32-bit memory address (little-endian)
    pub out: u32, // 32-bit memory address (little-endian)
                  // No credits field - memory management already resolved
                  // No gate_type field - determined by position in level
}

impl GateV5b {
    /// Create a new gate
    pub fn new(in1: u32, in2: u32, out: u32) -> Result<Self, String> {
        // Validate 32-bit addresses against scratch space max
        if in1 as u64 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in1 address {} exceeds 32-bit maximum", in1));
        }
        if in2 as u64 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in2 address {} exceeds 32-bit maximum", in2));
        }
        if out as u64 >= MAX_MEMORY_ADDRESS {
            return Err(format!("out address {} exceeds 32-bit maximum", out));
        }

        Ok(GateV5b { in1, in2, out })
    }

    /// Check if this gate represents a valid operation
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify gate size
        assert_eq!(GATE_SIZE, 12);
        assert_eq!(GATE_SIZE, std::mem::size_of::<GateV5b>());

        // Verify output entry size
        assert_eq!(OUTPUT_ENTRY_SIZE, 4);

        // Verify max address space
        assert_eq!(MAX_MEMORY_ADDRESS, 4_294_967_296);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(std::mem::size_of::<HeaderV5b>(), HEADER_SIZE);
    }

    #[test]
    fn test_level_header_size() {
        assert_eq!(std::mem::size_of::<LevelHeader>(), LEVEL_HEADER_SIZE);
    }

    #[test]
    fn test_header_validation() {
        let mut header = HeaderV5b::new();
        assert!(header.validate().is_ok());

        // Test invalid magic
        header.magic = [0, 0, 0, 0];
        assert!(header.validate().is_err());
        header.magic = crate::v5::MAGIC;

        // Test invalid version
        header.version = 0x04;
        assert!(header.validate().is_err());
        header.version = crate::v5::VERSION;

        // Test invalid format type
        header.format_type = 0x00; // Should be 0x01 for v5b
        assert!(header.validate().is_err());
        header.format_type = 0x01;

        // Test scratch space overflow
        header.scratch_space = MAX_MEMORY_ADDRESS + 1;
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_gate_validation() {
        // Valid gate
        let gate = GateV5b::new(100, 200, 300).unwrap();
        assert!(gate.validate(1000).is_ok());

        // Invalid addresses (exceeds u32::MAX would fail at creation)
        let gate = GateV5b::new(100, 200, 300).unwrap();
        assert!(gate.validate(250).is_err()); // exceeds scratch_space
    }

    #[test]
    fn test_gate_memory_layout() {
        // Verify #[repr(C)] layout for zero-copy casting
        assert_eq!(std::mem::size_of::<GateV5b>(), 12);
        assert_eq!(std::mem::align_of::<GateV5b>(), 4);

        // Test that we can safely cast bytes to gates
        let gates = [GateV5b::new(10, 20, 30).unwrap(),
            GateV5b::new(40, 50, 60).unwrap()];

        // Convert to bytes
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                gates.as_ptr() as *const u8,
                gates.len() * std::mem::size_of::<GateV5b>(),
            )
        };

        // Cast back
        let gates_back: &[GateV5b] =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const GateV5b, gates.len()) };

        assert_eq!(gates_back, &gates[..]);
    }

    #[test]
    fn test_level_header() {
        let header = LevelHeader::new(100, 50);
        let num_gates = header.num_gates();
        assert_eq!(num_gates, 150);
        let num_xor_gates = header.num_xor_gates;
        assert_eq!(num_xor_gates, 100);
        let num_and_gates = header.num_and_gates;
        assert_eq!(num_and_gates, 50);

        // Test serialization
        let bytes = header.to_bytes();
        let header2 = LevelHeader::from_bytes(&bytes);
        let header_num_gates = header.num_gates();
        let header2_num_gates = header2.num_gates();
        assert_eq!(header_num_gates, header2_num_gates);
        let header_num_xor_gates = header.num_xor_gates;
        let header2_num_xor_gates = header2.num_xor_gates;
        assert_eq!(header_num_xor_gates, header2_num_xor_gates);
        let header_num_and_gates = header.num_and_gates;
        let header2_num_and_gates = header2.num_and_gates;
        assert_eq!(header_num_and_gates, header2_num_and_gates);

        // Test validation
        assert!(header.validate().is_ok());

        let bad_header = LevelHeader {
            num_xor_gates: u32::MAX,
            num_and_gates: 100, // This would overflow
        };
        assert!(bad_header.validate().is_err());
    }
}

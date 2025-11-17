//! CKT Format v5c - Flat production format with execution-ordered gates
//!
//! This module implements the v5c format specification with:
//! - 32-bit memory addresses (not wire IDs)
//! - Flat array organization (no level structure)
//! - 256 KiB blocks optimized for 1 MB L2 cache
//! - Bit-compacted gate types (1 bit per gate)
//! - Gates stored in execution order
//!
//! v5c is designed for garbling workloads where both gate data and ciphertext
//! accumulation buffers fit comfortably in L2 cache, with Arc-sharing support
//! for distributing blocks to multiple worker threads.

use std::io::{self, Error, ErrorKind};

use crate::GateType;

#[cfg(test)]
pub mod integration;
pub mod reader;
pub mod writer;

/// Block size for v5c format (256 KiB)
pub const BLOCK_SIZE: usize = 256 * 1024; // 262,144 bytes

/// Maximum gates per block (calculated to fit in BLOCK_SIZE with alignment)
pub const GATES_PER_BLOCK: usize = 21_620;

/// Size of a single gate (3 × u32 LE)
pub const GATE_SIZE: usize = 12;

/// Header size
pub const HEADER_SIZE: usize = 88;

/// Output entry size (u32 LE)
pub const OUTPUT_ENTRY_SIZE: usize = 4;

/// Section alignment (256 KiB)
pub const ALIGNMENT: usize = 256 * 1024;

/// Block layout offsets and sizes
pub const GATES_OFFSET: usize = 0;
pub const GATES_SIZE: usize = GATES_PER_BLOCK * GATE_SIZE; // 259,440 bytes
pub const TYPES_OFFSET: usize = GATES_SIZE; // 259,440
pub const TYPES_SIZE: usize = GATES_PER_BLOCK.div_ceil(8); // 2,703 bytes
pub const BLOCK_PADDING: usize = BLOCK_SIZE - GATES_SIZE - TYPES_SIZE; // 1 byte

/// Magic bytes for v5 format: "Zk2u"
pub const MAGIC: [u8; 4] = crate::v5::MAGIC;

/// Version number
pub const VERSION: u8 = crate::v5::VERSION;

/// Format type for v5c
pub const FORMAT_TYPE: u8 = 0x02;

/// Secondary magic bytes: "nkas"
pub const NKAS: [u8; 4] = [0x6E, 0x6B, 0x61, 0x73];

/// Maximum addressable memory (2^32)
pub const MAX_MEMORY_ADDRESS: u64 = 4_294_967_296;

/// Disk I/O buffer size (for integration with io_uring triple buffering)
pub const DISK_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Number of processing blocks per disk buffer
pub const BLOCKS_PER_DISK_BUFFER: usize = DISK_BUFFER_SIZE / BLOCK_SIZE; // 16

/// Expected ciphertext vector capacity per block (for garbling)
pub const CIPHERTEXTS_PER_BLOCK: usize = GATES_PER_BLOCK;

/// Expected ciphertext vector size in bytes (16 bytes per ciphertext)
pub const CIPHERTEXT_VEC_SIZE: usize = CIPHERTEXTS_PER_BLOCK * 16; // 346,320 bytes

// Compile-time assertions
const _: () = assert!(GATES_SIZE + TYPES_SIZE + BLOCK_PADDING == BLOCK_SIZE);
const _: () = assert!(GATES_SIZE.is_multiple_of(8), "Gates size must be 8-byte aligned");
const _: () = assert!(TYPES_OFFSET.is_multiple_of(8), "Types must start at 8-byte boundary");
const _: () = assert!(BLOCKS_PER_DISK_BUFFER == 16);
const _: () = assert!(
    CIPHERTEXT_VEC_SIZE < 512 * 1024,
    "Ciphertext vec should be < 512 KB"
);
const _: () = assert!(
    GATES_SIZE + CIPHERTEXT_VEC_SIZE < 1024 * 1024,
    "Gate block + ciphertext vec must fit in 1 MB L2"
);

/// Header structure for v5c format (88 bytes)
///
/// The header is padded to 256 KiB in the file for alignment.
#[derive(Debug, Clone, Copy)]
pub struct HeaderV5c {
    // Identification (10 bytes)
    pub magic: [u8; 4],  // "Zk2u" (0x5A6B3275)
    pub version: u8,     // Always 0x05
    pub format_type: u8, // Always 0x02 for v5c
    pub nkas: [u8; 4],   // "nkas" (0x6E6B6173)

    // Checksum (32 bytes)
    pub checksum: [u8; 32], // BLAKE3 hash

    // Circuit metadata (46 bytes)
    pub xor_gates: u64,      // Total XOR gates (little-endian)
    pub and_gates: u64,      // Total AND gates (little-endian)
    pub primary_inputs: u64, // Number of primary inputs
    pub scratch_space: u64,  // Maximum scratch space entries needed
    pub num_outputs: u64,    // Number of outputs
    pub reserved2: [u8; 6],  // Reserved for future use
}

impl HeaderV5c {
    /// Create a new header with default values
    pub fn new() -> Self {
        HeaderV5c {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE,
            nkas: NKAS,
            checksum: [0; 32],
            xor_gates: 0,
            and_gates: 0,
            primary_inputs: 0,
            scratch_space: 0,
            num_outputs: 0,
            reserved2: [0; 6],
        }
    }

    /// Get total number of gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates.saturating_add(self.and_gates)
    }

    /// Get the number of full blocks
    pub fn num_full_blocks(&self) -> u64 {
        self.total_gates() / GATES_PER_BLOCK as u64
    }

    /// Get the number of gates in the partial block (0 if none)
    pub fn partial_block_gates(&self) -> usize {
        (self.total_gates() % GATES_PER_BLOCK as u64) as usize
    }

    /// Get total number of blocks (including partial)
    pub fn total_blocks(&self) -> u64 {
        self.total_gates().div_ceil(GATES_PER_BLOCK as u64)
    }

    /// Validate the header
    pub fn validate(&self) -> Result<(), String> {
        // Check magic bytes
        if self.magic != MAGIC {
            return Err(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                MAGIC, self.magic
            ));
        }

        // Check version
        if self.version != VERSION {
            return Err(format!(
                "Invalid version: expected {}, got {}",
                VERSION, self.version
            ));
        }

        // Check format type
        if self.format_type != FORMAT_TYPE {
            return Err(format!(
                "Invalid format type: expected {}, got {}",
                FORMAT_TYPE, self.format_type
            ));
        }

        // Check nkas field
        if self.nkas != NKAS {
            return Err(format!(
                "Invalid nkas bytes: expected {:?}, got {:?}",
                NKAS, self.nkas
            ));
        }

        // Check reserved2 field
        if self.reserved2 != [0; 6] {
            return Err(format!(
                "Reserved2 field must be zero, got {:?}",
                self.reserved2
            ));
        }

        // Check for gate count overflow
        if self.total_gates() == u64::MAX {
            return Err("Total gate count would overflow".to_string());
        }

        // Validate scratch space
        if self.scratch_space > MAX_MEMORY_ADDRESS {
            return Err(format!(
                "Scratch space {} exceeds maximum addressable memory {}",
                self.scratch_space, MAX_MEMORY_ADDRESS
            ));
        }

        Ok(())
    }

    /// Convert header to byte array for writing (packed format)
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        let mut offset = 0;

        // magic (4 bytes)
        bytes[offset..offset + 4].copy_from_slice(&self.magic);
        offset += 4;

        // version (1 byte)
        bytes[offset] = self.version;
        offset += 1;

        // format_type (1 byte)
        bytes[offset] = self.format_type;
        offset += 1;

        // nkas (4 bytes)
        bytes[offset..offset + 4].copy_from_slice(&self.nkas);
        offset += 4;

        // checksum (32 bytes)
        bytes[offset..offset + 32].copy_from_slice(&self.checksum);
        offset += 32;

        // xor_gates (8 bytes, little-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.xor_gates.to_le_bytes());
        offset += 8;

        // and_gates (8 bytes, little-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.and_gates.to_le_bytes());
        offset += 8;

        // primary_inputs (8 bytes, little-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.primary_inputs.to_le_bytes());
        offset += 8;

        // scratch_space (8 bytes, little-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.scratch_space.to_le_bytes());
        offset += 8;

        // num_outputs (8 bytes, little-endian)
        bytes[offset..offset + 8].copy_from_slice(&self.num_outputs.to_le_bytes());
        offset += 8;

        // reserved2 (6 bytes)
        bytes[offset..offset + 6].copy_from_slice(&self.reserved2);

        bytes
    }

    /// Create header from byte array (packed format)
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "insufficient bytes for header",
            ));
        }

        let mut offset = 0;

        // magic (4 bytes)
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        // version (1 byte)
        let version = bytes[offset];
        offset += 1;

        // format_type (1 byte)
        let format_type = bytes[offset];
        offset += 1;

        // nkas (4 bytes)
        let mut nkas = [0u8; 4];
        nkas.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        // checksum (32 bytes)
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // xor_gates (8 bytes, little-endian)
        let xor_gates = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // and_gates (8 bytes, little-endian)
        let and_gates = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // primary_inputs (8 bytes, little-endian)
        let primary_inputs = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // scratch_space (8 bytes, little-endian)
        let scratch_space = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // num_outputs (8 bytes, little-endian)
        let num_outputs = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // reserved2 (6 bytes)
        let mut reserved2 = [0u8; 6];
        reserved2.copy_from_slice(&bytes[offset..offset + 6]);

        let header = Self {
            magic,
            version,
            format_type,
            nkas,
            checksum,
            xor_gates,
            and_gates,
            primary_inputs,
            scratch_space,
            num_outputs,
            reserved2,
        };

        header
            .validate()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        Ok(header)
    }
}

impl Default for HeaderV5c {
    fn default() -> Self {
        Self::new()
    }
}

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

/// A 256 KiB block containing gates and their types
///
/// This struct is #[repr(C)] with exact layout matching the file format.
/// It can be safely cast from aligned byte buffers.
#[repr(C)]
pub struct Block {
    /// Gates in execution order (21,620 gates × 12 bytes = 259,440 bytes)
    pub gates: [GateV5c; GATES_PER_BLOCK],
    /// Gate types bit-packed (2,703 bytes)
    /// Bit N corresponds to gates[N]: 0 = XOR, 1 = AND
    pub types: [u8; TYPES_SIZE],
    /// Padding to reach exactly 256 KiB (1 byte)
    pub _padding: [u8; BLOCK_PADDING],
}

impl Block {
    /// Get the type of a specific gate in this block
    ///
    /// Returns true for AND gate, false for XOR gate
    #[inline]
    pub fn gate_type(&self, index: usize) -> GateType {
        debug_assert!(index < GATES_PER_BLOCK);
        if get_gate_type(&self.types, index) {
            GateType::AND
        } else {
            GateType::XOR
        }
    }

    /// Get the number of valid gates in this block
    ///
    /// For full blocks this is GATES_PER_BLOCK (21,620).
    /// For the last block it may be less.
    #[inline]
    pub fn num_gates(&self, total_gates: u64, block_index: usize) -> usize {
        let gates_before = block_index * GATES_PER_BLOCK;
        let remaining = total_gates.saturating_sub(gates_before as u64) as usize;
        remaining.min(GATES_PER_BLOCK)
    }
}

/// Helper function to get gate type from bit-packed types array
///
/// Returns true for AND gate, false for XOR gate
#[inline]
pub fn get_gate_type(types: &[u8], gate_index: usize) -> bool {
    let byte_index = gate_index / 8;
    let bit_index = gate_index % 8;
    ((types[byte_index] >> bit_index) & 1) != 0
}

/// Helper function to set gate type in bit-packed types array
///
/// gate_type: true for AND gate, false for XOR gate
#[inline]
pub fn set_gate_type(types: &mut [u8], gate_index: usize, gate_type: bool) {
    let byte_index = gate_index / 8;
    let bit_index = gate_index % 8;
    if gate_type {
        types[byte_index] |= 1 << bit_index;
    } else {
        types[byte_index] &= !(1 << bit_index);
    }
}

/// Calculate padded size for alignment to 256 KiB boundaries
pub fn padded_size(size: usize) -> usize {
    size.div_ceil(ALIGNMENT) * ALIGNMENT
}

/// Calculate the file size for a circuit
pub fn calculate_file_size(total_gates: u64, num_outputs: u64) -> u64 {
    let header_padded = ALIGNMENT as u64;
    let outputs_size = num_outputs * OUTPUT_ENTRY_SIZE as u64;
    let outputs_padded = padded_size(outputs_size as usize) as u64;
    let num_blocks = total_gates.div_ceil(GATES_PER_BLOCK as u64);
    let blocks_size = num_blocks * BLOCK_SIZE as u64;

    header_padded + outputs_padded + blocks_size
}

/// Statistics about a written circuit
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub scratch_space: u64,
    pub num_outputs: u64,
    pub checksum: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify block size
        assert_eq!(BLOCK_SIZE, 262144);
        assert_eq!(GATES_PER_BLOCK, 21620);
        assert_eq!(GATE_SIZE, 12);

        // Verify block layout
        assert_eq!(GATES_SIZE, 259440);
        assert_eq!(TYPES_SIZE, 2703);
        assert_eq!(BLOCK_PADDING, 1);
        assert_eq!(GATES_SIZE + TYPES_SIZE + BLOCK_PADDING, BLOCK_SIZE);

        // Verify alignment
        assert_eq!(ALIGNMENT, 262144);
        assert_eq!(BLOCKS_PER_DISK_BUFFER, 16);

        // Verify L2 cache fit
        let total_working_set = GATES_SIZE + CIPHERTEXT_VEC_SIZE;
        assert!(
            total_working_set < 1024 * 1024,
            "Gate block + ciphertext vec = {} bytes, should fit in 1 MB L2",
            total_working_set
        );
    }

    #[test]
    fn test_header_size() {
        assert_eq!(std::mem::size_of::<HeaderV5c>(), HEADER_SIZE);
    }

    #[test]
    fn test_gate_size() {
        assert_eq!(std::mem::size_of::<GateV5c>(), GATE_SIZE);
        assert_eq!(std::mem::align_of::<GateV5c>(), 4);
    }

    #[test]
    fn test_block_size() {
        assert_eq!(std::mem::size_of::<Block>(), BLOCK_SIZE);
    }

    #[test]
    fn test_header_validation() {
        let mut header = HeaderV5c::new();
        assert!(header.validate().is_ok());

        // Test invalid magic
        header.magic = [0, 0, 0, 0];
        assert!(header.validate().is_err());
        header.magic = MAGIC;

        // Test invalid version
        header.version = 0x04;
        assert!(header.validate().is_err());
        header.version = VERSION;

        // Test invalid format type
        header.format_type = 0x00;
        assert!(header.validate().is_err());
        header.format_type = FORMAT_TYPE;

        // Test scratch space overflow (MUST use write_unaligned for packed struct)
        unsafe {
            std::ptr::write_unaligned(
                std::ptr::addr_of_mut!(header.scratch_space),
                MAX_MEMORY_ADDRESS + 1,
            );
        }
        assert!(header.validate().is_err());
        unsafe {
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.scratch_space), 1000);
        }

        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_gate_validation() {
        let gate = GateV5c::new(100, 200, 300);
        assert!(gate.validate(1000).is_ok());
        assert!(gate.validate(250).is_err()); // out exceeds
    }

    #[test]
    fn test_gate_serialization() {
        let gate = GateV5c::new(0x12345678, 0xABCDEF01, 0xDEADBEEF);
        let bytes = gate.to_bytes();
        let gate2 = GateV5c::from_bytes(&bytes);
        assert_eq!(gate, gate2);
    }

    #[test]
    fn test_gate_type_bits() {
        let mut types = vec![0u8; TYPES_SIZE];

        // Set some gate types
        set_gate_type(&mut types, 0, false); // XOR
        set_gate_type(&mut types, 1, true); // AND
        set_gate_type(&mut types, 7, true); // AND
        set_gate_type(&mut types, 8, false); // XOR
        set_gate_type(&mut types, 21619, true); // AND (last gate)

        // Verify
        assert!(!get_gate_type(&types, 0));
        assert!(get_gate_type(&types, 1));
        assert!(get_gate_type(&types, 7));
        assert!(!get_gate_type(&types, 8));
        assert!(get_gate_type(&types, 21619));
    }

    #[test]
    fn test_header_total_gates() {
        let mut header = HeaderV5c::new();
        // MUST use write_unaligned for packed struct fields
        unsafe {
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.xor_gates), 1000);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.and_gates), 2000);
        }
        assert_eq!(header.total_gates(), 3000);
    }

    #[test]
    fn test_header_blocks() {
        let mut header = HeaderV5c::new();
        // MUST use write_unaligned for packed struct fields
        unsafe {
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.xor_gates), 50000);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.and_gates), 50000);
        }

        let total = header.total_gates(); // 100,000
        assert_eq!(total, 100000);
        assert_eq!(header.num_full_blocks(), 4); // 4 × 21,620 = 86,480
        assert_eq!(header.partial_block_gates(), 13520); // 100,000 - 86,480
        assert_eq!(header.total_blocks(), 5);
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(padded_size(88), ALIGNMENT); // Header
        assert_eq!(padded_size(4000), ALIGNMENT); // Small outputs
        assert_eq!(padded_size(ALIGNMENT), ALIGNMENT); // Exact fit
        assert_eq!(padded_size(ALIGNMENT + 1), ALIGNMENT * 2); // Just over
    }

    #[test]
    fn test_calculate_file_size() {
        // Small circuit: 1000 gates, 10 outputs
        let size = calculate_file_size(1000, 10);
        let expected = ALIGNMENT as u64 + // header
            ALIGNMENT as u64 + // outputs
            BLOCK_SIZE as u64; // 1 block
        assert_eq!(size, expected);

        // Exact block boundary: 21,620 gates
        let size = calculate_file_size(21620, 10);
        let expected = ALIGNMENT as u64 + // header
            ALIGNMENT as u64 + // outputs
            BLOCK_SIZE as u64; // 1 block (exact)
        assert_eq!(size, expected);

        // Two blocks: 21,621 gates
        let size = calculate_file_size(21621, 10);
        let expected = ALIGNMENT as u64 + // header
            ALIGNMENT as u64 + // outputs
            2 * BLOCK_SIZE as u64; // 2 blocks
        assert_eq!(size, expected);
    }

    #[test]
    fn test_header_roundtrip() {
        let mut header = HeaderV5c::new();
        // MUST use write_unaligned for packed struct fields
        unsafe {
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.xor_gates), 1234567);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.and_gates), 7654321);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.primary_inputs), 1000);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.scratch_space), 10000000);
            std::ptr::write_unaligned(std::ptr::addr_of_mut!(header.num_outputs), 100);
        }
        header.checksum = [0x42; 32]; // Arrays are always aligned

        let bytes = header.to_bytes();
        let header2 = HeaderV5c::from_bytes(&bytes).unwrap();

        assert_eq!(header.magic, header2.magic);
        assert_eq!(header.version, header2.version);
        assert_eq!(header.format_type, header2.format_type);

        // Use read_unaligned for packed struct fields
        unsafe {
            assert_eq!(
                std::ptr::read_unaligned(std::ptr::addr_of!(header.xor_gates)),
                std::ptr::read_unaligned(std::ptr::addr_of!(header2.xor_gates))
            );
            assert_eq!(
                std::ptr::read_unaligned(std::ptr::addr_of!(header.and_gates)),
                std::ptr::read_unaligned(std::ptr::addr_of!(header2.and_gates))
            );
            assert_eq!(
                std::ptr::read_unaligned(std::ptr::addr_of!(header.primary_inputs)),
                std::ptr::read_unaligned(std::ptr::addr_of!(header2.primary_inputs))
            );
            assert_eq!(
                std::ptr::read_unaligned(std::ptr::addr_of!(header.scratch_space)),
                std::ptr::read_unaligned(std::ptr::addr_of!(header2.scratch_space))
            );
            assert_eq!(
                std::ptr::read_unaligned(std::ptr::addr_of!(header.num_outputs)),
                std::ptr::read_unaligned(std::ptr::addr_of!(header2.num_outputs))
            );
        }
        assert_eq!(header.checksum, header2.checksum);
    }
}

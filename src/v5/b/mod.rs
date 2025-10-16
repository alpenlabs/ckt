//! CKT Format v5b - Production format with memory addresses and level organization
//!
//! This module implements the v5b variant of the CKT format specification.
//! v5b is the production format with:
//! - 24-bit memory addresses (not wire IDs)
//! - Level-based organization for parallel evaluation
//! - 504 gates per block (9 bytes/gate exactly)
//! - No credits field (memory management already resolved)
//! - Gate types inferred from position (first N are XOR, rest are AND)

use std::io::{self, Write};

// pub mod reader;
pub mod reader;
pub mod writer;

#[cfg(test)]
pub mod integration;

/// Number of gates per block in v5b format
/// 504 = 21 × 24, allowing 21 gates per AVX-512 operation
pub const GATES_PER_BLOCK: usize = 504;

/// Size of packed in1 stream in bytes (504 × 24 bits)
pub const IN1_STREAM_SIZE: usize = (GATES_PER_BLOCK * 24) / 8; // 1512 bytes

/// Size of packed in2 stream in bytes (504 × 24 bits)
pub const IN2_STREAM_SIZE: usize = (GATES_PER_BLOCK * 24) / 8; // 1512 bytes

/// Size of packed out stream in bytes (504 × 24 bits)
pub const OUT_STREAM_SIZE: usize = (GATES_PER_BLOCK * 24) / 8; // 1512 bytes

/// Total size of a gate block in v5b format
pub const BLOCK_SIZE: usize = IN1_STREAM_SIZE + IN2_STREAM_SIZE + OUT_STREAM_SIZE; // 4536 bytes

/// Size of the v5b header in bytes
pub const HEADER_SIZE: usize = 88;

/// Size of each output entry in bytes (24 bits)
pub const OUTPUT_ENTRY_SIZE: usize = 3;

/// Size of a level header in bytes
pub const LEVEL_HEADER_SIZE: usize = 8;

/// Maximum addressable memory (2^24)
pub const MAX_MEMORY_ADDRESS: u32 = 16_777_216;

/// AVX-512 alignment requirement
pub const ALIGNMENT: usize = 64;

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
        if scratch_space > MAX_MEMORY_ADDRESS as u64 {
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

/// A single gate in v5b format (simplified from v5a)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateV5b {
    pub in1: u32, // 24-bit memory address (upper 8 bits must be 0)
    pub in2: u32, // 24-bit memory address (upper 8 bits must be 0)
    pub out: u32, // 24-bit memory address (upper 8 bits must be 0)
                  // No credits field - memory management already resolved
                  // No gate_type field - determined by position in level
}

impl GateV5b {
    /// Create a new gate
    pub fn new(in1: u32, in2: u32, out: u32) -> Result<Self, String> {
        // Validate 24-bit addresses
        if in1 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in1 address {} exceeds 24-bit maximum", in1));
        }
        if in2 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in2 address {} exceeds 24-bit maximum", in2));
        }
        if out >= MAX_MEMORY_ADDRESS {
            return Err(format!("out address {} exceeds 24-bit maximum", out));
        }

        Ok(GateV5b { in1, in2, out })
    }

    /// Check if this gate represents a valid operation
    pub fn validate(&self) -> Result<(), String> {
        if self.in1 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in1 address {} exceeds maximum", self.in1));
        }
        if self.in2 >= MAX_MEMORY_ADDRESS {
            return Err(format!("in2 address {} exceeds maximum", self.in2));
        }
        if self.out >= MAX_MEMORY_ADDRESS {
            return Err(format!("out address {} exceeds maximum", self.out));
        }
        Ok(())
    }
}

/// Gate block structure for v5b (Structure-of-Arrays layout)
#[repr(C, align(64))]
pub struct BlockV5b {
    pub in1_stream: [u8; IN1_STREAM_SIZE], // 1512 bytes
    pub in2_stream: [u8; IN2_STREAM_SIZE], // 1512 bytes
    pub out_stream: [u8; OUT_STREAM_SIZE], // 1512 bytes
}

impl BlockV5b {
    /// Create a new empty block
    pub fn new() -> Self {
        BlockV5b {
            in1_stream: [0; IN1_STREAM_SIZE],
            in2_stream: [0; IN2_STREAM_SIZE],
            out_stream: [0; OUT_STREAM_SIZE],
        }
    }

    /// Pack a 24-bit value into the stream at the given gate index
    #[inline]
    pub fn pack_24bit(stream: &mut [u8], gate_idx: usize, value: u32) {
        debug_assert!(value < MAX_MEMORY_ADDRESS, "Value exceeds 24 bits");
        debug_assert!(gate_idx < GATES_PER_BLOCK, "Gate index out of bounds");

        let bit_offset = gate_idx * 24;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            // Aligned case - direct write
            stream[byte_offset] = (value & 0xFF) as u8;
            stream[byte_offset + 1] = ((value >> 8) & 0xFF) as u8;
            stream[byte_offset + 2] = ((value >> 16) & 0xFF) as u8;
        } else {
            // Unaligned case - need to handle bit shifting
            let mut bytes = [0u8; 4];
            bytes[0..3].copy_from_slice(&value.to_le_bytes()[0..3]);

            let shifted = u32::from_le_bytes(bytes) << bit_shift;
            let shifted_bytes = shifted.to_le_bytes();

            // Preserve existing bits and merge
            stream[byte_offset] = (stream[byte_offset] & ((1 << bit_shift) - 1)) | shifted_bytes[0];
            stream[byte_offset + 1] = shifted_bytes[1];
            stream[byte_offset + 2] = shifted_bytes[2];
            if byte_offset + 3 < stream.len() {
                stream[byte_offset + 3] =
                    (stream[byte_offset + 3] & (0xFF << (8 - bit_shift))) | shifted_bytes[3];
            }
        }
    }

    /// Unpack a 24-bit value from the stream at the given gate index
    #[inline]
    pub fn unpack_24bit(stream: &[u8], gate_idx: usize) -> u32 {
        debug_assert!(gate_idx < GATES_PER_BLOCK, "Gate index out of bounds");

        let bit_offset = gate_idx * 24;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            // Aligned case - direct read
            let mut bytes = [0u8; 4];
            bytes[0..3].copy_from_slice(&stream[byte_offset..byte_offset + 3]);
            u32::from_le_bytes(bytes) & 0xFFFFFF
        } else {
            // Unaligned case - need to handle bit shifting
            let mut bytes = [0u8; 4];
            let end = std::cmp::min(byte_offset + 4, stream.len());
            let len = end - byte_offset;
            bytes[0..len].copy_from_slice(&stream[byte_offset..end]);

            let value = u32::from_le_bytes(bytes) >> bit_shift;
            value & 0xFFFFFF
        }
    }

    /// Pack gates into the block
    pub fn pack_gates(&mut self, gates: &[GateV5b], start_idx: usize) {
        let end_idx = std::cmp::min(start_idx + GATES_PER_BLOCK, start_idx + gates.len());

        for (block_idx, gate_idx) in (start_idx..end_idx).enumerate() {
            let gate = &gates[gate_idx - start_idx];
            Self::pack_24bit(&mut self.in1_stream, block_idx, gate.in1);
            Self::pack_24bit(&mut self.in2_stream, block_idx, gate.in2);
            Self::pack_24bit(&mut self.out_stream, block_idx, gate.out);
        }
    }

    /// Unpack gates from the block
    pub fn unpack_gates(&self, num_gates: usize) -> Vec<GateV5b> {
        let mut gates = Vec::with_capacity(num_gates);

        for i in 0..num_gates {
            let in1 = Self::unpack_24bit(&self.in1_stream, i);
            let in2 = Self::unpack_24bit(&self.in2_stream, i);
            let out = Self::unpack_24bit(&self.out_stream, i);

            gates.push(GateV5b { in1, in2, out });
        }

        gates
    }

    /// Write the block to a writer
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.in1_stream)?;
        writer.write_all(&self.in2_stream)?;
        writer.write_all(&self.out_stream)?;
        Ok(())
    }
}

impl Default for BlockV5b {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify block size calculation
        assert_eq!(IN1_STREAM_SIZE, 1512);
        assert_eq!(IN2_STREAM_SIZE, 1512);
        assert_eq!(OUT_STREAM_SIZE, 1512);
        assert_eq!(BLOCK_SIZE, 4536);

        // Verify gates per block
        assert_eq!(GATES_PER_BLOCK, 504);

        // Verify 504 = 21 × 24
        assert_eq!(504, 21 * 24);

        // Verify exact 9 bytes per gate
        assert_eq!(BLOCK_SIZE / GATES_PER_BLOCK, 9);
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
        header.scratch_space = MAX_MEMORY_ADDRESS as u64 + 1;
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_gate_validation() {
        // Valid gate
        let gate = GateV5b::new(100, 200, 300).unwrap();
        assert!(gate.validate().is_ok());

        // Invalid addresses
        assert!(GateV5b::new(MAX_MEMORY_ADDRESS, 200, 300).is_err());
        assert!(GateV5b::new(100, MAX_MEMORY_ADDRESS, 300).is_err());
        assert!(GateV5b::new(100, 200, MAX_MEMORY_ADDRESS).is_err());
    }

    #[test]
    fn test_24bit_packing() {
        let mut block = BlockV5b::new();

        // Test aligned packing (gate 0)
        BlockV5b::pack_24bit(&mut block.in1_stream, 0, 0x123456);
        assert_eq!(BlockV5b::unpack_24bit(&block.in1_stream, 0), 0x123456);

        // Test unaligned packing (gate 1)
        BlockV5b::pack_24bit(&mut block.in1_stream, 1, 0xABCDEF);
        assert_eq!(BlockV5b::unpack_24bit(&block.in1_stream, 1), 0xABCDEF);

        // Verify gate 0 is unchanged
        assert_eq!(BlockV5b::unpack_24bit(&block.in1_stream, 0), 0x123456);

        // Test multiple gates
        for i in 0..21 {
            // Test first AVX-512 chunk
            let value = (i as u32 + 1) * 0x1111;
            BlockV5b::pack_24bit(&mut block.in2_stream, i, value);
        }

        for i in 0..21 {
            let expected = (i as u32 + 1) * 0x1111;
            assert_eq!(BlockV5b::unpack_24bit(&block.in2_stream, i), expected);
        }
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

    #[test]
    fn test_block_pack_unpack() {
        let gates = vec![
            GateV5b::new(10, 20, 30).unwrap(),
            GateV5b::new(40, 50, 60).unwrap(),
            GateV5b::new(70, 80, 90).unwrap(),
            GateV5b::new(0xFFFFFF - 1, 0xFFFFFF - 2, 0xFFFFFF - 3).unwrap(),
        ];

        let mut block = BlockV5b::new();
        block.pack_gates(&gates, 0);

        let unpacked = block.unpack_gates(gates.len());
        assert_eq!(gates, unpacked);
    }

    #[test]
    fn bench_decode_comparison() {
        use std::time::Instant;

        // Create a full block with 504 gates
        let mut block = BlockV5b::new();
        let mut gates = Vec::with_capacity(GATES_PER_BLOCK);

        // Fill with realistic data
        for i in 0..GATES_PER_BLOCK {
            let in1 = ((i * 7 + 2) % MAX_MEMORY_ADDRESS as usize) as u32;
            let in2 = ((i * 5 + 3) % MAX_MEMORY_ADDRESS as usize) as u32;
            let out = ((i + 100) % MAX_MEMORY_ADDRESS as usize) as u32;
            gates.push(GateV5b { in1, in2, out });
        }

        // Pack the gates into the block
        for (i, gate) in gates.iter().enumerate() {
            BlockV5b::pack_24bit(&mut block.in1_stream, i, gate.in1);
            BlockV5b::pack_24bit(&mut block.in2_stream, i, gate.in2);
            BlockV5b::pack_24bit(&mut block.out_stream, i, gate.out);
        }

        const ITERATIONS: usize = 10000;

        // Benchmark scalar unpacking
        println!("\n=== v5b Decode Performance Benchmark ===");
        println!("Block size: {} gates", GATES_PER_BLOCK);
        println!("Iterations: {}", ITERATIONS);

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut unpacked = Vec::with_capacity(GATES_PER_BLOCK);
            for i in 0..GATES_PER_BLOCK {
                let in1 = BlockV5b::unpack_24bit(&block.in1_stream, i);
                let in2 = BlockV5b::unpack_24bit(&block.in2_stream, i);
                let out = BlockV5b::unpack_24bit(&block.out_stream, i);
                unpacked.push(GateV5b { in1, in2, out });
            }
        }
        let scalar_time = start.elapsed();

        let scalar_ns_per_gate =
            scalar_time.as_nanos() as f64 / (ITERATIONS as f64 * GATES_PER_BLOCK as f64);
        let scalar_gates_per_sec = 1_000_000_000.0 / scalar_ns_per_gate;
        let scalar_mb_per_sec = scalar_gates_per_sec * 9.0 / (1024.0 * 1024.0);

        println!("\nScalar Decoding:");
        println!("  Time: {:?}", scalar_time);
        println!("  Per gate: {:.2} ns", scalar_ns_per_gate);
        println!("  Gates/sec: {:.2}M", scalar_gates_per_sec / 1_000_000.0);
        println!("  Throughput: {:.2} MB/s", scalar_mb_per_sec);

        println!("\n=== End Benchmark ===\n");
    }
}

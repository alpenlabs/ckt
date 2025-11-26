use crate::GateType;

use super::constants::*;
use super::gate::GateV5c;

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

/// Get the number of valid gates in this block
///
/// For full blocks this is GATES_PER_BLOCK (21,620).
/// For the last block it may be less.
#[inline]
pub fn get_block_num_gates(total_gates: u64, block_index: usize) -> usize {
    let gates_before = block_index * GATES_PER_BLOCK;
    let remaining = total_gates.saturating_sub(gates_before as u64) as usize;
    remaining.min(GATES_PER_BLOCK)
}

/// Calculate padded size for alignment to 256 KiB boundaries
pub fn padded_size(size: usize) -> usize {
    ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT
}

/// Calculate the file size for a circuit
pub fn calculate_file_size(total_gates: u64, num_outputs: u64) -> u64 {
    let header_padded = ALIGNMENT as u64;
    let outputs_size = num_outputs * OUTPUT_ENTRY_SIZE as u64;
    let outputs_padded = padded_size(outputs_size as usize) as u64;
    let num_blocks = (total_gates + GATES_PER_BLOCK as u64 - 1) / GATES_PER_BLOCK as u64;
    let blocks_size = num_blocks * BLOCK_SIZE as u64;

    header_padded + outputs_padded + blocks_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v5::c::HeaderV5c;

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
        assert_eq!(get_gate_type(&types, 0), false);
        assert_eq!(get_gate_type(&types, 1), true);
        assert_eq!(get_gate_type(&types, 7), true);
        assert_eq!(get_gate_type(&types, 8), false);
        assert_eq!(get_gate_type(&types, 21619), true);
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

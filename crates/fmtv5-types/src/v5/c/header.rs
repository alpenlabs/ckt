use std::io::{self, Error, ErrorKind};

use super::constants::*;

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

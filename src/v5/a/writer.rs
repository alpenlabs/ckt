//! High-performance v5a writer using monoio io_uring
//!
//! This implementation provides a clean API for writing v5a format circuits:
//! - Automatic buffering of gates into 256-gate blocks
//! - Efficient bit packing with Structure-of-Arrays layout
//! - Direct async I/O with monoio
//! - BLAKE3 checksum calculation following spec order

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

// Re-use constants and types from reader
use super::reader::{
    BLOCK_SIZE_V5A, FORMAT_TYPE_A, GATES_PER_BLOCK, GateV5a, HeaderV5a, MAGIC, VERSION,
};

/// Block builder that accumulates gates and encodes them into v5a format
struct BlockBuilder {
    // Structure-of-Arrays buffers
    in1_values: Vec<u64>,
    in2_values: Vec<u64>,
    out_values: Vec<u64>,
    credits: Vec<u32>,
    gate_types: Vec<bool>,
}

impl BlockBuilder {
    fn new() -> Self {
        Self {
            in1_values: Vec::with_capacity(GATES_PER_BLOCK),
            in2_values: Vec::with_capacity(GATES_PER_BLOCK),
            out_values: Vec::with_capacity(GATES_PER_BLOCK),
            credits: Vec::with_capacity(GATES_PER_BLOCK),
            gate_types: Vec::with_capacity(GATES_PER_BLOCK),
        }
    }

    fn add_gate(&mut self, gate: GateV5a) -> Result<()> {
        // Validate wire IDs
        if gate.in1 > 0x3FFFFFFFF || gate.in2 > 0x3FFFFFFFF || gate.out > 0x3FFFFFFFF {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Wire ID exceeds 34-bit limit",
            ));
        }

        if gate.credits > 0xFFFFFF {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Credits exceed 24-bit limit",
            ));
        }

        self.in1_values.push(gate.in1);
        self.in2_values.push(gate.in2);
        self.out_values.push(gate.out);
        self.credits.push(gate.credits);
        self.gate_types.push(gate.gate_type);

        Ok(())
    }

    fn len(&self) -> usize {
        self.in1_values.len()
    }

    fn is_full(&self) -> bool {
        self.len() >= GATES_PER_BLOCK
    }

    fn clear(&mut self) {
        self.in1_values.clear();
        self.in2_values.clear();
        self.out_values.clear();
        self.credits.clear();
        self.gate_types.clear();
    }

    /// Encode the current gates into a v5a block
    fn encode(&self) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE_V5A];

        // Pad with zeros if not full
        let mut in1_padded = self.in1_values.clone();
        let mut in2_padded = self.in2_values.clone();
        let mut out_padded = self.out_values.clone();
        let mut credits_padded = self.credits.clone();

        in1_padded.resize(GATES_PER_BLOCK, 0);
        in2_padded.resize(GATES_PER_BLOCK, 0);
        out_padded.resize(GATES_PER_BLOCK, 0);
        credits_padded.resize(GATES_PER_BLOCK, 0);

        // Encode in1 values (34 bits each, packed)
        pack_34_bits(&in1_padded, &mut block[0..1088]);

        // Encode in2 values
        pack_34_bits(&in2_padded, &mut block[1088..2176]);

        // Encode out values
        pack_34_bits(&out_padded, &mut block[2176..3264]);

        // Encode credits (24 bits each, packed)
        pack_24_bits(&credits_padded, &mut block[3264..4032]);

        // Encode gate types as bit vector
        for (i, &gate_type) in self.gate_types.iter().enumerate() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if gate_type {
                block[4032 + byte_idx] |= 1 << bit_idx;
            }
        }
        // Remaining bits stay 0 for padding

        block
    }
}

/// Production circuit writer for v5a format
pub struct CircuitWriterV5a {
    /// File handle
    file: File,

    /// Current file offset for writing blocks
    current_offset: u64,

    /// Current block builder
    current_block: BlockBuilder,

    /// Circuit metadata
    primary_inputs: u64,
    outputs: Vec<u64>,
    xor_gates_written: u64,
    and_gates_written: u64,

    /// Checksum hasher
    hasher: Hasher,

    /// Path for finalization
    path: std::path::PathBuf,
}

impl CircuitWriterV5a {
    /// Create a new v5a writer
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        outputs: Vec<u64>,
    ) -> Result<Self> {
        let path = path.as_ref().to_owned();

        // Open file with O_DIRECT for optimal performance
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
        }

        let file = opts.open(&path).await?;

        // Calculate initial offsets
        let header_size = std::mem::size_of::<HeaderV5a>();
        let outputs_size = outputs.len() * 5; // 5 bytes per output
        let initial_offset = (header_size + outputs_size) as u64;

        // Write placeholder header and outputs
        let placeholder = vec![0u8; header_size + outputs_size];
        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        // Create hasher and start with outputs (spec step 1)
        let mut hasher = Hasher::new();
        for &output in &outputs {
            let mut bytes = [0u8; 5];
            bytes[..5].copy_from_slice(&output.to_le_bytes()[..5]);
            hasher.update(&bytes);
        }

        Ok(Self {
            file,
            current_offset: initial_offset,
            current_block: BlockBuilder::new(),
            primary_inputs,
            outputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            hasher,
            path,
        })
    }

    /// Write a single gate
    pub async fn write_gate(&mut self, gate: GateV5a) -> Result<()> {
        // Add to current block
        self.current_block.add_gate(gate)?;

        // Track gate type statistics
        match gate.gate_type {
            false => self.xor_gates_written += 1,
            true => self.and_gates_written += 1,
        }

        // Flush block if full
        if self.current_block.is_full() {
            self.flush_current_block().await?;
        }

        Ok(())
    }

    /// Write multiple gates efficiently
    pub async fn write_gates(&mut self, gates: &[GateV5a]) -> Result<()> {
        for &gate in gates {
            self.write_gate(gate).await?;
        }
        Ok(())
    }

    /// Flush the current block (internal method)
    async fn flush_current_block(&mut self) -> Result<()> {
        if self.current_block.len() == 0 {
            return Ok(());
        }

        // Encode the block
        let encoded = self.current_block.encode();

        // Hash the block (spec step 2)
        self.hasher.update(&encoded);

        // Write block to file
        let (res, _) = self.file.write_all_at(encoded, self.current_offset).await;
        res?;

        self.current_offset += BLOCK_SIZE_V5A as u64;

        // Clear block for next batch
        self.current_block.clear();

        Ok(())
    }

    /// Finalize the circuit file
    pub async fn finalize(mut self) -> Result<CircuitStats> {
        // Flush any remaining gates in the current block
        if self.current_block.len() > 0 {
            self.flush_current_block().await?;
        }

        // Sync the file to ensure all blocks are written
        self.file.sync_all().await?;

        // Hash header fields after checksum (spec step 3)
        self.hasher.update(&self.xor_gates_written.to_le_bytes());
        self.hasher.update(&self.and_gates_written.to_le_bytes());
        self.hasher.update(&self.primary_inputs.to_le_bytes());
        self.hasher.update(&self.outputs.len().to_le_bytes());

        // Compute final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Create the final header
        let header = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: *checksum_bytes,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
        };

        // Write the final header and outputs at the beginning of the file
        self.write_header_and_outputs(&header).await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
            checksum: *checksum_bytes,
        };

        Ok(stats)
    }

    /// Write header and outputs to the file
    async fn write_header_and_outputs(&self, header: &HeaderV5a) -> Result<()> {
        // Reopen file for updating header
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);

        let file = opts.open(&self.path).await?;

        // Write header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                header as *const _ as *const u8,
                std::mem::size_of::<HeaderV5a>(),
            )
        };

        let (res, _) = file.write_all_at(header_bytes.to_vec(), 0).await;
        res?;

        // Write outputs
        let outputs_offset = std::mem::size_of::<HeaderV5a>() as u64;
        let mut outputs_buffer = Vec::with_capacity(self.outputs.len() * 5);

        for &output in &self.outputs {
            let mut bytes = [0u8; 5];
            bytes[..5].copy_from_slice(&output.to_le_bytes()[..5]);
            outputs_buffer.extend_from_slice(&bytes);
        }

        let (res, _) = file.write_all_at(outputs_buffer, outputs_offset).await;
        res?;

        // Sync file
        file.sync_all().await?;

        Ok(())
    }
}

/// Circuit statistics returned after writing
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub num_outputs: u64,
    pub checksum: [u8; 32],
}

/// Pack 34-bit values into a byte array
fn pack_34_bits(values: &[u64], output: &mut [u8]) {
    let mut bit_offset = 0usize;

    for &value in values {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        // Ensure value fits in 34 bits
        let value = value & 0x3FFFFFFFF;

        if bit_shift == 0 {
            // Aligned case: can write directly
            if byte_offset + 4 < output.len() {
                output[byte_offset] = value as u8;
                output[byte_offset + 1] = (value >> 8) as u8;
                output[byte_offset + 2] = (value >> 16) as u8;
                output[byte_offset + 3] = (value >> 24) as u8;
                output[byte_offset + 4] = (value >> 32) as u8;
            }
        } else {
            // Unaligned case: need to split across bytes
            // A 34-bit value with bit_shift will span at most 6 bytes
            let shifted = value << bit_shift;
            let bytes = shifted.to_le_bytes();

            // Write the bytes, ORing with existing data
            if byte_offset < output.len() {
                output[byte_offset] |= bytes[0];
            }
            if byte_offset + 1 < output.len() {
                output[byte_offset + 1] |= bytes[1];
            }
            if byte_offset + 2 < output.len() {
                output[byte_offset + 2] |= bytes[2];
            }
            if byte_offset + 3 < output.len() {
                output[byte_offset + 3] |= bytes[3];
            }
            if byte_offset + 4 < output.len() {
                output[byte_offset + 4] |= bytes[4];
            }
            // May need a 6th byte for the remaining bits
            if byte_offset + 5 < output.len() && bytes[5] != 0 {
                output[byte_offset + 5] |= bytes[5];
            }
        }

        bit_offset += 34;
    }
}

/// Pack 24-bit values into a byte array
fn pack_24_bits(values: &[u32], output: &mut [u8]) {
    let mut bit_offset = 0usize;

    for &value in values {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        // Ensure value fits in 24 bits
        let value = value & 0xFFFFFF;

        if bit_shift == 0 {
            // Aligned case: can write directly
            if byte_offset + 2 < output.len() {
                output[byte_offset] = value as u8;
                output[byte_offset + 1] = (value >> 8) as u8;
                output[byte_offset + 2] = (value >> 16) as u8;
            }
        } else {
            // Unaligned case: need to split across bytes
            // A 24-bit value with bit_shift will span at most 4 bytes
            let shifted = (value as u32) << bit_shift;

            // Write the bytes, ORing with existing data
            if byte_offset < output.len() {
                output[byte_offset] |= shifted as u8;
            }
            if byte_offset + 1 < output.len() {
                output[byte_offset + 1] |= (shifted >> 8) as u8;
            }
            if byte_offset + 2 < output.len() {
                output[byte_offset + 2] |= (shifted >> 16) as u8;
            }
            // May need a 4th byte for the remaining bits
            if byte_offset + 3 < output.len() && (shifted >> 24) != 0 {
                output[byte_offset + 3] |= (shifted >> 24) as u8;
            }
        }

        bit_offset += 24;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pack_34_bits() {
        // Test aligned packing
        let values = vec![0x3FFFFFFFF, 0x123456789, 0xABCDEF012];
        let mut output = vec![0u8; 1088];
        pack_34_bits(&values, &mut output);

        // Verify first value (all bits set in 34-bit range)
        let first_bytes = &output[0..5];
        let first_value = u64::from_le_bytes([
            first_bytes[0],
            first_bytes[1],
            first_bytes[2],
            first_bytes[3],
            first_bytes[4],
            0,
            0,
            0,
        ]);
        assert_eq!(first_value & 0x3FFFFFFFF, 0x3FFFFFFFF);
    }

    #[test]
    fn test_pack_24_bits() {
        // Test aligned packing
        let values = vec![0xFFFFFF, 0x123456, 0xABCDEF];
        let mut output = vec![0u8; 768];
        pack_24_bits(&values, &mut output);

        // Verify first value
        let first_value = u32::from_le_bytes([output[0], output[1], output[2], 0]);
        assert_eq!(first_value, 0xFFFFFF);
    }

    #[test]
    fn test_block_builder() {
        let mut builder = BlockBuilder::new();

        // Add some gates
        let gate1 = GateV5a {
            in1: 2,
            in2: 3,
            out: 4,
            credits: 1,
            gate_type: false, // XOR
        };

        let gate2 = GateV5a {
            in1: 4,
            in2: 5,
            out: 6,
            credits: 2,
            gate_type: true, // AND
        };

        assert!(builder.add_gate(gate1).is_ok());
        assert!(builder.add_gate(gate2).is_ok());

        assert_eq!(builder.len(), 2);
        assert!(!builder.is_full());

        // Test encoding
        let encoded = builder.encode();
        assert_eq!(encoded.len(), BLOCK_SIZE_V5A);
    }

    #[test]
    fn test_pack_unpack_34_bits_round_trip() {
        // Helper function to extract 34-bit values
        fn extract_34_bits(data: &[u8], bit_offset: usize) -> u64 {
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;

            // Read 8 bytes (we need at most 5 for 34 bits + shift)
            let mut bytes = [0u8; 8];
            let to_copy = std::cmp::min(8, data.len() - byte_offset);
            bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);

            let value = u64::from_le_bytes(bytes);
            (value >> bit_shift) & 0x3FFFFFFFF
        }

        // Test various values including edge cases
        let test_values: Vec<u64> = vec![
            0,
            1,
            2,
            3,
            0xFF,
            0xFFFF,
            0xFFFFFF,
            0xFFFFFFFF,
            0x3FFFFFFFF, // Max 34-bit value
            100,
            101,
            102,
            103,
            104,
            0x123456789,
            0x2AAAAAAAA,
            0x155555555,
        ];

        // Pack all values
        let mut packed = vec![0u8; 1088]; // Space for 256 values
        pack_34_bits(&test_values, &mut packed);

        // Unpack and verify
        for (i, &expected) in test_values.iter().enumerate() {
            let bit_offset = i * 34;
            let actual = extract_34_bits(&packed, bit_offset);
            assert_eq!(
                actual, expected,
                "Value {} mismatch: expected {:#x}, got {:#x}",
                i, expected, actual
            );
        }
    }

    #[test]
    fn test_pack_unpack_full_block() {
        // Helper function to extract 34-bit values
        fn extract_34_bits(data: &[u8], bit_offset: usize) -> u64 {
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;

            let mut bytes = [0u8; 8];
            let to_copy = std::cmp::min(8, data.len() - byte_offset);
            bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);

            let value = u64::from_le_bytes(bytes);
            (value >> bit_shift) & 0x3FFFFFFFF
        }

        // Generate 256 test values
        let mut test_values = Vec::with_capacity(256);
        for i in 0..256 {
            // Use similar pattern as make_gate in integration tests
            let value = match i {
                0 => 2u64,
                1 => 3u64,
                2 => 4u64,
                3 => 5u64,
                _ => 100 + i as u64,
            };
            test_values.push(value);
        }

        // Pack all 256 values
        let mut packed = vec![0u8; 1088]; // Space for exactly 256 34-bit values
        pack_34_bits(&test_values, &mut packed);

        // Unpack and verify all 256 values
        for (i, &expected) in test_values.iter().enumerate() {
            let bit_offset = i * 34;
            let actual = extract_34_bits(&packed, bit_offset);
            assert_eq!(
                actual, expected,
                "Value {} mismatch at bit offset {}: expected {:#x}, got {:#x}",
                i, bit_offset, expected, actual
            );
        }

        // Also test that our writer's encoder produces correct results
        let mut builder = BlockBuilder::new();
        for i in 0..256 {
            let gate = GateV5a {
                in1: 2 + (i as u64 % 10),
                in2: 3 + (i as u64 % 8),
                out: 100 + i as u64,
                credits: 1 + (i as u32 % 100),
                gate_type: i % 3 == 0,
            };
            builder.add_gate(gate).unwrap();
        }

        let encoded = builder.encode();

        // Verify first few gates in the encoded block
        for i in 0..5 {
            let in1 = extract_34_bits(&encoded[0..1088], i * 34);
            let expected_in1 = 2 + (i as u64 % 10);
            assert_eq!(
                in1, expected_in1,
                "Gate {} in1 mismatch: expected {}, got {}",
                i, expected_in1, in1
            );
        }
    }

    #[monoio::test]
    async fn test_writer_basic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.v5a");

        let writer = CircuitWriterV5a::new(&path, 10, vec![100, 101, 102])
            .await
            .unwrap();

        let stats = writer.finalize().await.unwrap();

        assert_eq!(stats.total_gates, 0);
        assert_eq!(stats.primary_inputs, 10);
        assert_eq!(stats.num_outputs, 3);

        // Verify file exists
        assert!(path.exists());
    }

    #[monoio::test]
    async fn test_writer_with_gates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_gates.v5a");

        let mut writer = CircuitWriterV5a::new(&path, 2, vec![6]).await.unwrap();

        // Write a few gates
        let gates = vec![
            GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: 2,
                gate_type: false,
            },
            GateV5a {
                in1: 2,
                in2: 4,
                out: 5,
                credits: 1,
                gate_type: true,
            },
            GateV5a {
                in1: 4,
                in2: 5,
                out: 6,
                credits: 0,
                gate_type: false,
            },
        ];

        for gate in gates {
            writer.write_gate(gate).await.unwrap();
        }

        let stats = writer.finalize().await.unwrap();

        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
    }

    #[monoio::test]
    async fn test_writer_validation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_validation.v5a");

        let mut writer = CircuitWriterV5a::new(&path, 2, vec![]).await.unwrap();

        // Test wire ID validation
        let invalid_gate = GateV5a {
            in1: 0x400000000, // Exceeds 34-bit limit
            in2: 3,
            out: 4,
            credits: 1,
            gate_type: false,
        };

        assert!(writer.write_gate(invalid_gate).await.is_err());

        // Test credits validation
        let invalid_credits = GateV5a {
            in1: 2,
            in2: 3,
            out: 4,
            credits: 0x1000000, // Exceeds 24-bit limit
            gate_type: false,
        };

        assert!(writer.write_gate(invalid_credits).await.is_err());
    }
}

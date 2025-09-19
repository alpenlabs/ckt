use blake3::Hasher;
use cynosure::hints::{likely, unlikely};
use monoio::fs::File;
use std::io::Result;

use crate::GateType;
use crate::v4::b::{
    CircuitHeader, Gate, Level,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v4::{CircuitStats, FormatType, VERSION};

/// High-performance async writer for CKT v4b format using monoio
pub struct CircuitWriter {
    file: File,
    buffer: Vec<u8>,
    current_level: u32,
    primary_inputs: u64,
    outputs: Vec<u64>,
    xor_gates_written: u64,
    and_gates_written: u64,
    bytes_written: u64,
    hasher: Hasher,
    previous_output: u64,
}

impl CircuitWriter {
    /// Create a new v4b writer with the given primary inputs and output addresses
    pub async fn new(file: File, primary_inputs: u64, outputs: Vec<u64>) -> Result<Self> {
        // Previous output starts at 2 + primary_inputs (after constants and primary inputs)
        let previous_output = 2 + primary_inputs;

        // Calculate output addresses size
        let mut output_buffer = Vec::with_capacity(outputs.len() * 8);
        for &output_addr in &outputs {
            let varint = StandardVarInt::new(output_addr)?;
            let mut temp_buf = [0u8; 8];
            let size = varint.encode(&mut temp_buf)?;
            output_buffer.extend_from_slice(&temp_buf[..size]);
        }

        // Write placeholder header (74 bytes fixed)
        let placeholder = vec![0u8; CircuitHeader::FIXED_SIZE];
        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        let output_buffer_len = output_buffer.len();
        // Write output memory addresses
        let (res, _) = file
            .write_all_at(output_buffer, CircuitHeader::FIXED_SIZE as u64)
            .await;
        res?;

        Ok(Self {
            file,
            buffer: Vec::with_capacity(256 * 1024), // 256KB buffer for level data
            current_level: 1,                       // Start at level 1 (level 0 is implicit)
            primary_inputs,
            outputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            bytes_written: (CircuitHeader::FIXED_SIZE + output_buffer_len) as u64,
            hasher: Hasher::new(),
            previous_output,
        })
    }

    /// Write a complete level with memory-addressed gates
    pub async fn write_level(&mut self, level: &Level) -> Result<()> {
        if unlikely(level.is_empty()) {
            return Ok(());
        }

        // Write level header: num_xor with AND gate flag, optionally num_and
        let has_and_gates = !level.and_gates.is_empty();
        let num_xor_flagged =
            FlaggedVarInt::with_flag(level.xor_gates.len() as u64, has_and_gates)?;
        let mut temp_buf = [0u8; 8];
        let bytes_used = num_xor_flagged.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);
        self.hasher.update(&temp_buf[..bytes_used]);

        // Only write num_and if there are AND gates (flag optimization)
        if has_and_gates {
            let num_and_varint = StandardVarInt::new(level.and_gates.len() as u64)?;
            let bytes_used = num_and_varint.encode(&mut temp_buf)?;
            self.buffer.extend_from_slice(&temp_buf[..bytes_used]);
            self.hasher.update(&temp_buf[..bytes_used]);
        }

        // Write all XOR gates
        for gate in &level.xor_gates {
            self.write_gate(gate, GateType::XOR)?;
        }

        // Write all AND gates
        for gate in &level.and_gates {
            self.write_gate(gate, GateType::AND)?;
        }

        self.current_level += 1;

        // Flush buffer if it's getting large
        if unlikely(self.buffer.len() > 128 * 1024) {
            self.flush_buffer().await?;
        }

        Ok(())
    }

    /// Write a single gate with memory addresses
    fn write_gate(&mut self, gate: &Gate, gate_type: GateType) -> Result<()> {
        let mut temp_buf = [0u8; 24]; // Enough for 3 memory addresses

        // Encode input1 memory address
        let bytes1 =
            FlaggedVarInt::encode_memory_address(gate.in1, self.previous_output, &mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes1]);
        self.hasher.update(&temp_buf[..bytes1]);

        // Encode input2 memory address
        let bytes2 =
            FlaggedVarInt::encode_memory_address(gate.in2, self.previous_output, &mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes2]);
        self.hasher.update(&temp_buf[..bytes2]);

        // Encode output memory address
        let bytes3 =
            FlaggedVarInt::encode_memory_address(gate.out, self.previous_output, &mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes3]);
        self.hasher.update(&temp_buf[..bytes3]);

        // Update previous output for next gate
        self.previous_output = gate.out;

        // Track gate type counts
        match gate_type {
            GateType::XOR => self.xor_gates_written += 1,
            GateType::AND => self.and_gates_written += 1,
        }

        Ok(())
    }

    /// Write multiple levels in sequence
    pub async fn write_levels(&mut self, levels: &[Level]) -> Result<()> {
        for level in levels {
            self.write_level(level).await?;
        }
        Ok(())
    }

    /// Get current level
    pub fn current_level(&self) -> u32 {
        self.current_level
    }

    /// Get total gates written so far
    pub fn gates_written(&self) -> u64 {
        self.xor_gates_written + self.and_gates_written
    }

    /// Get XOR gates written so far
    pub fn xor_gates_written(&self) -> u64 {
        self.xor_gates_written
    }

    /// Get AND gates written so far
    pub fn and_gates_written(&self) -> u64 {
        self.and_gates_written
    }

    /// Flush the write buffer to file
    async fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            let buf = std::mem::take(&mut self.buffer);
            let (result, returned_buf) = self.file.write_all_at(buf, self.bytes_written).await;
            result?;

            let bytes_written = returned_buf.len() as u64;
            self.bytes_written += bytes_written;

            // Reuse the buffer
            self.buffer = returned_buf;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts, scratch space, and checksum
    pub async fn finish(mut self, max_scratch_space: u64) -> Result<(File, CircuitStats)> {
        // Flush any remaining level data
        self.flush_buffer().await?;

        // Hash is computed as: hash(levels || header_fields_after_checksum)
        // Add the header fields after checksum to the hash
        self.hasher.update(&self.xor_gates_written.to_le_bytes());
        self.hasher.update(&self.and_gates_written.to_le_bytes());
        self.hasher.update(&self.primary_inputs.to_le_bytes());
        self.hasher.update(&max_scratch_space.to_le_bytes());
        self.hasher
            .update(&(self.outputs.len() as u64).to_le_bytes());

        // Also hash the output addresses
        for &output_addr in &self.outputs {
            let varint = StandardVarInt::new(output_addr)?;
            let mut temp_buf = [0u8; 8];
            let size = varint.encode(&mut temp_buf)?;
            self.hasher.update(&temp_buf[..size]);
        }

        // Compute the final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Store checksum for return
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_bytes);

        // Build complete header with checksum
        let mut header_bytes = Vec::with_capacity(CircuitHeader::FIXED_SIZE);
        header_bytes.push(VERSION);
        header_bytes.push(FormatType::TypeB.to_byte());
        header_bytes.extend_from_slice(checksum_bytes);
        header_bytes.extend_from_slice(&self.xor_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.and_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.primary_inputs.to_le_bytes());
        header_bytes.extend_from_slice(&max_scratch_space.to_le_bytes());
        header_bytes.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());

        // Update header at the beginning of the file
        let (res, _) = self.file.write_all_at(header_bytes, 0).await;
        res?;

        // Sync file to ensure all data is written
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
            total_levels: (self.current_level - 1), // Subtract 1 since we start at level 1
            bytes_written: self.bytes_written,
            checksum,
            max_scratch_space,
        };

        Ok((self.file, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::b::hp::reader::CircuitReader;
    use monoio::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_writer_reader_roundtrip() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Write test data
        {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .await?;

            let outputs = vec![8, 9];
            let mut writer = CircuitWriter::new(file, 4, outputs).await?;

            // Level 1: Two XOR gates with memory addresses
            let mut level1 = Level::new(1);
            level1.xor_gates.push(Gate::new(2, 3, 6));
            level1.xor_gates.push(Gate::new(4, 5, 7));

            // Level 2: One AND gate
            let mut level2 = Level::new(2);
            level2.and_gates.push(Gate::new(6, 7, 8));

            writer.write_level(&level1).await?;
            writer.write_level(&level2).await?;

            let (_, stats) = writer.finish(9).await?; // Max scratch space = 9
            assert_eq!(stats.total_gates, 3);
            assert_eq!(stats.xor_gates, 2);
            assert_eq!(stats.and_gates, 1);
            assert_eq!(stats.max_scratch_space, 9);
        }

        // Read back and verify
        {
            let file = OpenOptions::new().read(true).open(&path).await?;

            let mut reader = CircuitReader::new(file, 64 * 1024).await?;

            assert_eq!(reader.header().xor_gates, 2);
            assert_eq!(reader.header().and_gates, 1);
            assert_eq!(reader.header().primary_inputs, 4);
            assert_eq!(reader.header().scratch_space, 9);
            assert_eq!(reader.outputs(), &[8, 9]);

            // Read level 1
            let level1_read = reader.read_level().await?.unwrap();
            assert_eq!(level1_read.xor_gates.len(), 2);
            assert_eq!(level1_read.and_gates.len(), 0);
            assert_eq!(level1_read.xor_gates[0], Gate::new(2, 3, 6));
            assert_eq!(level1_read.xor_gates[1], Gate::new(4, 5, 7));

            // Read level 2
            let level2_read = reader.read_level().await?.unwrap();
            assert_eq!(level2_read.xor_gates.len(), 0);
            assert_eq!(level2_read.and_gates.len(), 1);
            assert_eq!(level2_read.and_gates[0], Gate::new(6, 7, 8));

            // No more levels
            assert!(reader.read_level().await?.is_none());
        }

        Ok(())
    }

    #[monoio::test]
    async fn test_large_circuit() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 100, vec![]).await?;

        // Write many levels with many gates
        for level_id in 0..1000 {
            let mut level = Level::new(level_id);

            // Add 100 XOR gates per level
            for i in 0..100 {
                let base = level_id as u64 * 100 + i;
                level
                    .xor_gates
                    .push(Gate::new(base + 2, base + 3, base + 1000));
            }

            writer.write_level(&level).await?;
        }

        let (_, stats) = writer.finish(200000).await?;
        assert_eq!(stats.total_gates, 100000);
        assert_eq!(stats.xor_gates, 100000);
        assert_eq!(stats.and_gates, 0);
        assert_eq!(stats.total_levels, 1000);

        Ok(())
    }

    #[monoio::test]
    async fn test_relative_encoding_efficiency() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 0, vec![1002]).await?;

        // Create levels with sequential memory addresses for efficient relative encoding
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(2, 3, 1000));
        level1.xor_gates.push(Gate::new(1000, 3, 1001));

        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(1000, 1001, 1002));

        writer.write_level(&level1).await?;
        writer.write_level(&level2).await?;

        let (_, stats) = writer.finish(1003).await?;

        // The encoding should be efficient due to relative encoding
        // Most addresses should use 1-2 bytes due to small relative offsets
        assert!(stats.bytes_written < 200); // Should be quite small

        Ok(())
    }
}

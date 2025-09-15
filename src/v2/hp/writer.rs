use cynosure::hints::{likely, unlikely};
use monoio::fs::File;
use std::io::{Error, ErrorKind, Result};

use crate::v2::{CircuitHeaderV2, Gate, GateType, Level, VERSION, varints::*};

/// High-performance async writer for CKT v2 format using monoio
pub struct CircuitWriterV2 {
    file: File,
    buffer: Vec<u8>,
    wire_counter: u64,
    xor_gates_written: u64,
    and_gates_written: u64,
    primary_inputs: u64,
    bytes_written: u64,
}

impl CircuitWriterV2 {
    /// Create a new v2 writer with placeholder header
    pub async fn new(file: File, primary_inputs: u64) -> Result<Self> {
        let mut writer = Self {
            file,
            buffer: Vec::with_capacity(64 * 1024), // 64KB buffer
            wire_counter: primary_inputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            primary_inputs,
            bytes_written: 0,
        };

        // Write placeholder header - will be updated at end
        writer.write_placeholder_header().await?;
        Ok(writer)
    }
    /// Write placeholder header (25 bytes total)
    async fn write_placeholder_header(&mut self) -> Result<()> {
        // Version byte
        self.buffer.push(VERSION);

        // XOR gates count placeholder (8 bytes)
        self.buffer.extend_from_slice(&[0u8; 8]);

        // AND gates count placeholder (8 bytes)
        self.buffer.extend_from_slice(&[0u8; 8]);

        // Primary inputs count (8 bytes, little-endian)
        self.buffer
            .extend_from_slice(&self.primary_inputs.to_le_bytes());

        self.flush_buffer().await?;
        Ok(())
    }

    /// Write a complete level (XOR gates followed by AND gates)
    pub async fn write_level(&mut self, level: &Level) -> Result<()> {
        if unlikely(level.is_empty()) {
            return Ok(());
        }

        // Write level header: num_xor, num_and
        let num_xor_varint = StandardVarInt::new(level.xor_gates.len() as u64)?;
        let mut temp_buf = [0u8; 8]; // Max StandardVarInt size
        let bytes_used = num_xor_varint.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);

        let num_and_varint = StandardVarInt::new(level.and_gates.len() as u64)?;
        let bytes_used = num_and_varint.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);

        // Write all XOR gates
        for gate in &level.xor_gates {
            self.write_gate(gate, GateType::XOR).await?;
        }

        // Write all AND gates
        for gate in &level.and_gates {
            self.write_gate(gate, GateType::AND).await?;
        }

        // Flush buffer if it's getting large
        if unlikely(self.buffer.len() > 32 * 1024) {
            self.flush_buffer().await?;
        }

        Ok(())
    }

    /// Write a single gate with optimal wire ID encoding
    async fn write_gate(&mut self, gate: &Gate, gate_type: GateType) -> Result<()> {
        // Validate gate against circuit constraints
        if unlikely(gate.input1 >= self.wire_counter || gate.input2 >= self.wire_counter) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Gate inputs ({}, {}) reference unavailable wires (counter: {})",
                    gate.input1, gate.input2, self.wire_counter
                ),
            ));
        }

        if unlikely(gate.output != self.wire_counter) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Gate output {} does not match expected wire counter {}",
                    gate.output, self.wire_counter
                ),
            ));
        }

        // Encode input1 with optimal encoding
        let input1_varint = WireVarInt::optimal_encoding(gate.input1, self.wire_counter)?;
        let mut temp_buf = [0u8; 8]; // Max WireVarInt size
        let bytes_used = input1_varint.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);

        // Encode input2 with optimal encoding
        let input2_varint = WireVarInt::optimal_encoding(gate.input2, self.wire_counter)?;
        let bytes_used = input2_varint.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);

        // Encode output (usually relative(0) since output == counter)
        let output_varint = WireVarInt::optimal_encoding(gate.output, self.wire_counter)?;
        let bytes_used = output_varint.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);

        // Update counters
        self.wire_counter += 1;

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

    /// Get the current wire counter (next available wire ID)
    pub fn wire_counter(&self) -> u64 {
        self.wire_counter
    }

    /// Get total gates written so far
    pub fn gates_written(&self) -> u64 {
        self.xor_gates_written + self.and_gates_written
    }

    /// Get XOR gates written so far
    pub fn xor_gates_written(&self) -> u64 {
        self.xor_gates_written
    }

    /// Flush the write buffer to file
    async fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            let buf = std::mem::take(&mut self.buffer);
            let (result, returned_buf) = self.file.write_all_at(buf, self.bytes_written).await;
            result?;

            self.bytes_written += returned_buf.len() as u64;
            self.buffer = returned_buf;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts
    pub async fn finish(mut self) -> Result<(File, CircuitStats)> {
        // Flush any remaining data
        self.flush_buffer().await?;

        // Update header at position 0 with actual counts
        let mut header_buf = Vec::with_capacity(CircuitHeaderV2::SIZE);
        header_buf.push(VERSION);
        header_buf.extend_from_slice(&self.xor_gates_written.to_le_bytes());
        header_buf.extend_from_slice(&self.and_gates_written.to_le_bytes());
        header_buf.extend_from_slice(&self.primary_inputs.to_le_bytes());

        let (write_result, _) = self.file.write_all_at(header_buf, 0).await;
        write_result?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            final_wire_counter: self.wire_counter,
            bytes_written: self.bytes_written,
        };

        Ok((self.file, stats))
    }
}

/// Statistics about the written circuit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub final_wire_counter: u64,
    pub bytes_written: u64,
}

impl CircuitStats {
    pub fn compression_ratio(&self, original_size: u64) -> f64 {
        if original_size == 0 {
            0.0
        } else {
            self.bytes_written as f64 / original_size as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monoio::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_writer_basic() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
            .await?;

        let mut writer = CircuitWriterV2::new(file, 4).await?; // 4 primary inputs

        // Create a simple level with 2 XOR gates and 1 AND gate
        let mut level = Level::new();
        level.xor_gates.push(Gate::new(0, 1, 4)); // XOR(0,1) -> 4
        level.xor_gates.push(Gate::new(2, 3, 5)); // XOR(2,3) -> 5
        level.and_gates.push(Gate::new(4, 5, 6)); // AND(4,5) -> 6

        writer.write_level(&level).await?;

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);

        Ok(())
    }

    #[monoio::test]
    async fn test_writer_multiple_levels() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
            .await?;

        let mut writer = CircuitWriterV2::new(file, 2).await?; // 2 primary inputs

        // Level 0: Gates that only use primary inputs
        let mut level0 = Level::new();
        level0.xor_gates.push(Gate::new(0, 1, 2)); // XOR(0,1) -> 2

        // Level 1: Gates that use Level 0 outputs
        let mut level1 = Level::new();
        level1.xor_gates.push(Gate::new(0, 2, 3)); // XOR(0,2) -> 3
        level1.and_gates.push(Gate::new(1, 3, 4)); // AND(1,3) -> 4

        writer.write_level(&level0).await?;
        writer.write_level(&level1).await?;

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.final_wire_counter, 5); // primary_inputs(2) + gates(3)

        Ok(())
    }

    #[monoio::test]
    async fn test_writer_validation() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
            .await?;

        let mut writer = CircuitWriterV2::new(file, 2).await?; // 2 primary inputs

        let mut level = Level::new();
        // This should fail: referencing unavailable wire 5
        level.xor_gates.push(Gate::new(0, 5, 2));

        let result = writer.write_level(&level).await;
        assert!(result.is_err());

        Ok(())
    }
}

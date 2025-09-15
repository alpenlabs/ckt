use cynosure::hints::{likely, unlikely};
use std::io::{Error, ErrorKind, Result, Seek, SeekFrom, Write};

use crate::v2::{CircuitHeaderV2, Gate, GateType, Level, VERSION, varints::*};

/// Standard writer for CKT v2 format using std::io traits
pub struct CircuitWriterV2<W: Write + Seek> {
    writer: W,
    buffer: Vec<u8>,
    wire_counter: u64,
    primary_inputs: u64,
    xor_gates_written: u64,
    and_gates_written: u64,
    bytes_written: u64,
}

impl<W: Write + Seek> CircuitWriterV2<W> {
    /// Create a new v2 writer with the given primary inputs count
    pub fn new(writer: W, primary_inputs: u64) -> Result<Self> {
        let mut circuit_writer = Self {
            writer,
            buffer: Vec::with_capacity(64 * 1024), // 64KB buffer
            wire_counter: primary_inputs,
            primary_inputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            bytes_written: 0,
        };

        // Write placeholder header (25 bytes total)
        circuit_writer.write_placeholder_header()?;
        Ok(circuit_writer)
    }

    /// Write placeholder header (25 bytes total)
    fn write_placeholder_header(&mut self) -> Result<()> {
        // Version byte
        self.buffer.push(VERSION);

        // XOR gates count placeholder (8 bytes)
        self.buffer.extend_from_slice(&[0u8; 8]);

        // AND gates count placeholder (8 bytes)
        self.buffer.extend_from_slice(&[0u8; 8]);

        // Primary inputs count (8 bytes, little-endian)
        self.buffer
            .extend_from_slice(&self.primary_inputs.to_le_bytes());

        self.flush_buffer()?;
        Ok(())
    }

    /// Write a complete level (XOR gates followed by AND gates)
    pub fn write_level(&mut self, level: &Level) -> Result<()> {
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
            self.write_gate(gate, GateType::XOR)?;
        }

        // Write all AND gates
        for gate in &level.and_gates {
            self.write_gate(gate, GateType::AND)?;
        }

        // Flush buffer if it's getting large
        if unlikely(self.buffer.len() > 32 * 1024) {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// Write a single gate with optimal wire ID encoding
    fn write_gate(&mut self, gate: &Gate, gate_type: GateType) -> Result<()> {
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
    pub fn write_levels(&mut self, levels: &[Level]) -> Result<()> {
        for level in levels {
            self.write_level(level)?;
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

    /// Get AND gates written so far
    pub fn and_gates_written(&self) -> u64 {
        self.and_gates_written
    }

    /// Flush the write buffer to writer
    fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            self.writer.write_all(&self.buffer)?;
            self.bytes_written += self.buffer.len() as u64;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts
    pub fn finish(mut self) -> Result<(W, CircuitStats)> {
        // Flush any remaining data
        self.flush_buffer()?;

        // Seek back to beginning and update header with actual counts
        self.writer.seek(SeekFrom::Start(0))?;

        // Write updated header (25 bytes total)
        let mut header_bytes = Vec::with_capacity(CircuitHeaderV2::SIZE);
        header_bytes.push(VERSION);
        header_bytes.extend_from_slice(&self.xor_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.and_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.primary_inputs.to_le_bytes());

        self.writer.write_all(&header_bytes)?;

        // Seek back to end
        self.writer.seek(SeekFrom::End(0))?;
        self.writer.flush()?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            final_wire_counter: self.wire_counter,
            bytes_written: self.bytes_written,
        };

        Ok((self.writer, stats))
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
    use std::io::Cursor;

    #[test]
    fn test_writer_basic() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 4)?; // 4 primary inputs

        // Create a simple level with 2 XOR gates and 1 AND gate
        let mut level = Level::new();
        level.xor_gates.push(Gate::new(0, 1, 4)); // XOR(0,1) -> 4
        level.xor_gates.push(Gate::new(2, 3, 5)); // XOR(2,3) -> 5
        level.and_gates.push(Gate::new(4, 5, 6)); // AND(4,5) -> 6

        writer.write_level(&level)?;

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);

        Ok(())
    }

    #[test]
    fn test_writer_multiple_levels() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 2)?; // 2 primary inputs

        // Level 0: Gates that only use primary inputs
        let mut level0 = Level::new();
        level0.xor_gates.push(Gate::new(0, 1, 2)); // XOR(0,1) -> 2

        // Level 1: Gates that use Level 0 outputs
        let mut level1 = Level::new();
        level1.xor_gates.push(Gate::new(0, 2, 3)); // XOR(0,2) -> 3
        level1.and_gates.push(Gate::new(1, 3, 4)); // AND(1,3) -> 4

        writer.write_level(&level0)?;
        writer.write_level(&level1)?;

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.final_wire_counter, 5); // primary_inputs(2) + gates(3)

        Ok(())
    }

    #[test]
    fn test_writer_validation() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 2)?; // 2 primary inputs

        let mut level = Level::new();
        // This should fail: referencing unavailable wire 5
        level.xor_gates.push(Gate::new(0, 5, 2));

        let result = writer.write_level(&level);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_empty_level() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 2)?;

        let empty_level = Level::new();
        writer.write_level(&empty_level)?; // Should succeed and do nothing

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 0);

        Ok(())
    }

    #[test]
    fn test_large_buffer_flush() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 100)?; // 100 primary inputs

        // Create a large level that should trigger buffer flush
        let mut level = Level::new();
        for i in 0..1000 {
            let input1 = i % 100;
            let input2 = (i + 1) % 100;
            let output = 100 + i;
            level.xor_gates.push(Gate::new(input1, input2, output));
        }

        writer.write_level(&level)?;

        let (cursor, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 1000);
        assert!(cursor.into_inner().len() > 0);

        Ok(())
    }
}

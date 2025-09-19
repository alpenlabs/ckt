use blake3::Hasher;
use cynosure::hints::{cold_and_empty, likely, unlikely};
use std::io::{Result, Seek, SeekFrom, Write};

use super::{
    Gate, Level,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::{
    GateType,
    v4::{CircuitStats, FormatType, VERSION, b::CircuitHeader},
};

/// Standard writer for CKT v4b format using std::io traits
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    buffer: Vec<u8>,
    current_level: u32,
    primary_inputs: u64,
    outputs: Vec<u64>,
    xor_gates_written: u64,
    and_gates_written: u64,
    bytes_written: u64,
    header_position: u64,
    outputs_size: usize,
    hasher: Hasher,
    previous_output: u64,
}

impl<W: Write + Seek> CircuitWriter<W> {
    /// Create a new v4b writer with the given primary inputs and output addresses
    pub fn new(writer: W, primary_inputs: u64, outputs: Vec<u64>) -> Result<Self> {
        // Previous output starts at 2 + primary_inputs (after constants and primary inputs)
        let previous_output = 2 + primary_inputs;

        let mut circuit_writer = Self {
            writer,
            buffer: Vec::with_capacity(64 * 1024), // 64KB buffer
            current_level: 1,                      // Start at level 1 (level 0 is implicit)
            primary_inputs,
            outputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            bytes_written: 0,
            header_position: 0,
            outputs_size: 0,
            hasher: Hasher::new(),
            previous_output,
        };

        // Write placeholder header and output addresses
        circuit_writer.write_placeholder_header()?;
        circuit_writer.write_output_addresses()?;

        Ok(circuit_writer)
    }

    /// Write placeholder header (74 bytes fixed)
    fn write_placeholder_header(&mut self) -> Result<()> {
        // Remember where we are for later update
        self.header_position = self.writer.stream_position()?;

        // Write placeholder header directly to writer (not through buffer)
        let placeholder = vec![0u8; CircuitHeader::FIXED_SIZE];
        self.writer.write_all(&placeholder)?;
        self.bytes_written += CircuitHeader::FIXED_SIZE as u64;

        Ok(())
    }

    /// Write output memory addresses
    fn write_output_addresses(&mut self) -> Result<()> {
        let mut output_buffer = Vec::new();

        for &output_addr in &self.outputs {
            let varint = StandardVarInt::new(output_addr)?;
            let mut temp_buf = [0u8; 8];
            let size = varint.encode(&mut temp_buf)?;
            output_buffer.extend_from_slice(&temp_buf[..size]);
        }

        self.outputs_size = output_buffer.len();
        self.writer.write_all(&output_buffer)?;
        self.bytes_written += self.outputs_size as u64;

        Ok(())
    }

    /// Write a complete level with memory-addressed gates
    pub fn write_level(&mut self, level: &Level) -> Result<()> {
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
        if unlikely(self.buffer.len() > 32 * 1024) {
            self.flush_buffer()?;
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
            GateType::AND => {
                cold_and_empty();
                self.and_gates_written += 1
            }
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

    /// Flush the write buffer to writer
    fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            self.writer.write_all(&self.buffer)?;
            self.bytes_written += self.buffer.len() as u64;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts, scratch space, and checksum
    pub fn finish(mut self, max_scratch_space: u64) -> Result<(W, CircuitStats)> {
        // Flush any remaining level data
        self.flush_buffer()?;

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

        // Seek back to beginning and update header with actual counts and checksum
        self.writer.seek(SeekFrom::Start(self.header_position))?;

        // Write complete header with checksum
        self.writer.write_all(&[VERSION])?;
        self.writer.write_all(&[FormatType::TypeB.to_byte()])?;
        self.writer.write_all(checksum_bytes)?;
        self.writer
            .write_all(&self.xor_gates_written.to_le_bytes())?;
        self.writer
            .write_all(&self.and_gates_written.to_le_bytes())?;
        self.writer.write_all(&self.primary_inputs.to_le_bytes())?;
        self.writer.write_all(&max_scratch_space.to_le_bytes())?;
        self.writer
            .write_all(&(self.outputs.len() as u64).to_le_bytes())?;

        // Seek back to end
        self.writer.seek(SeekFrom::End(0))?;
        self.writer.flush()?;

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

        Ok((self.writer, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_writer_basic() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let outputs = vec![6, 7]; // Output memory addresses
        let mut writer = CircuitWriter::new(buffer, 4, outputs)?; // 4 primary inputs

        // Level 1: Gates with explicit memory addresses
        // Memory layout: [0:false, 1:true, 2-5:primary inputs, 6+:gates]
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(2, 3, 6)); // Read from addresses 2,3, write to 6
        level1.xor_gates.push(Gate::new(4, 5, 7)); // Read from addresses 4,5, write to 7

        // Level 2: Gate using previous level outputs
        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(6, 7, 8)); // Read from 6,7, write to 8

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;

        let (_, stats) = writer.finish(9)?; // 0-8 inclusive = 9 entries
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);
        assert_eq!(stats.num_outputs, 2);
        assert_eq!(stats.max_scratch_space, 9); // 0-8 inclusive = 9 entries

        Ok(())
    }

    #[test]
    fn test_memory_address_tracking() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2, vec![10])?;

        // Initial previous output should be 2 + primary_inputs = 4
        assert_eq!(writer.previous_output, 4);

        // Write a gate and check previous output updates
        let level = Level {
            id: 1,
            xor_gates: vec![Gate::new(2, 3, 100)],
            and_gates: vec![],
        };
        writer.write_level(&level)?;
        assert_eq!(writer.previous_output, 100);

        Ok(())
    }

    #[test]
    fn test_relative_encoding() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 0, vec![10])?;

        // Set up scenario for relative encoding
        writer.previous_output = 1000;

        let mut level = Level::new(1);
        // These addresses should use relative encoding since they're close to previous_output
        level.xor_gates.push(Gate::new(998, 999, 1001));
        level.and_gates.push(Gate::new(1000, 1001, 1002));

        writer.write_level(&level)?;

        let (cursor, _) = writer.finish(1003)?; // Max address used
        let data = cursor.into_inner();

        // The encoding should be efficient due to relative encoding
        assert!(data.len() < 200); // Reasonable upper bound

        Ok(())
    }

    #[test]
    fn test_empty_level_handling() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2, vec![])?;

        let empty_level = Level::new(1);
        writer.write_level(&empty_level)?; // Should succeed and do nothing

        let (_, stats) = writer.finish(5)?; // Just constants + primary inputs
        assert_eq!(stats.total_gates, 0);
        assert_eq!(stats.total_levels, 0);

        Ok(())
    }

    #[test]
    fn test_constants_and_primary_inputs() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let primary_inputs = 5;
        let mut writer = CircuitWriter::new(buffer, primary_inputs, vec![7, 8])?;

        // Memory layout should be:
        // 0: false constant
        // 1: true constant
        // 2-6: primary inputs (5 total)
        // 7+: gate outputs

        let mut level = Level::new(1);
        // Gate using constants
        level.xor_gates.push(Gate::new(0, 1, 7)); // XOR false with true
        // Gate using primary inputs
        level.and_gates.push(Gate::new(2, 3, 8)); // AND first two primary inputs

        writer.write_level(&level)?;

        let (_, stats) = writer.finish(9)?; // 0-8 inclusive = 9 entries
        assert_eq!(stats.primary_inputs, 5);
        assert_eq!(stats.total_gates, 2);
        // Max scratch space should be at least 9 (0-8 inclusive)
        assert!(stats.max_scratch_space >= 9);

        Ok(())
    }
}

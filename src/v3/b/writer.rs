use blake3::Hasher;
use cynosure::hints::{likely, unlikely};
use std::io::{Result, Seek, SeekFrom, Write};

use super::{
    Gate, Level,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::{
    GateType,
    v3::{CircuitStats, FormatType, VERSION, b::CircuitHeader},
};

/// Standard writer for CKT v3b format using std::io traits
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    buffer: Vec<u8>,
    current_level: u32,
    primary_inputs: u64,
    xor_gates_written: u64,
    and_gates_written: u64,
    bytes_written: u64,
    level_sizes: Vec<usize>,
    header_position: u64,
    hasher: Hasher,
}

impl<W: Write + Seek> CircuitWriter<W> {
    /// Create a new v3b writer with the given primary inputs count
    pub fn new(writer: W, primary_inputs: u64) -> Result<Self> {
        let mut circuit_writer = Self {
            writer,
            buffer: Vec::with_capacity(64 * 1024), // 64KB buffer
            current_level: 1,                      // Start at level 1 (level 0 is implicit)
            primary_inputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            bytes_written: 0,
            level_sizes: vec![primary_inputs as usize], // Level 0 size
            header_position: 0,
            hasher: Hasher::new(),
        };

        // Write placeholder header (58 bytes total)
        circuit_writer.write_placeholder_header()?;
        Ok(circuit_writer)
    }

    /// Write placeholder header (58 bytes total)
    fn write_placeholder_header(&mut self) -> Result<()> {
        // Remember where we are for later update
        self.header_position = self.writer.stream_position()?;

        // Write placeholder header directly to writer (not through buffer)
        // This ensures it doesn't get hashed
        let mut placeholder = vec![0u8; CircuitHeader::SIZE];
        placeholder[0] = VERSION;
        placeholder[1] = FormatType::TypeB.to_byte();
        // Rest are zeros (checksum, counts)
        // We'll update with real values later

        self.writer.write_all(&placeholder)?;
        self.bytes_written += CircuitHeader::SIZE as u64;

        Ok(())
    }

    /// Write a complete level (XOR gates followed by AND gates)
    pub fn write_level(&mut self, level: &Level) -> Result<()> {
        if unlikely(level.is_empty()) {
            return Ok(());
        }

        // Write level header: num_xor with AND gate flag, optionally num_and
        let has_and_gates = !level.and_gates.is_empty();
        let num_xor_flagged =
            FlaggedVarInt::with_flag(level.xor_gates.len() as u64, has_and_gates)?;
        let mut temp_buf = [0u8; 8]; // Max FlaggedVarInt size
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

        // Track level size
        let level_size = level.xor_gates.len() + level.and_gates.len();
        self.level_sizes.push(level_size);
        self.current_level += 1;

        // Flush buffer if it's getting large
        if unlikely(self.buffer.len() > 32 * 1024) {
            self.flush_buffer()?;
        }

        Ok(())
    }

    /// Write a single gate with implicit output
    fn write_gate(&mut self, gate: &Gate, gate_type: GateType) -> Result<()> {
        let mut temp_buf = [0u8; 32]; // Max size for wire encoding

        // Encode input1 wire location
        let bytes1 = FlaggedVarInt::encode_wire_location(
            gate.in1.level,
            gate.in1.index,
            self.current_level,
            &mut temp_buf,
        )?;
        self.buffer.extend_from_slice(&temp_buf[..bytes1]);
        self.hasher.update(&temp_buf[..bytes1]);

        // Encode input2 wire location
        let bytes2 = FlaggedVarInt::encode_wire_location(
            gate.in2.level,
            gate.in2.index,
            self.current_level,
            &mut temp_buf,
        )?;
        self.buffer.extend_from_slice(&temp_buf[..bytes2]);
        self.hasher.update(&temp_buf[..bytes2]);

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
            // Note: buffer should only contain gate data, not header
            self.writer.write_all(&self.buffer)?;
            self.bytes_written += self.buffer.len() as u64;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts and checksum
    pub fn finish(mut self) -> Result<(W, CircuitStats)> {
        // Flush any remaining gate data
        self.flush_buffer()?;

        // Hash is computed as: hash(gate_data || header_fields_after_checksum)
        // Add the actual header fields (after checksum position) to the hash
        self.hasher.update(&self.xor_gates_written.to_le_bytes());
        self.hasher.update(&self.and_gates_written.to_le_bytes());
        self.hasher.update(&self.primary_inputs.to_le_bytes());

        // Compute the final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Store checksum for return
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_bytes);

        // Seek back to beginning and update header with actual counts and checksum
        self.writer.seek(SeekFrom::Start(self.header_position))?;

        // Write complete header with checksum
        let mut header_bytes = Vec::with_capacity(CircuitHeader::SIZE);
        header_bytes.push(VERSION);
        header_bytes.push(FormatType::TypeB.to_byte());
        header_bytes.extend_from_slice(checksum_bytes);
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
            total_levels: (self.current_level - 1) as u32, // Subtract 1 since we start at level 1
            bytes_written: self.bytes_written,
            checksum,
        };

        Ok((self.writer, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::b::{WireLocation, reader::CircuitReader};
    use std::io::Cursor;

    #[test]
    fn test_writer_basic() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 4)?; // 4 primary inputs

        // Level 1: 2 XOR gates using primary inputs
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // input from primary input 0
            WireLocation::new(0, 1), // input from primary input 1
        ));
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 2), // input from primary input 2
            WireLocation::new(0, 3), // input from primary input 3
        ));

        // Level 2: 1 AND gate using outputs from level 1
        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(
            WireLocation::new(1, 0), // input from level 1, gate 0 (wire 4)
            WireLocation::new(1, 1), // input from level 1, gate 1 (wire 5)
        ));

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;

        let (cursor, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);

        // Verify we can read it back
        let data = cursor.into_inner();
        let cursor = Cursor::new(data);
        let mut reader = CircuitReader::new(cursor)?;

        assert_eq!(reader.header().xor_gates, 2);
        assert_eq!(reader.header().and_gates, 1);

        let read_level1 = reader.read_level()?.unwrap();
        assert_eq!(read_level1.xor_gates.len(), 2);
        assert_eq!(read_level1.and_gates.len(), 0);

        let read_level2 = reader.read_level()?.unwrap();
        assert_eq!(read_level2.xor_gates.len(), 0);
        assert_eq!(read_level2.and_gates.len(), 1);

        Ok(())
    }

    #[test]
    fn test_writer_multiple_levels() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2)?; // 2 primary inputs

        // Level 1: Gates that only use primary inputs
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // primary input 0
            WireLocation::new(0, 1), // primary input 1
        )); // This produces wire 2

        // Level 2: XOR gate that uses Level 1 output
        let mut level2 = Level::new(2);
        level2.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // primary input 0
            WireLocation::new(1, 0), // level 1, gate 0 (wire 2)
        )); // This produces wire 3

        // Level 3: AND gate that uses Level 2 output
        let mut level3 = Level::new(3);
        level3.and_gates.push(Gate::new(
            WireLocation::new(0, 1), // primary input 1
            WireLocation::new(2, 0), // level 2, gate 0 (wire 3)
        )); // This produces wire 4

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;
        writer.write_level(&level3)?;

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.total_levels, 3);

        Ok(())
    }

    #[test]
    fn test_empty_level() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2)?;

        let empty_level = Level::new(1);
        writer.write_level(&empty_level)?; // Should succeed and do nothing

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 0);

        Ok(())
    }

    #[test]
    fn test_previous_level_encoding() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2)?;

        // Level 1
        let mut level1 = Level::new(1);
        level1
            .xor_gates
            .push(Gate::new(WireLocation::new(0, 0), WireLocation::new(0, 1)));

        // Level 2 - uses previous level (should use optimized encoding)
        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(
            WireLocation::new(1, 0), // Previous level - should be efficiently encoded
            WireLocation::new(1, 0), // Previous level - should be efficiently encoded
        ));

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;

        let (cursor, _) = writer.finish()?;
        let data = cursor.into_inner();

        // The previous level references should be encoded more compactly
        // (exact size depends on varint encoding, but should be small)
        assert!(data.len() < 100); // Reasonable upper bound for this simple circuit

        Ok(())
    }

    #[test]
    fn test_checksum_verification() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 3)?; // 3 primary inputs

        // Create some test levels
        let mut level1 = Level::new(1);
        level1
            .xor_gates
            .push(Gate::new(WireLocation::new(0, 0), WireLocation::new(0, 1)));
        level1
            .and_gates
            .push(Gate::new(WireLocation::new(0, 1), WireLocation::new(0, 2)));

        let mut level2 = Level::new(2);
        level2.xor_gates.push(Gate::new(
            WireLocation::new(1, 0), // Previous level
            WireLocation::new(1, 1), // Previous level
        ));

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;

        let (cursor, _stats) = writer.finish()?;
        let data = cursor.into_inner();

        // Read back and verify checksum
        let cursor = Cursor::new(data.clone());
        let mut reader = CircuitReader::new(cursor)?;

        // Read all data
        while let Some(_level) = reader.read_level()? {
            // Just read through all levels
        }

        // Verify checksum should pass
        let cursor = Cursor::new(data.clone());
        let _checksum = super::super::verify_checksum(cursor)?;

        // Now corrupt the data
        let mut corrupted_data = data.clone();
        // Corrupt a byte in the middle of the file (guaranteed to exist)
        let corrupt_index = corrupted_data.len() / 2;
        corrupted_data[corrupt_index] ^= 0xFF; // Flip some bits in the data

        // Checksum verification should fail for corrupted data
        let cursor = Cursor::new(corrupted_data);
        let result = super::super::verify_checksum(cursor);
        assert!(
            result.is_err(),
            "Checksum verification should fail for corrupted data"
        );

        Ok(())
    }
}

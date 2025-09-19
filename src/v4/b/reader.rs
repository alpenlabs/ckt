use cynosure::hints::{likely, unlikely};
use std::io::{Error, ErrorKind, Read, Result};

use super::{
    AndGates, Gate, Level, XorGates,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v4::{FormatType, VERSION, b::CircuitHeader};

/// Standard reader for CKT v4b format using std::io traits
pub struct CircuitReader<R: Read> {
    reader: R,
    /// Buffer for efficient reading
    buffer: Vec<u8>,
    /// Current position in buffer
    buffer_offset: usize,
    /// Valid data end in buffer
    max_valid_bytes: usize,
    /// Previous gate's output address for relative decoding
    previous_output: u64,
    /// Current level being read
    current_level: u32,
    /// Circuit header
    header: CircuitHeader,
    /// Output memory addresses
    outputs: Vec<u64>,
    /// Number of levels read so far
    levels_read: usize,
    /// Total gates read so far
    gates_read: u64,
    /// Whether we've reached EOF
    eof_reached: bool,
}

impl<R: Read> CircuitReader<R> {
    /// Create a new v4b reader
    pub fn new(reader: R) -> Result<Self> {
        Self::with_buffer_size(reader, 64 * 1024)
    }

    /// Create a new v4b reader with specified buffer size
    pub fn with_buffer_size(mut reader: R, buffer_size: usize) -> Result<Self> {
        // Read fixed header (74 bytes)
        let mut header_bytes = [0u8; CircuitHeader::FIXED_SIZE];
        reader.read_exact(&mut header_bytes)?;

        // Validate version and type
        if unlikely(header_bytes[0] != VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", header_bytes[0]),
            ));
        }

        if unlikely(header_bytes[1] != FormatType::TypeB.to_byte()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid format type for v4b: {}", header_bytes[1]),
            ));
        }

        // Extract checksum
        let mut stored_checksum = [0u8; 32];
        stored_checksum.copy_from_slice(&header_bytes[2..34]);

        // Parse remaining header fields
        let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());
        let scratch_space = u64::from_le_bytes(header_bytes[58..66].try_into().unwrap());
        let num_outputs = u64::from_le_bytes(header_bytes[66..74].try_into().unwrap());

        let header = CircuitHeader {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum: stored_checksum,
            xor_gates,
            and_gates,
            primary_inputs,
            scratch_space,
            num_outputs,
        };

        // Read output memory addresses
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        let mut output_buffer = vec![0u8; 8]; // Temp buffer for varint reading

        for _ in 0..num_outputs {
            // Read enough bytes for a varint
            reader.read_exact(&mut output_buffer[0..1])?;

            // Determine varint length from first byte
            let length = match output_buffer[0] >> 6 {
                0b00 => 1,
                0b01 => 2,
                0b10 => 4,
                0b11 => 8,
                _ => unreachable!(),
            };

            if length > 1 {
                reader.read_exact(&mut output_buffer[1..length])?;
            }

            let (varint, _) = StandardVarInt::decode(&output_buffer[..length])?;
            outputs.push(varint.value());
        }

        // Previous output starts at 2 + primary_inputs (after constants and primary inputs)
        let previous_output = 2 + primary_inputs;

        Ok(Self {
            reader,
            buffer: vec![0; buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            previous_output,
            current_level: 1, // Start at level 1 (level 0 is implicit)
            header,
            outputs,
            levels_read: 0,
            gates_read: 0,
            eof_reached: false,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeader {
        &self.header
    }

    /// Get output memory addresses
    pub fn outputs(&self) -> &[u64] {
        &self.outputs
    }

    /// Get previous output address
    pub fn previous_output(&self) -> u64 {
        self.previous_output
    }

    /// Get current level
    pub fn current_level(&self) -> u32 {
        self.current_level
    }

    /// Get number of levels read so far
    pub fn levels_read(&self) -> usize {
        self.levels_read
    }

    /// Get total gates read so far
    pub fn gates_read(&self) -> u64 {
        self.gates_read
    }

    /// Read the next level in AoS (Array of Structures) format
    pub fn read_level(&mut self) -> Result<Option<Level>> {
        if unlikely(self.gates_read >= self.header.total_gates()) {
            return Ok(None);
        }

        // Read level header
        let num_xor_flagged = self.read_flagged_varint()?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        let num_and = if has_and_gates {
            self.read_standard_varint()?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut level =
            Level::with_capacity(self.current_level, num_xor as usize, num_and as usize);

        // Read XOR gates
        for _ in 0..num_xor {
            let gate = self.read_gate()?;
            level.xor_gates.push(gate);
            self.gates_read += 1;
        }

        // Read AND gates
        for _ in 0..num_and {
            let gate = self.read_gate()?;
            level.and_gates.push(gate);
            self.gates_read += 1;
        }

        self.levels_read += 1;
        self.current_level += 1;

        Ok(Some(level))
    }

    /// Read the next level in SoA (Structure of Arrays) format for vectorization
    pub fn read_soa_level<const N: usize>(&mut self) -> Result<Option<(XorGates<N>, AndGates<N>)>> {
        if unlikely(self.gates_read >= self.header.total_gates()) {
            return Ok(None);
        }

        // Read level header
        let num_xor_flagged = self.read_flagged_varint()?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        let num_and = if has_and_gates {
            self.read_standard_varint()?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        // Check if level fits in arrays
        if num_xor as usize > N || num_and as usize > N {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Level too large for SoA arrays: {} XOR, {} AND gates (max {})",
                    num_xor, num_and, N
                ),
            ));
        }

        let mut xor_gates = XorGates::<N>::with_capacity(num_xor as usize);
        let mut and_gates = AndGates::<N>::with_capacity(num_and as usize);

        // Read XOR gates into SoA
        for _ in 0..num_xor {
            let gate = self.read_gate()?;
            xor_gates.add_gate(gate);
            self.gates_read += 1;
        }

        // Read AND gates into SoA
        for _ in 0..num_and {
            let gate = self.read_gate()?;
            and_gates.add_gate(gate);
            self.gates_read += 1;
        }

        xor_gates.count = num_xor as usize;
        and_gates.count = num_and as usize;

        self.levels_read += 1;
        self.current_level += 1;

        Ok(Some((xor_gates, and_gates)))
    }

    /// Read a single gate with memory addresses
    fn read_gate(&mut self) -> Result<Gate> {
        // Read input1 memory address
        let (in1, consumed1) = self.read_memory_address()?;
        self.consume_bytes(consumed1);

        // Read input2 memory address
        let (in2, consumed2) = self.read_memory_address()?;
        self.consume_bytes(consumed2);

        // Read output memory address
        let (out, consumed3) = self.read_memory_address()?;
        self.consume_bytes(consumed3);

        // Update previous output for next gate
        self.previous_output = out;

        Ok(Gate::new(in1, in2, out))
    }

    /// Read a memory address using FlaggedVarInt encoding
    fn read_memory_address(&mut self) -> Result<(u64, usize)> {
        // First ensure we have at least 1 byte to determine varint length
        self.ensure_bytes(1)?;

        // Determine actual varint length from first byte
        let first_byte = self.buffer[self.buffer_offset];
        let needed = match first_byte >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        };

        // Now ensure we have the actual bytes needed
        self.ensure_bytes(needed)?;

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        FlaggedVarInt::decode_memory_address(buffer_slice, self.previous_output)
    }

    /// Read a FlaggedVarInt from buffer
    fn read_flagged_varint(&mut self) -> Result<FlaggedVarInt> {
        // First ensure we have at least 1 byte to determine varint length
        self.ensure_bytes(1)?;

        // Determine actual varint length from first byte
        let first_byte = self.buffer[self.buffer_offset];
        let needed = match first_byte >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        };

        // Now ensure we have the actual bytes needed
        self.ensure_bytes(needed)?;

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = FlaggedVarInt::decode(buffer_slice)?;
        self.consume_bytes(consumed);
        Ok(varint)
    }

    /// Read a StandardVarInt from buffer
    fn read_standard_varint(&mut self) -> Result<u64> {
        // First ensure we have at least 1 byte to determine varint length
        self.ensure_bytes(1)?;

        // Determine actual varint length from first byte
        let first_byte = self.buffer[self.buffer_offset];
        let needed = match first_byte >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        };

        // Now ensure we have the actual bytes needed
        self.ensure_bytes(needed)?;

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = StandardVarInt::decode(buffer_slice)?;
        self.consume_bytes(consumed);
        Ok(varint.value())
    }

    /// Consume bytes from buffer
    #[inline(always)]
    fn consume_bytes(&mut self, count: usize) {
        self.buffer_offset += count;
    }

    /// Ensure at least `needed` bytes are available in buffer
    fn ensure_bytes(&mut self, needed: usize) -> Result<()> {
        let available = self.max_valid_bytes - self.buffer_offset;

        if likely(available >= needed) {
            return Ok(());
        }

        // If we've already hit EOF, check if we have enough
        if self.eof_reached {
            if available >= needed {
                return Ok(());
            } else {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Unexpected end of data",
                ));
            }
        }

        // Compact buffer if needed
        if self.buffer_offset > 0 {
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.max_valid_bytes -= self.buffer_offset;
            self.buffer_offset = 0;
        }

        // Fill buffer
        let buffer_space = self.buffer.len() - self.max_valid_bytes;
        if buffer_space > 0 {
            let bytes_read = self.reader.read(&mut self.buffer[self.max_valid_bytes..])?;
            self.max_valid_bytes += bytes_read;

            if bytes_read == 0 {
                self.eof_reached = true;
            }
        }

        // Check if we now have enough
        let available = self.max_valid_bytes - self.buffer_offset;
        if available < needed {
            Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Not enough data available",
            ))
        } else {
            Ok(())
        }
    }
}

/// Verify the BLAKE3 checksum of a v4b format file
///
/// This function reads the entire file and verifies that the stored checksum
/// matches the computed checksum of: hash(levels || header_fields_after_checksum || output_addresses)
/// Returns the checksum if verification succeeds
pub fn verify_checksum<R: std::io::Read>(mut reader: R) -> Result<[u8; 32]> {
    use super::varints::StandardVarInt;
    use blake3::Hasher;

    // Read fixed header (74 bytes)
    let mut header_bytes = [0u8; CircuitHeader::FIXED_SIZE];
    reader.read_exact(&mut header_bytes)?;

    // Validate version and type
    if header_bytes[0] != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid version: {}", header_bytes[0]),
        ));
    }

    if header_bytes[1] != FormatType::TypeB.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid format type: {}", header_bytes[1]),
        ));
    }

    // Extract stored checksum
    let mut stored_checksum = [0u8; 32];
    stored_checksum.copy_from_slice(&header_bytes[2..34]);

    // Parse num_outputs from header
    let num_outputs = u64::from_le_bytes(header_bytes[66..74].try_into().unwrap());

    // Save header fields after checksum for hashing at the end
    let header_fields_after_checksum = &header_bytes[34..];

    // Read output addresses (to skip them in the data stream)
    let mut output_addresses = Vec::new();
    let mut output_buffer = vec![0u8; 8]; // Temp buffer for varint reading

    for _ in 0..num_outputs {
        // Read enough bytes for a varint
        reader.read_exact(&mut output_buffer[0..1])?;

        // Determine varint length from first byte
        let length = match output_buffer[0] >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        };

        if length > 1 {
            reader.read_exact(&mut output_buffer[1..length])?;
        }

        output_addresses.push(output_buffer[..length].to_vec());
    }

    // Hash all level data first
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Then hash the header fields (after checksum)
    hasher.update(header_fields_after_checksum);

    // Finally hash the output addresses (like the writer does)
    for output_bytes in &output_addresses {
        hasher.update(output_bytes);
    }

    // Compare checksums
    let computed_hash = hasher.finalize();
    if computed_hash.as_bytes() == &stored_checksum {
        Ok(stored_checksum)
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum verification failed",
        ))
    }
}

/// Verify the checksum of a v4b file from a path
/// Returns the checksum if verification succeeds
pub fn verify_checksum_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let file = std::fs::File::open(path)?;
    verify_checksum(std::io::BufReader::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::b::writer::CircuitWriter;
    use std::io::Cursor;

    #[test]
    fn test_reader_writer_roundtrip() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let outputs = vec![8, 9];
        let mut writer = CircuitWriter::new(buffer, 4, outputs.clone())?;

        // Level 1: Two XOR gates
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(2, 3, 6));
        level1.xor_gates.push(Gate::new(4, 5, 7));

        // Level 2: One AND gate
        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(6, 7, 8));

        writer.write_level(&level1)?;
        writer.write_level(&level2)?;

        let (cursor, _) = writer.finish(9)?;
        let data = cursor.into_inner();

        // Read back
        let cursor = Cursor::new(data);
        let mut reader = CircuitReader::new(cursor)?;

        assert_eq!(reader.header().xor_gates, 2);
        assert_eq!(reader.header().and_gates, 1);
        assert_eq!(reader.header().primary_inputs, 4);
        assert_eq!(reader.header().scratch_space, 9);
        assert_eq!(reader.outputs(), &[8, 9]);

        // Read level 1
        let level1_read = reader.read_level()?.unwrap();
        assert_eq!(level1_read.xor_gates.len(), 2);
        assert_eq!(level1_read.and_gates.len(), 0);
        assert_eq!(level1_read.xor_gates[0], Gate::new(2, 3, 6));
        assert_eq!(level1_read.xor_gates[1], Gate::new(4, 5, 7));

        // Read level 2
        let level2_read = reader.read_level()?.unwrap();
        assert_eq!(level2_read.xor_gates.len(), 0);
        assert_eq!(level2_read.and_gates.len(), 1);
        assert_eq!(level2_read.and_gates[0], Gate::new(6, 7, 8));

        // No more levels
        assert!(reader.read_level()?.is_none());

        Ok(())
    }

    #[test]
    fn test_soa_reading() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2, vec![])?;

        // Create a level with multiple gates
        let mut level = Level::new(1);
        level.xor_gates.push(Gate::new(2, 3, 4));
        level.xor_gates.push(Gate::new(3, 4, 5));
        level.and_gates.push(Gate::new(4, 5, 6));

        writer.write_level(&level)?;

        let (cursor, _) = writer.finish(7)?;
        let data = cursor.into_inner();

        // Read back in SoA format
        let cursor = Cursor::new(data);
        let mut reader = CircuitReader::new(cursor)?;

        let (xor_gates, and_gates): (XorGates<10>, AndGates<10>) =
            reader.read_soa_level()?.unwrap();

        assert_eq!(xor_gates.count, 2);
        assert_eq!(xor_gates.input1_addrs, vec![2, 3]);
        assert_eq!(xor_gates.input2_addrs, vec![3, 4]);
        assert_eq!(xor_gates.output_addrs, vec![4, 5]);

        assert_eq!(and_gates.count, 1);
        assert_eq!(and_gates.input1_addrs, vec![4]);
        assert_eq!(and_gates.input2_addrs, vec![5]);
        assert_eq!(and_gates.output_addrs, vec![6]);

        Ok(())
    }

    #[test]
    fn test_checksum_verification() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2, vec![5])?;

        let mut level = Level::new(1);
        level.xor_gates.push(Gate::new(2, 3, 5));
        writer.write_level(&level)?;

        let (cursor, stats) = writer.finish(6)?;
        let data = cursor.into_inner();

        // Verify checksum
        let cursor = Cursor::new(data.clone());
        let checksum = verify_checksum(cursor)?;
        assert_eq!(checksum, stats.checksum);

        // Corrupt data and verify failure
        let mut corrupted = data.clone();
        // Corrupt a byte in the middle of the actual data
        if corrupted.len() > 80 {
            // Corrupt level data (after header + outputs)
            corrupted[80] ^= 0xFF;
        } else if corrupted.len() > 40 {
            // If file is smaller, corrupt somewhere in the middle
            let mid = corrupted.len() / 2;
            corrupted[mid] ^= 0xFF;
        }

        let cursor = Cursor::new(corrupted);
        assert!(verify_checksum(cursor).is_err());

        Ok(())
    }
}

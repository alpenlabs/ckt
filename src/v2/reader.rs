use cynosure::hints::{likely, prefetch_read_data, unlikely};
use std::io::{Error, ErrorKind, Read, Result};

use crate::v2::{AndGates, CircuitHeaderV2, Gate, Level, XorGates, varints::*};

/// Standard reader for CKT v2 format using std::io traits
pub struct CircuitReaderV2<R: Read> {
    reader: R,
    /// Buffer used for efficient reads
    buffer: Vec<u8>,
    /// Current position in the buffer
    buffer_offset: usize,
    /// How many valid bytes are in the buffer
    max_valid_bytes: usize,
    /// Current wire counter for decoding relative wire IDs
    wire_counter: u64,
    /// Circuit header
    header: CircuitHeaderV2,
    /// Number of levels read so far
    levels_read: usize,
    /// Total gates read so far
    gates_read: u64,
    /// Whether we've reached EOF
    eof_reached: bool,
}

impl<R: Read> CircuitReaderV2<R> {
    /// Create a new v2 reader
    pub fn new(mut reader: R) -> Result<Self> {
        // Read header (25 bytes: 1 + 8 + 8 + 8)
        let mut header_bytes = [0u8; CircuitHeaderV2::SIZE];
        reader.read_exact(&mut header_bytes)?;

        let version = header_bytes[0];
        if unlikely(version != crate::v2::VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", version),
            ));
        }

        let xor_gates = u64::from_le_bytes(header_bytes[1..9].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[9..17].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[17..25].try_into().unwrap());

        let header = CircuitHeaderV2::with_counts(xor_gates, and_gates, primary_inputs);

        Ok(Self {
            reader,
            buffer: vec![0; 64 * 1024], // 64KB buffer
            buffer_offset: 0,
            max_valid_bytes: 0,
            wire_counter: primary_inputs,
            header,
            levels_read: 0,
            gates_read: 0,
            eof_reached: false,
        })
    }

    /// Create a new v2 reader with custom buffer size
    pub fn with_buffer_size(mut reader: R, buffer_size: usize) -> Result<Self> {
        // Read header first
        let mut header_bytes = [0u8; CircuitHeaderV2::SIZE];
        reader.read_exact(&mut header_bytes)?;

        let version = header_bytes[0];
        if unlikely(version != crate::v2::VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", version),
            ));
        }

        let xor_gates = u64::from_le_bytes(header_bytes[1..9].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[9..17].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[17..25].try_into().unwrap());

        let header = CircuitHeaderV2::with_counts(xor_gates, and_gates, primary_inputs);

        Ok(Self {
            reader,
            buffer: vec![0; buffer_size.max(1024)], // At least 1KB
            buffer_offset: 0,
            max_valid_bytes: 0,
            wire_counter: primary_inputs,
            header,
            levels_read: 0,
            gates_read: 0,
            eof_reached: false,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeaderV2 {
        &self.header
    }

    /// Get current wire counter
    pub fn wire_counter(&self) -> u64 {
        self.wire_counter
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
        if unlikely(self.gates_read >= self.header.total_gates() || self.eof_reached) {
            return Ok(None);
        }

        // Read level header (num_xor as FlaggedVarInt with AND gate flag)
        let num_xor_flagged = match self.read_flagged_varint()? {
            Some(val) => val,
            None => return Ok(None),
        };

        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        // Only read num_and if flag indicates AND gates are present
        let num_and = if has_and_gates {
            match self.read_standard_varint()? {
                Some(val) => val,
                None => return Ok(None),
            }
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut level = Level::with_capacity(num_xor as usize, num_and as usize);

        // Read XOR gates
        for _ in 0..num_xor {
            let gate = self.read_gate()?;
            level.xor_gates.push(gate);
        }

        // Read AND gates
        for _ in 0..num_and {
            let gate = self.read_gate()?;
            level.and_gates.push(gate);
        }

        self.levels_read += 1;
        self.gates_read += num_xor + num_and;

        Ok(Some(level))
    }

    /// Read the next level in SoA (Structure of Arrays) format for vectorization
    pub fn read_soa_level<const N: usize>(&mut self) -> Result<Option<(XorGates<N>, AndGates<N>)>> {
        if unlikely(self.gates_read >= self.header.total_gates() || self.eof_reached) {
            return Ok(None);
        }

        // Read level header (num_xor as FlaggedVarInt with AND gate flag)
        let num_xor_flagged = match self.read_flagged_varint()? {
            Some(val) => val,
            None => return Ok(None),
        };

        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        // Only read num_and if flag indicates AND gates are present
        let num_and = if has_and_gates {
            match self.read_standard_varint()? {
                Some(val) => val,
                None => return Ok(None),
            }
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut xor_gates = XorGates::<N>::new();
        let mut and_gates = AndGates::<N>::new();

        // Read XOR gates into SoA format
        let xor_count = (num_xor as usize).min(N);
        for i in 0..xor_count {
            let gate = self.read_gate()?;
            xor_gates.input1s[i] = gate.input1;
            xor_gates.input2s[i] = gate.input2;
            xor_gates.outputs[i] = gate.output;
        }
        xor_gates.count = xor_count;

        // Skip any remaining XOR gates that don't fit
        for _ in xor_count..num_xor as usize {
            self.read_gate()?;
        }

        // Read AND gates into SoA format
        let and_count = (num_and as usize).min(N);
        for i in 0..and_count {
            let gate = self.read_gate()?;
            and_gates.input1s[i] = gate.input1;
            and_gates.input2s[i] = gate.input2;
            and_gates.outputs[i] = gate.output;
        }
        and_gates.count = and_count;

        // Skip any remaining AND gates that don't fit
        for _ in and_count..num_and as usize {
            self.read_gate()?;
        }

        self.levels_read += 1;
        self.gates_read += num_xor + num_and;

        Ok(Some((xor_gates, and_gates)))
    }

    /// Read all remaining levels at once
    pub fn read_all_levels(&mut self) -> Result<Vec<Level>> {
        let mut levels = Vec::new();

        while let Some(level) = self.read_level()? {
            levels.push(level);
        }

        Ok(levels)
    }

    /// Read a single gate and advance wire counter
    fn read_gate(&mut self) -> Result<Gate> {
        // Read input1 as FlaggedVarInt
        let input1_varint = self
            .read_flagged_varint()?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Expected input1 wire ID"))?;
        let input1 = input1_varint.decode_to_absolute(self.wire_counter);

        // Read input2 as FlaggedVarInt
        let input2_varint = self
            .read_flagged_varint()?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Expected input2 wire ID"))?;
        let input2 = input2_varint.decode_to_absolute(self.wire_counter);

        // Read output as FlaggedVarInt
        let output_varint = self
            .read_flagged_varint()?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "Expected output wire ID"))?;
        let output = output_varint.decode_to_absolute(self.wire_counter);

        // Advance wire counter (output should equal current counter)
        self.wire_counter += 1;

        Ok(Gate::new(input1, input2, output))
    }

    /// Read a StandardVarInt from the buffer
    fn read_standard_varint(&mut self) -> Result<Option<u64>> {
        // First ensure we have at least 1 byte to read the length
        if unlikely(!self.ensure_bytes_available(1)?) {
            return Ok(None);
        }

        // Determine the length from the first byte
        let first_byte = self.buffer[self.buffer_offset];
        let length = match first_byte >> 6 {
            0b00 => 1, // Most common case for small values
            0b01 => 2,
            0b10 => 4,
            0b11 => 8, // Least common case
            _ => unreachable!(),
        };

        // Now ensure we have that many bytes
        if unlikely(!self.ensure_bytes_available(length)?) {
            return Ok(None);
        }

        let buffer_slice = &self.buffer[self.buffer_offset..];
        let (varint, bytes_consumed) = StandardVarInt::decode(buffer_slice)?;
        self.buffer_offset += bytes_consumed;

        Ok(Some(varint.value()))
    }

    /// Read a FlaggedVarInt from the buffer
    fn read_flagged_varint(&mut self) -> Result<Option<FlaggedVarInt>> {
        // First ensure we have at least 1 byte to read the length
        if unlikely(!self.ensure_bytes_available(1)?) {
            return Ok(None);
        }

        // Determine the length from the first byte
        let first_byte = self.buffer[self.buffer_offset];
        let length = match first_byte >> 6 {
            0b00 => 1, // Most common case for relative wire IDs
            0b01 => 2,
            0b10 => 4,
            0b11 => 8, // Least common case
            _ => unreachable!(),
        };

        // Now ensure we have that many bytes
        if unlikely(!self.ensure_bytes_available(length)?) {
            return Ok(None);
        }

        let buffer_slice = &self.buffer[self.buffer_offset..];
        let (varint, bytes_consumed) = FlaggedVarInt::decode(buffer_slice)?;
        self.buffer_offset += bytes_consumed;

        Ok(Some(varint))
    }

    /// Ensure at least `needed` bytes are available in the buffer
    /// Returns false on EOF, true if bytes are available
    fn ensure_bytes_available(&mut self, needed: usize) -> Result<bool> {
        // Fast path: already have enough bytes
        if likely(self.buffer_offset + needed <= self.max_valid_bytes) {
            return Ok(true);
        }

        if unlikely(self.eof_reached) {
            return Ok(false);
        }

        // Check if we need to refill buffer
        if unlikely(self.buffer_offset == self.max_valid_bytes) {
            if unlikely(!self.fill_buffer()?) {
                self.eof_reached = true;
                return Ok(false);
            }
        }

        // Check if we now have enough after refill
        if likely(self.buffer_offset + needed <= self.max_valid_bytes) {
            return Ok(true);
        }

        // Compact buffer if needed
        if likely(self.buffer_offset > 0) {
            let remaining = self.max_valid_bytes - self.buffer_offset;
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.buffer_offset = 0;
            self.max_valid_bytes = remaining;

            // Try filling again after compact
            if self.fill_buffer()? {
                return Ok(self.buffer_offset + needed <= self.max_valid_bytes);
            } else {
                self.eof_reached = true;
                return Ok(false);
            }
        }

        Ok(false)
    }

    /// Fill buffer with more data from reader
    /// Returns false on EOF, true if more data was read
    fn fill_buffer(&mut self) -> Result<bool> {
        if unlikely(self.eof_reached) {
            return Ok(false);
        }

        let space_available = self.buffer.len() - self.max_valid_bytes;
        if unlikely(space_available == 0) {
            // Buffer is full, can't read more
            return Ok(false);
        }

        let bytes_read = self.reader.read(&mut self.buffer[self.max_valid_bytes..])?;

        if unlikely(bytes_read == 0) {
            self.eof_reached = true;
            return Ok(false);
        }

        self.max_valid_bytes += bytes_read;

        // Prefetch next data if buffer has more space
        if likely(self.max_valid_bytes < self.buffer.len()) {
            unsafe {
                prefetch_read_data(self.buffer.as_ptr().add(self.max_valid_bytes), 0);
            };
        }

        Ok(true)
    }
}

/// Read just the header from any reader
pub fn read_header<R: Read>(reader: &mut R) -> Result<CircuitHeaderV2> {
    let mut header_bytes = [0u8; CircuitHeaderV2::SIZE];
    reader.read_exact(&mut header_bytes)?;

    let version = header_bytes[0];
    if unlikely(version != crate::v2::VERSION) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Unsupported version: {}", version),
        ));
    }

    let xor_gates = u64::from_le_bytes(header_bytes[1..9].try_into().unwrap());
    let and_gates = u64::from_le_bytes(header_bytes[9..17].try_into().unwrap());
    let primary_inputs = u64::from_le_bytes(header_bytes[17..25].try_into().unwrap());

    Ok(CircuitHeaderV2::with_counts(
        xor_gates,
        and_gates,
        primary_inputs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::writer::CircuitWriterV2;
    use std::io::Cursor;

    fn create_test_circuit() -> Result<Vec<u8>> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 4)?; // 4 primary inputs

        // Level 0: Gates using only primary inputs
        let mut level0 = Level::new();
        level0.xor_gates.push(Gate::new(0, 1, 4)); // XOR(0,1) -> 4
        level0.xor_gates.push(Gate::new(2, 3, 5)); // XOR(2,3) -> 5

        // Level 1: Gates using Level 0 outputs
        let mut level1 = Level::new();
        level1.and_gates.push(Gate::new(4, 5, 6)); // AND(4,5) -> 6

        writer.write_level(&level0)?;
        writer.write_level(&level1)?;

        let (cursor, _stats) = writer.finish()?;
        Ok(cursor.into_inner())
    }

    #[test]
    fn test_reader_basic() -> Result<()> {
        let data = create_test_circuit()?;
        let cursor = Cursor::new(data);
        let mut reader = CircuitReaderV2::new(cursor)?;

        assert_eq!(reader.header().xor_gates, 2);
        assert_eq!(reader.header().and_gates, 1);
        assert_eq!(reader.header().primary_inputs, 4);

        // Read Level 0
        let level0 = reader.read_level()?.unwrap();
        assert_eq!(level0.xor_gates.len(), 2);
        assert_eq!(level0.and_gates.len(), 0);
        assert_eq!(level0.xor_gates[0], Gate::new(0, 1, 4));
        assert_eq!(level0.xor_gates[1], Gate::new(2, 3, 5));

        // Read Level 1
        let level1 = reader.read_level()?.unwrap();
        assert_eq!(level1.xor_gates.len(), 0);
        assert_eq!(level1.and_gates.len(), 1);
        assert_eq!(level1.and_gates[0], Gate::new(4, 5, 6));

        // Should be at end
        assert!(reader.read_level()?.is_none());
        assert_eq!(reader.gates_read(), 3);
        assert_eq!(reader.levels_read(), 2);

        Ok(())
    }

    #[test]
    fn test_reader_soa() -> Result<()> {
        let data = create_test_circuit()?;
        let cursor = Cursor::new(data);
        let mut reader = CircuitReaderV2::new(cursor)?;

        // Read Level 0 in SoA format
        let (xor_gates, and_gates) = reader.read_soa_level::<8>()?.unwrap();

        assert_eq!(xor_gates.count, 2);
        assert_eq!(xor_gates.input1s[0], 0);
        assert_eq!(xor_gates.input2s[0], 1);
        assert_eq!(xor_gates.outputs[0], 4);
        assert_eq!(xor_gates.input1s[1], 2);
        assert_eq!(xor_gates.input2s[1], 3);
        assert_eq!(xor_gates.outputs[1], 5);

        assert_eq!(and_gates.count, 0);

        // Read Level 1 in SoA format
        let (xor_gates, and_gates) = reader.read_soa_level::<8>()?.unwrap();

        assert_eq!(xor_gates.count, 0);
        assert_eq!(and_gates.count, 1);
        assert_eq!(and_gates.input1s[0], 4);
        assert_eq!(and_gates.input2s[0], 5);
        assert_eq!(and_gates.outputs[0], 6);

        Ok(())
    }

    #[test]
    fn test_read_all_levels() -> Result<()> {
        let data = create_test_circuit()?;
        let cursor = Cursor::new(data);
        let mut reader = CircuitReaderV2::new(cursor)?;

        let levels = reader.read_all_levels()?;
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0].xor_gates.len(), 2);
        assert_eq!(levels[1].and_gates.len(), 1);

        Ok(())
    }

    #[test]
    fn test_read_header_only() -> Result<()> {
        let data = create_test_circuit()?;
        let mut cursor = Cursor::new(data);

        let header = read_header(&mut cursor)?;
        assert_eq!(header.xor_gates, 2);
        assert_eq!(header.and_gates, 1);
        assert_eq!(header.primary_inputs, 4);

        Ok(())
    }

    #[test]
    fn test_empty_circuit() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let writer = CircuitWriterV2::new(buffer, 2)?; // 2 primary inputs

        let (cursor, _stats) = writer.finish()?;
        let data = cursor.into_inner();

        let cursor = Cursor::new(data);
        let mut reader = CircuitReaderV2::new(cursor)?;

        assert_eq!(reader.header().xor_gates, 0);
        assert_eq!(reader.header().and_gates, 0);
        assert_eq!(reader.header().primary_inputs, 2);
        assert!(reader.read_level()?.is_none());

        Ok(())
    }

    #[test]
    fn test_small_buffer() -> Result<()> {
        let data = create_test_circuit()?;
        let cursor = Cursor::new(data);
        let mut reader = CircuitReaderV2::with_buffer_size(cursor, 32)?; // Small buffer

        // Should still work with small buffer
        let level0 = reader.read_level()?.unwrap();
        assert_eq!(level0.xor_gates.len(), 2);

        let level1 = reader.read_level()?.unwrap();
        assert_eq!(level1.and_gates.len(), 1);

        assert!(reader.read_level()?.is_none());

        Ok(())
    }

    #[test]
    fn test_soa_truncation() -> Result<()> {
        // Create circuit with more gates than SoA array size
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriterV2::new(buffer, 10)?; // 10 primary inputs

        let mut level = Level::new();
        // Add more XOR gates than our test array size
        for i in 0..5 {
            level.xor_gates.push(Gate::new(i, i + 1, 10 + i));
        }

        writer.write_level(&level)?;
        let (cursor, _stats) = writer.finish()?;

        let cursor = Cursor::new(cursor.into_inner());
        let mut reader = CircuitReaderV2::new(cursor)?;

        // Read with small SoA array
        let (xor_gates, and_gates) = reader.read_soa_level::<3>()?.unwrap();

        assert_eq!(xor_gates.count, 3); // Should only read first 3
        assert_eq!(and_gates.count, 0);
        assert_eq!(reader.gates_read(), 5); // But all gates should be consumed

        Ok(())
    }
}

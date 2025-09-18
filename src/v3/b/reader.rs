use cynosure::hints::{likely, unlikely};
use std::io::{Error, ErrorKind, Read, Result};

use super::{
    AndGates, Gate, Level, WireLocation, XorGates,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v3::{CircuitHeaderV3B, FormatType, VERSION};

/// Standard reader for CKT v3b format using std::io traits
pub struct CircuitReaderV3B<R: Read> {
    reader: R,
    /// Buffer for efficient reading
    buffer: Vec<u8>,
    /// Current position in buffer
    buffer_offset: usize,
    /// Valid data end in buffer
    max_valid_bytes: usize,
    /// Current wire counter (next output wire ID)
    wire_counter: u64,
    /// Current level being read
    current_level: u32,
    /// Circuit header
    header: CircuitHeaderV3B,
    /// Number of levels read so far
    levels_read: usize,
    /// Total gates read so far
    gates_read: u64,
    /// Whether we've reached EOF
    eof_reached: bool,
    /// Track level sizes for wire decoding
    level_sizes: Vec<usize>,
}

impl<R: Read> CircuitReaderV3B<R> {
    /// Create a new v3b reader and verify checksum
    pub fn new(reader: R) -> Result<Self> {
        Self::with_buffer_size(reader, 64 * 1024)
    }

    /// Create a new v3b reader with specified buffer size
    pub fn with_buffer_size(mut reader: R, buffer_size: usize) -> Result<Self> {
        // Read header (58 bytes)
        let mut header_bytes = [0u8; CircuitHeaderV3B::SIZE];
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
                format!("Invalid format type for v3b: {}", header_bytes[1]),
            ));
        }

        // Extract checksum
        let mut stored_checksum = [0u8; 32];
        stored_checksum.copy_from_slice(&header_bytes[2..34]);

        // Parse remaining header fields
        let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());

        let header = CircuitHeaderV3B {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum: stored_checksum,
            xor_gates,
            and_gates,
            primary_inputs,
        };

        // Initialize level sizes with level 0 (primary inputs)
        let mut level_sizes = Vec::new();
        level_sizes.push(primary_inputs as usize);

        Ok(Self {
            reader,
            buffer: vec![0; buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            wire_counter: primary_inputs,
            current_level: 1, // Start at level 1 (level 0 is implicit)
            header,
            levels_read: 0,
            gates_read: 0,
            eof_reached: false,
            level_sizes,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeaderV3B {
        &self.header
    }

    /// Get current wire counter
    pub fn wire_counter(&self) -> u64 {
        self.wire_counter
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
            self.wire_counter += 1;
            self.gates_read += 1;
        }

        // Read AND gates
        for _ in 0..num_and {
            let gate = self.read_gate()?;
            level.and_gates.push(gate);
            self.wire_counter += 1;
            self.gates_read += 1;
        }

        // Track level size
        let level_size = (num_xor + num_and) as usize;
        self.level_sizes.push(level_size);

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
            xor_gates.input1s.push(gate.input1);
            xor_gates.input2s.push(gate.input2);
            xor_gates.count += 1;
            self.wire_counter += 1;
            self.gates_read += 1;
        }

        // Read AND gates into SoA
        for _ in 0..num_and {
            let gate = self.read_gate()?;
            and_gates.input1s.push(gate.input1);
            and_gates.input2s.push(gate.input2);
            and_gates.count += 1;
            self.wire_counter += 1;
            self.gates_read += 1;
        }

        // Track level size
        let level_size = (num_xor + num_and) as usize;
        self.level_sizes.push(level_size);

        self.levels_read += 1;
        self.current_level += 1;

        Ok(Some((xor_gates, and_gates)))
    }

    /// Read all remaining levels
    pub fn read_all_levels(&mut self) -> Result<Vec<Level>> {
        let mut levels = Vec::new();
        while let Some(level) = self.read_level()? {
            levels.push(level);
        }
        Ok(levels)
    }

    /// Read a single gate with implicit output
    fn read_gate(&mut self) -> Result<Gate> {
        // Decode input1 wire location
        let (level1, index1) = self.read_wire_location()?;
        let input1 = WireLocation::new(level1, index1);

        // Decode input2 wire location
        let (level2, index2) = self.read_wire_location()?;
        let input2 = WireLocation::new(level2, index2);

        // Output is implicit (current wire counter)
        Ok(Gate::new(input1, input2))
    }

    /// Read and decode a wire location
    fn read_wire_location(&mut self) -> Result<(u32, u32)> {
        // Ensure we have enough data for worst case (1 + 8 + 8 = 17 bytes)
        self.ensure_bytes_available(17)?;

        // Decode directly from buffer
        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (level, index, consumed) =
            FlaggedVarInt::decode_wire_location(buffer_slice, self.current_level)?;

        self.buffer_offset += consumed;

        Ok((level, index))
    }

    /// Read a standard varint
    fn read_standard_varint(&mut self) -> Result<u64> {
        self.ensure_bytes_available(8)?; // Max StandardVarInt size

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = StandardVarInt::decode(buffer_slice)?;

        self.buffer_offset += consumed;

        Ok(varint.value())
    }

    /// Read a flagged varint
    fn read_flagged_varint(&mut self) -> Result<FlaggedVarInt> {
        self.ensure_bytes_available(8)?; // Max FlaggedVarInt size

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = FlaggedVarInt::decode(buffer_slice)?;

        self.buffer_offset += consumed;

        Ok(varint)
    }

    /// Ensure at least `needed` bytes are available in buffer
    fn ensure_bytes_available(&mut self, needed: usize) -> Result<()> {
        let available = self.max_valid_bytes - self.buffer_offset;

        if likely(available >= needed) {
            return Ok(());
        }

        // Compact buffer if needed
        if self.buffer_offset > 0 {
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.max_valid_bytes -= self.buffer_offset;
            self.buffer_offset = 0;
        }

        // Read more data
        self.fill_buffer()?;

        // Check again
        let available = self.max_valid_bytes - self.buffer_offset;
        if available < needed && !self.eof_reached {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", needed, available),
            ));
        }

        Ok(())
    }

    /// Fill buffer with more data
    fn fill_buffer(&mut self) -> Result<()> {
        let buffer_space = self.buffer.len() - self.max_valid_bytes;
        if buffer_space == 0 {
            return Ok(()); // Buffer is full
        }

        let bytes_read = self.reader.read(&mut self.buffer[self.max_valid_bytes..])?;
        if bytes_read == 0 {
            self.eof_reached = true;
        }
        self.max_valid_bytes += bytes_read;

        Ok(())
    }
}

/// Read v3b header from a reader
pub fn read_header<R: Read>(reader: &mut R) -> Result<CircuitHeaderV3B> {
    let mut header_bytes = [0u8; CircuitHeaderV3B::SIZE];
    reader.read_exact(&mut header_bytes)?;

    // Validate version and type
    if header_bytes[0] != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Unsupported version: {}", header_bytes[0]),
        ));
    }

    if header_bytes[1] != FormatType::TypeB.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid format type for v3b: {}", header_bytes[1]),
        ));
    }

    // Extract checksum
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&header_bytes[2..34]);

    // Parse remaining header fields
    let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
    let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
    let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());

    Ok(CircuitHeaderV3B {
        version: header_bytes[0],
        format_type: header_bytes[1],
        checksum,
        xor_gates,
        and_gates,
        primary_inputs,
    })
}

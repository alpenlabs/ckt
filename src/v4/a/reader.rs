use super::varints::{FlaggedVarInt, StandardVarInt};
use super::{CircuitHeader, Gate};
use crate::GateType;
use crate::v4::{FormatType, VERSION};
use cynosure::hints::unlikely;
use std::io::{Error, ErrorKind, Read, Result};

/// Reader for v4a format with credit-aware gate decoding
pub struct CircuitReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    /// Start of valid data in buffer
    buffer_offset: usize,
    /// End of valid data in buffer
    buffer_valid_len: usize,
    total_gates_read: usize,
    header: CircuitHeader,
    outputs: Vec<u64>,
    wire_counter: u64,
    eof_reached: bool,
}

impl<R: Read> CircuitReader<R> {
    /// Create a new v4a reader
    pub fn new(reader: R) -> Result<Self> {
        Self::with_buffer_size(reader, 64 * 1024 * 1024) // 64MB default buffer
    }

    /// Create a new v4a reader with specified buffer size
    pub fn with_buffer_size(mut reader: R, buffer_size: usize) -> Result<Self> {
        // Read fixed header first (66 bytes)
        let mut header_bytes = [0u8; CircuitHeader::FIXED_SIZE];
        reader.read_exact(&mut header_bytes)?;

        // Validate version and type
        if unlikely(header_bytes[0] != VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Unsupported version: expected {}, got {}",
                    VERSION, header_bytes[0]
                ),
            ));
        }

        if unlikely(header_bytes[1] != FormatType::TypeA.to_byte()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid format type for v4a: expected {}, got {}",
                    FormatType::TypeA.to_byte(),
                    header_bytes[1]
                ),
            ));
        }

        // Extract checksum
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&header_bytes[2..34]);

        let header = CircuitHeader {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum,
            xor_gates: u64::from_le_bytes(header_bytes[34..42].try_into().unwrap()),
            and_gates: u64::from_le_bytes(header_bytes[42..50].try_into().unwrap()),
            primary_inputs: u64::from_le_bytes(header_bytes[50..58].try_into().unwrap()),
            num_outputs: u64::from_le_bytes(header_bytes[58..66].try_into().unwrap()),
        };

        // Read output wire IDs efficiently
        let mut outputs = Vec::with_capacity(header.num_outputs as usize);

        // Read outputs in a more streamlined way
        for _ in 0..header.num_outputs {
            // Read first byte to determine length
            let mut first_byte = [0u8; 1];
            reader.read_exact(&mut first_byte)?;

            let length = 1 << (first_byte[0] >> 6);

            if length == 1 {
                let (varint, _) = StandardVarInt::decode(&first_byte)?;
                outputs.push(varint.value());
            } else {
                // Read remaining bytes
                let mut varint_bytes = vec![first_byte[0]];
                varint_bytes.resize(length, 0);
                reader.read_exact(&mut varint_bytes[1..])?;

                let (varint, _) = StandardVarInt::decode(&varint_bytes)?;
                outputs.push(varint.value());
            }
        }

        // Wire counter starts at 2 + primary_inputs
        let wire_counter = 2 + header.primary_inputs;

        let buffer = vec![0u8; buffer_size];

        Ok(Self {
            reader,
            buffer,
            buffer_offset: 0,
            buffer_valid_len: 0,
            total_gates_read: 0,
            header,
            outputs,
            wire_counter,
            eof_reached: false,
        })
    }

    /// Get the circuit header
    #[inline(always)]
    pub fn header(&self) -> &CircuitHeader {
        &self.header
    }

    /// Get output wire IDs
    #[inline(always)]
    pub fn outputs(&self) -> &[u64] {
        &self.outputs
    }

    /// Get total number of gates in the circuit
    #[inline(always)]
    pub fn total_gates(&self) -> u64 {
        self.header.xor_gates + self.header.and_gates
    }

    /// Get number of XOR gates
    #[inline(always)]
    pub fn xor_gates(&self) -> u64 {
        self.header.xor_gates
    }

    /// Get number of AND gates
    #[inline(always)]
    pub fn and_gates(&self) -> u64 {
        self.header.and_gates
    }

    /// Get number of primary inputs
    #[inline(always)]
    pub fn primary_inputs(&self) -> u64 {
        self.header.primary_inputs
    }

    /// Get total gates read so far
    #[inline(always)]
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }

    /// Read next batch of gates (up to 8)
    /// Returns the gates and their types
    #[inline]
    pub fn next_batch(&mut self) -> Result<Option<Vec<(Gate, GateType)>>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if unlikely(self.total_gates_read >= total_gates) {
            return Ok(None);
        }

        // Make sure we have some data
        if self.buffer_offset >= self.buffer_valid_len {
            if !self.refill_buffer()? {
                return Ok(None);
            }
        }

        let mut gates = Vec::with_capacity(8);
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_to_read = gates_remaining.min(8);

        // Read gates efficiently
        for _ in 0..gates_to_read {
            // Ensure we have enough bytes for worst-case gate (4 varints * 8 bytes = 32 bytes)
            if unlikely(self.buffer_valid_len - self.buffer_offset < 32) {
                self.compact_and_refill()?;
            }

            // Decode gate directly from buffer
            let gate = self.read_gate_from_buffer()?;
            gates.push((gate, GateType::XOR)); // Will be fixed after reading gate types
        }

        // Read gate types byte
        if unlikely(self.buffer_offset >= self.buffer_valid_len) {
            self.compact_and_refill()?;
        }

        let gate_types = self.buffer[self.buffer_offset];
        self.buffer_offset += 1;

        // Update gate types
        for (i, (_, gate_type)) in gates.iter_mut().enumerate() {
            *gate_type = if (gate_types >> i) & 1 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            };
        }

        self.total_gates_read += gates.len();
        Ok(Some(gates))
    }

    /// Read a single gate from the buffer
    #[inline(always)]
    fn read_gate_from_buffer(&mut self) -> Result<Gate> {
        let buffer_slice = &self.buffer[self.buffer_offset..self.buffer_valid_len];

        // Decode input1
        let (in1, consumed1) = FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter)?;
        self.buffer_offset += consumed1;

        // Decode input2
        let buffer_slice = &self.buffer[self.buffer_offset..self.buffer_valid_len];
        let (in2, consumed2) = FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter)?;
        self.buffer_offset += consumed2;

        // Decode output
        let buffer_slice = &self.buffer[self.buffer_offset..self.buffer_valid_len];
        let (out, consumed3) = FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter)?;
        self.buffer_offset += consumed3;

        // Update wire counter for next gate
        self.wire_counter = out + 1;

        // Decode credits
        let buffer_slice = &self.buffer[self.buffer_offset..self.buffer_valid_len];
        let (credits_varint, consumed4) = StandardVarInt::decode(buffer_slice)?;
        self.buffer_offset += consumed4;

        Ok(Gate::new(in1, in2, out, credits_varint.value() as u32))
    }

    /// Refill buffer with new data
    #[inline]
    fn refill_buffer(&mut self) -> Result<bool> {
        if self.eof_reached {
            return Ok(false);
        }

        self.buffer_offset = 0;
        self.buffer_valid_len = 0;

        match self.reader.read(&mut self.buffer) {
            Ok(0) => {
                self.eof_reached = true;
                Ok(false)
            }
            Ok(n) => {
                self.buffer_valid_len = n;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Compact buffer and refill
    #[inline]
    fn compact_and_refill(&mut self) -> Result<()> {
        // Move remaining data to beginning
        if self.buffer_offset > 0 && self.buffer_offset < self.buffer_valid_len {
            let remaining = self.buffer_valid_len - self.buffer_offset;
            self.buffer
                .copy_within(self.buffer_offset..self.buffer_valid_len, 0);
            self.buffer_offset = 0;
            self.buffer_valid_len = remaining;
        } else if self.buffer_offset >= self.buffer_valid_len {
            self.buffer_offset = 0;
            self.buffer_valid_len = 0;
        }

        // Fill remaining buffer space
        if !self.eof_reached {
            let buffer_space = self.buffer.len() - self.buffer_valid_len;
            if buffer_space > 0 {
                match self.reader.read(&mut self.buffer[self.buffer_valid_len..]) {
                    Ok(0) => self.eof_reached = true,
                    Ok(n) => self.buffer_valid_len += n,
                    Err(e) => return Err(e),
                }
            }
        }

        // Check if we have any data
        if self.buffer_valid_len == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Unexpected end of file",
            ));
        }

        Ok(())
    }
}

/// Verify the BLAKE3 checksum of a v4a file
/// Returns the checksum if verification succeeds
pub fn verify_checksum<R: std::io::Read>(mut reader: R) -> Result<[u8; 32]> {
    use blake3::Hasher;

    // Read fixed header
    let mut header_bytes = [0u8; CircuitHeader::FIXED_SIZE];
    reader.read_exact(&mut header_bytes)?;

    // Validate version and type
    if header_bytes[0] != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid version: expected {}, got {}",
                VERSION, header_bytes[0]
            ),
        ));
    }

    if header_bytes[1] != FormatType::TypeA.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid format type: expected {}, got {}",
                FormatType::TypeA.to_byte(),
                header_bytes[1]
            ),
        ));
    }

    // Extract stored checksum
    let mut stored_checksum = [0u8; 32];
    stored_checksum.copy_from_slice(&header_bytes[2..34]);

    // Parse num_outputs to skip them properly
    let num_outputs = u64::from_le_bytes(header_bytes[58..66].try_into().unwrap());

    // Skip output wire IDs
    for _ in 0..num_outputs {
        let mut first_byte = [0u8; 1];
        reader.read_exact(&mut first_byte)?;
        let length = 1 << (first_byte[0] >> 6);
        if length > 1 {
            let mut remaining = vec![0u8; length - 1];
            reader.read_exact(&mut remaining)?;
        }
    }

    // Hash all remaining data (batches)
    let mut hasher = Hasher::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Then hash the header fields after checksum
    hasher.update(&header_bytes[34..]); // xor, and, primary_inputs, num_outputs

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

/// Verify the checksum of a v4a file from a path
pub fn verify_checksum_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let file = std::fs::File::open(path)?;
    verify_checksum(std::io::BufReader::new(file))
}

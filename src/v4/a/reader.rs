use super::varints::{FlaggedVarInt, StandardVarInt};
use super::{CircuitHeader, Gate, OutputWire};
use crate::GateType;
use crate::v4::{FormatType, VERSION};
use std::io::{Error, ErrorKind, Read, Result, Seek};

/// Reader for v4a format with credit-aware gate decoding
pub struct CircuitReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    /// Start of valid data in buffer
    valid_start: usize,
    /// End of valid data in buffer (exclusive)
    valid_end: usize,
    total_gates_read: usize,
    header: CircuitHeader,
    outputs: Vec<u64>,
    total_bytes: usize,
    bytes_read: usize,
    wire_counter: u64,
    current_batch_gates: Vec<(Gate, GateType)>,
    current_batch_index: usize,
}

impl<R: Read> CircuitReader<R> {
    /// Create a new v4a reader
    pub fn new(mut reader: R, total_bytes: usize) -> Result<Self> {
        // Read fixed header first (66 bytes)
        let mut header_bytes = [0u8; CircuitHeader::FIXED_SIZE];
        reader.read_exact(&mut header_bytes)?;

        // Validate version and type
        if header_bytes[0] != VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Unsupported version: expected {}, got {}",
                    VERSION, header_bytes[0]
                ),
            ));
        }

        if header_bytes[1] != FormatType::TypeA.to_byte() {
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

        // Read output wire IDs
        let mut outputs = Vec::with_capacity(header.num_outputs as usize);
        let mut output_buffer = vec![0u8; 8]; // Temp buffer for varint reading

        for _ in 0..header.num_outputs {
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

        // Calculate bytes read so far
        let outputs_size = outputs
            .iter()
            .map(|&id| StandardVarInt::encoded_size(id))
            .sum::<usize>();
        let bytes_read = CircuitHeader::FIXED_SIZE + outputs_size;

        // Use 64MB buffer for better throughput
        const BUFFER_SIZE: usize = 64 * 1024 * 1024;
        let buffer = vec![0u8; BUFFER_SIZE];

        // Wire counter starts at 2 + primary_inputs
        let wire_counter = 2 + header.primary_inputs;

        Ok(Self {
            reader,
            buffer,
            valid_start: 0,
            valid_end: 0,
            total_gates_read: 0,
            header,
            outputs,
            total_bytes,
            bytes_read,
            wire_counter,
            current_batch_gates: Vec::with_capacity(8),
            current_batch_index: 0,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeader {
        &self.header
    }

    /// Get output wire IDs
    pub fn outputs(&self) -> &[u64] {
        &self.outputs
    }

    /// Get total number of gates in the circuit
    pub fn total_gates(&self) -> u64 {
        self.header.xor_gates + self.header.and_gates
    }

    /// Get number of XOR gates
    pub fn xor_gates(&self) -> u64 {
        self.header.xor_gates
    }

    /// Get number of AND gates
    pub fn and_gates(&self) -> u64 {
        self.header.and_gates
    }

    /// Get number of primary inputs
    pub fn primary_inputs(&self) -> u64 {
        self.header.primary_inputs
    }

    /// Get total gates read so far
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }

    /// Read next gate
    pub fn next_gate(&mut self) -> Result<Option<(Gate, GateType)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            return Ok(None);
        }

        // If we have gates in current batch, return from there
        if self.current_batch_index < self.current_batch_gates.len() {
            let gate = self.current_batch_gates[self.current_batch_index];
            self.current_batch_index += 1;
            self.total_gates_read += 1;

            // Update wire counter to gate output + 1
            self.wire_counter = gate.0.out + 1;

            return Ok(Some(gate));
        }

        // Need to read a new batch
        self.current_batch_gates.clear();
        self.current_batch_index = 0;

        // Read gates from buffer
        let batch_gates = self.read_batch()?;
        if batch_gates.is_empty() {
            return Ok(None);
        }

        self.current_batch_gates = batch_gates;
        let gate = self.current_batch_gates[0];
        self.current_batch_index = 1;
        self.total_gates_read += 1;

        // Update wire counter to gate output + 1
        self.wire_counter = gate.0.out + 1;

        Ok(Some(gate))
    }

    /// Read a batch of gates
    fn read_batch(&mut self) -> Result<Vec<(Gate, GateType)>> {
        // Ensure we have at least some data in buffer
        self.ensure_bytes_available(1)?; // At least one byte to start

        let mut gates = Vec::with_capacity(8);
        let mut offset = self.valid_start;

        // Read up to 8 gates
        for i in 0..8 {
            // Check if we've read all gates
            if self.total_gates_read + gates.len() >= self.total_gates() as usize {
                break;
            }

            // Helper to ensure bytes for a varint at current offset
            let ensure_varint_bytes = |slf: &mut Self, off: usize| -> Result<()> {
                // Make sure we have at least 1 byte to check varint length
                if off >= slf.valid_end {
                    slf.compact_buffer();
                    slf.fill_buffer()?;
                    if slf.available_bytes() == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "No data available"));
                    }
                }

                // Check first byte to determine varint length
                if off < slf.valid_end {
                    let first_byte = slf.buffer[off];
                    let needed = match first_byte >> 6 {
                        0b00 => 1,
                        0b01 => 2,
                        0b10 => 4,
                        0b11 => 8,
                        _ => unreachable!(),
                    };

                    // Ensure we have the needed bytes
                    if off + needed > slf.valid_end {
                        let bytes_short = (off + needed) - slf.valid_end;
                        slf.ensure_bytes_available(bytes_short)?;
                    }
                }
                Ok(())
            };

            // Decode input1
            ensure_varint_bytes(self, offset)?;
            if offset >= self.valid_end {
                offset = self.valid_start;
                if self.available_bytes() == 0 {
                    break;
                }
            }
            let (in1, consumed) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.valid_end],
                self.wire_counter,
            )?;
            offset += consumed;

            // Decode input2
            ensure_varint_bytes(self, offset)?;
            if offset >= self.valid_end {
                offset = self.valid_start;
            }
            let (in2, consumed) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.valid_end],
                self.wire_counter,
            )?;
            offset += consumed;

            // Decode output
            ensure_varint_bytes(self, offset)?;
            if offset >= self.valid_end {
                offset = self.valid_start;
            }
            let (out, consumed) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.valid_end],
                self.wire_counter,
            )?;
            offset += consumed;

            // Decode credits
            ensure_varint_bytes(self, offset)?;
            if offset >= self.valid_end {
                offset = self.valid_start;
            }
            let (credits_varint, consumed) =
                StandardVarInt::decode(&self.buffer[offset..self.valid_end])?;
            offset += consumed;

            gates.push((
                Gate::new(in1, in2, out, credits_varint.value() as u32),
                GateType::XOR, // Will be updated after reading gate types
            ));
        }

        if gates.is_empty() {
            self.valid_start = offset;
            return Ok(gates);
        }

        // Read gate types byte
        if offset >= self.valid_end {
            self.ensure_bytes_available(1)?;
            offset = self.valid_start;
        }

        let gate_types = self.buffer[offset];
        offset += 1;

        // Update gate types
        for (i, (_, gate_type)) in gates.iter_mut().enumerate() {
            *gate_type = if (gate_types >> i) & 1 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            };
        }

        self.valid_start = offset;
        Ok(gates)
    }

    /// Get number of bytes currently available in buffer
    #[inline]
    fn available_bytes(&self) -> usize {
        self.valid_end - self.valid_start
    }

    /// Ensure at least `needed` bytes are available in the buffer
    fn ensure_bytes_available(&mut self, needed: usize) -> Result<()> {
        // Fast path: already have enough bytes
        if self.available_bytes() >= needed {
            return Ok(());
        }

        // Check if file has enough remaining bytes
        let bytes_remaining_in_file = self.total_bytes - self.bytes_read;
        let bytes_available_total = self.available_bytes() + bytes_remaining_in_file;

        if bytes_available_total < needed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "Not enough data: need {} bytes but only {} available",
                    needed, bytes_available_total
                ),
            ));
        }

        // Try to fill first without compacting
        self.fill_buffer()?;

        // If still not enough space and we can compact, do it now
        if self.available_bytes() < needed {
            let space_at_end = self.buffer.len() - self.valid_end;
            if space_at_end < needed && self.valid_start > 0 {
                self.compact_buffer();
                self.fill_buffer()?; // Try filling again after compact
            }
        }

        Ok(())
    }

    /// Move remaining valid data to start of buffer
    fn compact_buffer(&mut self) {
        let available = self.available_bytes();
        if available > 0 && self.valid_start > 0 {
            self.buffer.copy_within(self.valid_start..self.valid_end, 0);
            self.valid_start = 0;
            self.valid_end = available;
        } else if available == 0 {
            self.valid_start = 0;
            self.valid_end = 0;
        }
    }

    /// Fill buffer with more data from reader
    fn fill_buffer(&mut self) -> Result<()> {
        // Calculate how many bytes we still need to read from the file
        let bytes_remaining = self.total_bytes - self.bytes_read;

        if bytes_remaining == 0 {
            return Ok(()); // Already read everything
        }

        // Keep reading until buffer is full or no more data
        while self.valid_end < self.buffer.len() && bytes_remaining > 0 {
            // Calculate how much to read this iteration
            let buffer_space = self.buffer.len() - self.valid_end;
            let to_read = buffer_space.min(bytes_remaining);

            if to_read == 0 {
                break; // Buffer is full
            }

            let bytes_read = self
                .reader
                .read(&mut self.buffer[self.valid_end..self.valid_end + to_read])?;

            if bytes_read == 0 {
                // EOF reached but we expected more data
                if bytes_remaining > 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("Unexpected EOF: expected {} more bytes", bytes_remaining),
                    ));
                }
                break;
            }

            self.valid_end += bytes_read;
            self.bytes_read += bytes_read;
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

    // Hash all data after checksum
    let mut hasher = Hasher::new();

    // First hash remaining batches
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

use cynosure::hints::{likely, prefetch_read_data, unlikely};
use monoio::fs::File;
use std::io::{Error, ErrorKind, Result};

use crate::GateType;
use crate::v4::a::{
    CircuitHeader, Gate,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v4::{FormatType, VERSION};

/// High performance async reader for CKT v4a format using monoio
pub struct CircuitReader {
    file: File,
    /// Buffer used for file reads with monoio
    buffer: Vec<u8>,
    /// Current position in the buffer offset
    buffer_offset: usize,
    /// How many valid bytes there are in the buffer
    max_valid_bytes: usize,
    /// Total gates read so far
    total_gates_read: usize,
    /// Circuit header
    header: CircuitHeader,
    /// Output wire IDs
    outputs: Vec<u64>,
    /// Total bytes in the file
    total_bytes: u64,
    /// How many bytes we've read from file
    bytes_read: u64,
    /// Current wire counter for relative decoding
    wire_counter: u64,
}

impl CircuitReader {
    /// Create a new v4a reader
    pub async fn new(file: File, max_buffer_size: usize) -> Result<Self> {
        let len = file.metadata().await?.len();

        // Read fixed header (66 bytes)
        let (res, header_bytes) = file
            .read_exact_at(Vec::with_capacity(CircuitHeader::FIXED_SIZE), 0)
            .await;
        res?;

        if unlikely(header_bytes.len() != CircuitHeader::FIXED_SIZE) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Incomplete header read",
            ));
        }

        // Validate version and type
        if unlikely(header_bytes[0] != VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", header_bytes[0]),
            ));
        }

        if unlikely(header_bytes[1] != FormatType::TypeA.to_byte()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid format type for v4a: {}", header_bytes[1]),
            ));
        }

        // Extract checksum
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&header_bytes[2..34]);

        // Parse remaining header fields
        let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());
        let num_outputs = u64::from_le_bytes(header_bytes[58..66].try_into().unwrap());

        let header = CircuitHeader {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum,
            xor_gates,
            and_gates,
            primary_inputs,
            num_outputs,
        };

        // Read output wire IDs
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        let mut offset = CircuitHeader::FIXED_SIZE as u64;

        // Read outputs one by one since they're variable length
        for _ in 0..num_outputs {
            // Read first byte to determine length
            let (res, first_byte) = file.read_exact_at(vec![0u8; 1], offset).await;
            res?;
            offset += 1;

            let length = match first_byte[0] >> 6 {
                0b00 => 1,
                0b01 => 2,
                0b10 => 4,
                0b11 => 8,
                _ => unreachable!(),
            };

            if length > 1 {
                // Read remaining bytes
                let (res, remaining_bytes) =
                    file.read_exact_at(vec![0u8; length - 1], offset).await;
                res?;
                offset += (length - 1) as u64;

                // Combine first byte with remaining
                let mut varint_bytes = vec![first_byte[0]];
                varint_bytes.extend_from_slice(&remaining_bytes);
                let (varint, _) = StandardVarInt::decode(&varint_bytes)?;
                outputs.push(varint.value());
            } else {
                // Single byte varint - first_byte is already the complete varint
                let (varint, _) = StandardVarInt::decode(&first_byte)?;
                outputs.push(varint.value());
            }
        }

        // Wire counter starts at 2 + primary_inputs
        let wire_counter = 2 + primary_inputs;

        Ok(Self {
            file,
            buffer: vec![0; max_buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            total_gates_read: 0,
            header,
            outputs,
            total_bytes: len,
            bytes_read: offset,
            wire_counter,
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

    /// Read next batch of gates (up to 8)
    /// Returns the gates and their types
    pub async fn next_batch(&mut self) -> Result<Option<Vec<(Gate, GateType)>>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if unlikely(self.total_gates_read >= total_gates) {
            return Ok(None);
        }

        // Fill buffer if needed
        if self.buffer_offset >= self.max_valid_bytes {
            self.fill_buffer().await?;
        }

        // Read gates from buffer
        let batch_gates = self.read_batch()?;
        if batch_gates.is_empty() {
            return Ok(None);
        }

        self.total_gates_read += batch_gates.len();
        Ok(Some(batch_gates))
    }

    /// Read a batch of gates from the buffer
    #[inline]
    fn read_batch(&mut self) -> Result<Vec<(Gate, GateType)>> {
        let mut gates = Vec::with_capacity(8);

        // Calculate how many gates in this batch are valid
        let total_gates = self.total_gates() as usize;
        let gates_remaining = total_gates - self.total_gates_read;
        let valid_gates_in_batch = gates_remaining.min(8);

        if valid_gates_in_batch == 0 {
            return Ok(gates);
        }

        // We always read 8 gates per batch (unused ones are zeroed)
        // Ensure we have enough data for worst case (32 bytes per gate + 1 byte types)
        let min_needed = 8 * 32 + 1;
        if unlikely(self.max_valid_bytes - self.buffer_offset < min_needed) {
            // We might not have all the data, but try to read what we can
        }

        // Always read 8 gates (the writer writes full batches with unused slots zeroed)
        for i in 0..8 {
            // For gates beyond valid_gates_in_batch, they should be zero
            // But we still need to read them to advance past the batch correctly

            // Decode input1
            let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
            let (in1, consumed1) =
                match FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter) {
                    Ok(result) => result,
                    Err(_) if i < valid_gates_in_batch => {
                        // Error reading a valid gate - this is a problem
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "Failed to read valid gate",
                        ));
                    }
                    Err(_) => {
                        // Error reading a zeroed gate - might be at end of buffer
                        break;
                    }
                };
            self.buffer_offset += consumed1;

            // Decode input2
            let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
            let (in2, consumed2) =
                match FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter) {
                    Ok(result) => result,
                    Err(_) => {
                        self.buffer_offset -= consumed1; // Rollback
                        break;
                    }
                };
            self.buffer_offset += consumed2;

            // Decode output
            let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
            let (out, consumed3) =
                match FlaggedVarInt::decode_wire_id(buffer_slice, self.wire_counter) {
                    Ok(result) => result,
                    Err(_) => {
                        self.buffer_offset -= consumed1 + consumed2; // Rollback
                        break;
                    }
                };
            self.buffer_offset += consumed3;

            // Update wire counter for next gate
            self.wire_counter = out + 1;

            // Decode credits
            let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
            let (credits_varint, consumed4) = match StandardVarInt::decode(buffer_slice) {
                Ok(result) => result,
                Err(_) => {
                    self.buffer_offset -= consumed1 + consumed2 + consumed3; // Rollback
                    self.wire_counter = out; // Also rollback wire counter
                    break;
                }
            };
            self.buffer_offset += consumed4;

            // Only add gates that are within the valid range
            if i < valid_gates_in_batch {
                gates.push((
                    Gate::new(in1, in2, out, credits_varint.value() as u32),
                    GateType::XOR, // Will be updated after reading gate types
                ));
            }

            // Prefetch next gate data if available
            if likely(self.buffer_offset + 32 < self.max_valid_bytes) {
                unsafe {
                    prefetch_read_data(self.buffer.as_ptr().add(self.buffer_offset + 32), 0);
                }
            }
        }

        // Read gate types byte - always present after 8 gates
        if unlikely(self.buffer_offset >= self.max_valid_bytes) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Missing gate types byte after batch",
            ));
        }

        let gate_types = self.buffer[self.buffer_offset];
        self.buffer_offset += 1;

        // Update gate types for the valid gates we read
        for (i, (_, gate_type)) in gates.iter_mut().enumerate() {
            *gate_type = if (gate_types >> i) & 1 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            };
        }

        Ok(gates)
    }

    /// Fill buffer with more data from file
    async fn fill_buffer(&mut self) -> Result<()> {
        // Reset buffer
        self.buffer_offset = 0;
        self.max_valid_bytes = 0;

        // Check if we've reached end of file
        if unlikely(self.bytes_read >= self.total_bytes) {
            return Ok(());
        }

        // Read more data
        let remaining_in_file = self.total_bytes - self.bytes_read;
        let to_read = self.buffer.len().min(remaining_in_file as usize);

        if to_read == 0 {
            return Ok(());
        }

        // Read from file
        let read_buffer = self.buffer[..to_read].to_vec();
        let (res, returned_buffer) = self.file.read_at(read_buffer, self.bytes_read).await;
        let bytes_read = res?;

        if bytes_read > 0 {
            // Copy read data back to buffer
            self.buffer[..bytes_read].copy_from_slice(&returned_buffer[..bytes_read]);
            self.max_valid_bytes = bytes_read;
            self.bytes_read += bytes_read as u64;

            // Prefetch first part of buffer
            if likely(self.max_valid_bytes > 0) {
                unsafe {
                    prefetch_read_data(self.buffer.as_ptr(), 0);
                }
            }
        }

        Ok(())
    }
}

/// Async function to verify the BLAKE3 checksum of a v4a file
/// Returns the checksum if verification succeeds
pub async fn verify_checksum_async(file: File) -> Result<[u8; 32]> {
    use blake3::Hasher;

    let len = file.metadata().await?.len();

    // Read header
    let (res, header_bytes) = file
        .read_exact_at(Vec::with_capacity(CircuitHeader::FIXED_SIZE), 0)
        .await;
    res?;

    // Validate version and type
    if header_bytes[0] != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid version: {}", header_bytes[0]),
        ));
    }

    if header_bytes[1] != FormatType::TypeA.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid format type: {}", header_bytes[1]),
        ));
    }

    // Extract stored checksum
    let mut stored_checksum = [0u8; 32];
    stored_checksum.copy_from_slice(&header_bytes[2..34]);

    // Parse num_outputs from header
    let num_outputs = u64::from_le_bytes(header_bytes[58..66].try_into().unwrap());

    // Read output wire IDs first (they're written after header but hashed last)
    let mut offset = CircuitHeader::FIXED_SIZE as u64;
    let mut output_buffers = Vec::new();

    for _ in 0..num_outputs {
        // Read first byte to determine length
        let (res, first_byte) = file.read_exact_at(vec![0u8; 1], offset).await;
        res?;
        offset += 1;

        let length = match first_byte[0] >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        };

        let mut varint_bytes = vec![first_byte[0]];
        if length > 1 {
            // Read remaining bytes
            let (res, remaining_bytes) = file.read_exact_at(vec![0u8; length - 1], offset).await;
            res?;
            offset += (length - 1) as u64;
            varint_bytes.extend_from_slice(&remaining_bytes);
        }

        output_buffers.push(varint_bytes);
    }

    // Now hash the batches (rest of file after outputs)
    let mut hasher = Hasher::new();
    let buffer = vec![0u8; 1024 * 1024]; // 1MB buffer

    while offset < len {
        let to_read = buffer.len().min((len - offset) as usize);
        let (res, read_buffer) = file.read_at(buffer[..to_read].to_vec(), offset).await;
        let bytes_read = res?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&read_buffer[..bytes_read]);
        offset += bytes_read as u64;
    }

    // Then hash the header fields after checksum
    hasher.update(&header_bytes[34..]); // xor, and, primary_inputs, num_outputs

    // Finally hash the output wire IDs (as the writer does)
    for output_bytes in &output_buffers {
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

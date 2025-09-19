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
    /// Current batch of decoded gates
    current_batch_gates: Vec<(Gate, GateType)>,
    /// Current index in the batch
    current_batch_index: usize,
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
    pub async fn next_gate(&mut self) -> Result<Option<(Gate, GateType)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if unlikely(self.total_gates_read >= total_gates) {
            return Ok(None);
        }

        // If we have gates in current batch, return from there
        if self.current_batch_index < self.current_batch_gates.len() {
            let gate = self.current_batch_gates[self.current_batch_index];
            self.current_batch_index += 1;
            self.total_gates_read += 1;

            // Wire counter already updated in read_batch, no need to update again

            return Ok(Some(gate));
        }

        // Need to read a new batch
        self.current_batch_gates.clear();
        self.current_batch_index = 0;

        // Fill buffer if needed
        if self.buffer_offset >= self.max_valid_bytes {
            self.fill_buffer().await?;
        }

        // Read gates from buffer
        let batch_gates = self.read_batch()?;
        if batch_gates.is_empty() {
            return Ok(None);
        }

        self.current_batch_gates = batch_gates;
        let gate = self.current_batch_gates[0];
        self.current_batch_index = 1;
        self.total_gates_read += 1;

        // Wire counter already updated in read_batch, no need to update again

        Ok(Some(gate))
    }

    /// Read a batch of gates from the buffer
    fn read_batch(&mut self) -> Result<Vec<(Gate, GateType)>> {
        let mut gates = Vec::with_capacity(8);
        let mut offset = self.buffer_offset;

        // Read up to 8 gates
        for _ in 0..8 {
            // Check if we've read all gates
            if self.total_gates_read + gates.len() >= self.total_gates() as usize {
                break;
            }

            // Check if we have enough bytes for at least one byte
            if offset >= self.max_valid_bytes {
                break;
            }

            // Helper to read a varint with proper length checking
            let read_varint = |buffer: &[u8], off: usize| -> Option<usize> {
                if off >= buffer.len() {
                    return None;
                }
                let first = buffer[off];
                match first >> 6 {
                    0b00 => Some(1),
                    0b01 => Some(2),
                    0b10 => Some(4),
                    0b11 => Some(8),
                    _ => None,
                }
            };

            // Read input1
            let len1 = read_varint(&self.buffer[..self.max_valid_bytes], offset);
            if len1.is_none() || offset + len1.unwrap() > self.max_valid_bytes {
                break;
            }
            let (in1, consumed1) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.max_valid_bytes],
                self.wire_counter,
            )?;
            offset += consumed1;

            // Read input2
            let len2 = read_varint(&self.buffer[..self.max_valid_bytes], offset);
            if len2.is_none() || offset + len2.unwrap() > self.max_valid_bytes {
                break;
            }
            let (in2, consumed2) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.max_valid_bytes],
                self.wire_counter,
            )?;
            offset += consumed2;

            // Read output
            let len3 = read_varint(&self.buffer[..self.max_valid_bytes], offset);
            if len3.is_none() || offset + len3.unwrap() > self.max_valid_bytes {
                break;
            }
            let (out, consumed3) = FlaggedVarInt::decode_wire_id(
                &self.buffer[offset..self.max_valid_bytes],
                self.wire_counter,
            )?;
            offset += consumed3;

            // Update wire counter for next gate
            self.wire_counter = out + 1;

            // Read credits
            let len4 = read_varint(&self.buffer[..self.max_valid_bytes], offset);
            if len4.is_none() || offset + len4.unwrap() > self.max_valid_bytes {
                break;
            }
            let (credits_varint, consumed4) =
                StandardVarInt::decode(&self.buffer[offset..self.max_valid_bytes])?;
            offset += consumed4;

            gates.push((
                Gate::new(in1, in2, out, credits_varint.value() as u32),
                GateType::XOR, // Will be updated after reading gate types
            ));

            // Update wire counter for next gate in batch
            self.wire_counter = out + 1;

            // Prefetch next gate data if available
            if likely(offset + 32 < self.max_valid_bytes) {
                unsafe {
                    prefetch_read_data(self.buffer.as_ptr().add(offset + 32), 0);
                }
            }
        }

        if gates.is_empty() {
            self.buffer_offset = offset;
            return Ok(gates);
        }

        // Read gate types byte
        if offset >= self.max_valid_bytes {
            return Ok(gates); // Incomplete batch, return what we have
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

        self.buffer_offset = offset;
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

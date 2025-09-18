use cynosure::hints::{likely, prefetch_read_data, unlikely};
use monoio::fs::File;
use std::io::{Error, ErrorKind, Result};

use crate::v3::a::{CircuitHeader, GateBatch34};
use crate::v3::{FormatType, VERSION};

/// High performance async reader for CKT v3a format using monoio
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
    /// Total bytes in the file
    total_bytes: u64,
    /// How many bytes we've read from file
    bytes_read: u64,
}

impl CircuitReader {
    /// Create a new v3a reader
    pub async fn new(file: File, max_buffer_size: usize) -> Result<Self> {
        let len = file.metadata().await?.len();

        // Read header (58 bytes)
        let (res, header_bytes) = file
            .read_exact_at(Vec::with_capacity(CircuitHeader::SIZE), 0)
            .await;
        res?;

        if unlikely(header_bytes.len() != CircuitHeader::SIZE) {
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
                format!("Invalid format type for v3a: {}", header_bytes[1]),
            ));
        }

        // Extract checksum
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&header_bytes[2..34]);

        // Parse remaining header fields
        let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());

        let header = CircuitHeader {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum,
            xor_gates,
            and_gates,
            primary_inputs,
        };

        Ok(Self {
            file,
            buffer: vec![0; max_buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            total_gates_read: 0,
            header,
            total_bytes: len,
            bytes_read: CircuitHeader::SIZE as u64,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeader {
        &self.header
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

    /// Read next batch of gates
    /// Returns the batch and the number of valid gates in it (1-8)
    #[inline]
    pub async fn next_batch(&mut self) -> Result<Option<(GateBatch34, usize)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if unlikely(self.total_gates_read >= total_gates) {
            return Ok(None);
        }

        // Ensure we have enough data
        if unlikely(self.buffer_offset == self.max_valid_bytes)
            && unlikely(!self.fill_buffer().await?) {
                return Ok(None);
            }

        // Check if we have a full batch
        if unlikely(self.max_valid_bytes - self.buffer_offset < GateBatch34::SIZE) {
            // Try to get more data
            if !self.fill_buffer().await? {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Unexpected end of circuit data",
                ));
            }
        }

        // Extract batch from buffer
        let mut batch_bytes = [0u8; GateBatch34::SIZE];
        batch_bytes.copy_from_slice(
            &self.buffer[self.buffer_offset..self.buffer_offset + GateBatch34::SIZE],
        );
        let batch = GateBatch34::from_bytes(&batch_bytes);
        self.buffer_offset += GateBatch34::SIZE;

        // Prefetch next batch if available
        if likely(self.buffer_offset + GateBatch34::SIZE <= self.max_valid_bytes) {
            unsafe {
                prefetch_read_data(
                    self.buffer
                        .as_ptr()
                        .add(self.buffer_offset + GateBatch34::SIZE),
                    0,
                );
            }
        }

        // Calculate how many gates are valid in this batch
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_in_batch = gates_remaining.min(8);
        self.total_gates_read += gates_in_batch;

        Ok(Some((batch, gates_in_batch)))
    }

    /// Skip a number of batches without processing them
    pub async fn skip_batches(&mut self, num_batches: usize) -> Result<()> {
        if num_batches == 0 {
            return Ok(());
        }

        let bytes_to_skip = num_batches * GateBatch34::SIZE;
        let gates_to_skip =
            (num_batches * 8).min(self.total_gates() as usize - self.total_gates_read);

        // Update gates count
        self.total_gates_read += gates_to_skip;

        // First, skip any data remaining in the buffer
        let buffer_remaining = self.max_valid_bytes - self.buffer_offset;
        if buffer_remaining > 0 {
            let skip_from_buffer = buffer_remaining.min(bytes_to_skip);
            self.buffer_offset += skip_from_buffer;

            if skip_from_buffer == bytes_to_skip {
                return Ok(());
            }

            // If we've consumed the entire buffer, reset it
            if self.buffer_offset >= self.max_valid_bytes {
                self.buffer_offset = 0;
                self.max_valid_bytes = 0;
            }

            // Calculate remaining bytes to skip from file
            let remaining_to_skip = bytes_to_skip - skip_from_buffer;
            self.bytes_read += remaining_to_skip as u64;
        } else {
            // Buffer is empty, skip directly in file
            self.bytes_read += bytes_to_skip as u64;
        }

        Ok(())
    }

    /// Fill buffer with more raw gates
    async fn fill_buffer(&mut self) -> Result<bool> {
        // Compact buffer if needed
        if self.buffer_offset > 0 && self.buffer_offset < self.max_valid_bytes {
            let remaining = self.max_valid_bytes - self.buffer_offset;
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.buffer_offset = 0;
            self.max_valid_bytes = remaining;
        } else if self.buffer_offset >= self.max_valid_bytes {
            self.buffer_offset = 0;
            self.max_valid_bytes = 0;
        }

        // Check if we've reached end of file
        if unlikely(self.bytes_read >= self.total_bytes) {
            return Ok(false);
        }

        // Read more data
        let buffer_space = self.buffer.len() - self.max_valid_bytes;
        let remaining_in_file = self.total_bytes - self.bytes_read;
        let to_read = buffer_space.min(remaining_in_file as usize);

        if to_read == 0 {
            return Ok(self.max_valid_bytes > self.buffer_offset);
        }

        // Read from file
        let read_buffer =
            self.buffer[self.max_valid_bytes..self.max_valid_bytes + to_read].to_vec();
        let (res, returned_buffer) = self.file.read_at(read_buffer, self.bytes_read).await;
        let bytes_read = res?;

        if bytes_read > 0 {
            // Copy read data back to buffer
            self.buffer[self.max_valid_bytes..self.max_valid_bytes + bytes_read]
                .copy_from_slice(&returned_buffer[..bytes_read]);
            self.max_valid_bytes += bytes_read;
            self.bytes_read += bytes_read as u64;
        }

        Ok(bytes_read > 0)
    }
}

/// Async function to verify the BLAKE3 checksum of a v3a file
/// Returns the checksum if verification succeeds
pub async fn verify_checksum_async(file: File) -> Result<[u8; 32]> {
    use blake3::Hasher;

    let len = file.metadata().await?.len();

    // Read header
    let (res, header_bytes) = file
        .read_exact_at(Vec::with_capacity(CircuitHeader::SIZE), 0)
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

    // Hash all gate data first
    let mut hasher = Hasher::new();
    let mut offset = CircuitHeader::SIZE as u64;
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

    // Then hash the header fields after checksum (xor, and, primary_inputs)
    hasher.update(&header_bytes[34..]);

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

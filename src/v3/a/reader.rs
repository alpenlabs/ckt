use super::GateBatch34;
use crate::v3::{FormatType, VERSION, a::CircuitHeader};
use std::io::{Error, ErrorKind, Read, Result, Seek};

/// Reader for compressed circuit format with batch API
pub struct CircuitReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    /// Start of valid data in buffer
    valid_start: usize,
    /// End of valid data in buffer (exclusive)
    valid_end: usize,
    total_gates_read: usize,
    header: CircuitHeader,
    total_bytes: usize,
    bytes_read: usize,
}

impl<R: Read> CircuitReader<R> {
    /// Create a new v3a reader
    pub fn new(mut reader: R, total_bytes: usize) -> Result<Self> {
        // Read header first (18 bytes: 1 version + 1 type + 8 xor + 8 and)
        let mut header_bytes = [0u8; CircuitHeader::SIZE];
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
                    "Invalid format type for v3a: expected {}, got {}",
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
        };

        // Use 64MB buffer for better throughput
        const BUFFER_SIZE: usize = 64 * 1024 * 1024;
        let buffer = vec![0u8; BUFFER_SIZE];

        Ok(Self {
            reader,
            buffer,
            valid_start: 0,
            valid_end: 0,
            total_gates_read: 0,
            header,
            total_bytes,
            bytes_read: CircuitHeader::SIZE,
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

    /// Get total gates read so far
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }

    /// Read next batch of gates
    /// Returns the batch and the number of valid gates in it (1-8)
    #[inline]
    pub fn next_batch(&mut self) -> Result<Option<(GateBatch34, usize)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            return Ok(None);
        }

        // Ensure we have a full batch worth of data
        self.ensure_bytes_available(GateBatch34::SIZE)?;

        // Check if we actually got enough data
        if self.available_bytes() < GateBatch34::SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected end of circuit data",
            ));
        }

        // Extract batch from buffer
        let mut batch_bytes = [0u8; GateBatch34::SIZE];
        batch_bytes
            .copy_from_slice(&self.buffer[self.valid_start..self.valid_start + GateBatch34::SIZE]);
        let batch = GateBatch34::from_bytes(&batch_bytes);
        self.valid_start += GateBatch34::SIZE;

        // Calculate how many gates are valid in this batch
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_in_batch = gates_remaining.min(8);
        self.total_gates_read += gates_in_batch;

        Ok(Some((batch, gates_in_batch)))
    }

    /// Read next batch of gates as a zero-copy reference
    ///
    /// The returned reference is valid only as long as you hold the reference
    /// and don't call any other methods on this reader. The borrow checker
    /// enforces this safety guarantee at compile time.
    #[inline]
    pub fn next_batch_ref(&mut self) -> Result<Option<(&GateBatch34, usize)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            return Ok(None);
        }

        // Ensure we have a full batch worth of data
        self.ensure_bytes_available(GateBatch34::SIZE)?;

        // Check if we actually got enough data
        if self.available_bytes() < GateBatch34::SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected end of circuit data",
            ));
        }

        // We can't actually provide zero-copy for v3a due to the bit packing
        // The 34-bit values are packed across byte boundaries, making zero-copy references impossible
        // Users should use next_batch() instead
        Err(Error::new(
            ErrorKind::Unsupported,
            "Zero-copy batch reference not supported for v3a format due to bit packing. Use next_batch() instead.",
        ))
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
        let mut bytes_remaining = self.total_bytes - self.bytes_read;

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
            dbg!(bytes_read);

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
            bytes_remaining -= bytes_read;
        }

        Ok(())
    }
}

/// Read v3a circuit header (works with any reader)
pub fn read_header<R: Read>(reader: &mut R) -> Result<CircuitHeader> {
    let mut header_bytes = [0u8; CircuitHeader::SIZE];
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
                "Invalid format type for v3a: expected {}, got {}",
                FormatType::TypeA.to_byte(),
                header_bytes[1]
            ),
        ));
    }

    // Extract checksum
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&header_bytes[2..34]);

    Ok(CircuitHeader {
        version: header_bytes[0],
        format_type: header_bytes[1],
        checksum,
        xor_gates: u64::from_le_bytes(header_bytes[34..42].try_into().unwrap()),
        and_gates: u64::from_le_bytes(header_bytes[42..50].try_into().unwrap()),
    })
}

/// Read v3a circuit header from seekable stream and reset position
pub fn read_header_seekable<S: Read + Seek>(reader: &mut S) -> Result<CircuitHeader> {
    use std::io::SeekFrom;

    let current_pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(0))?;
    let header = read_header(reader)?;
    reader.seek(SeekFrom::Start(current_pos))?;

    Ok(header)
}

/// Verify the BLAKE3 checksum of a v3a file
/// Returns the checksum if verification succeeds
pub fn verify_checksum<R: std::io::Read>(mut reader: R) -> Result<[u8; 32]> {
    use blake3::Hasher;

    // Read header
    let mut header_bytes = [0u8; CircuitHeader::SIZE];
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

    // Hash all gate data first
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

/// Verify the checksum of a v3a file from a path
/// Returns the checksum if verification succeeds
pub fn verify_checksum_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let file = std::fs::File::open(path)?;
    verify_checksum(std::io::BufReader::new(file))
}

// TODO: Add proper tests for v3a format with 34-bit wire IDs

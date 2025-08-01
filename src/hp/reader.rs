use monoio::fs::File;

use crate::{CircuitHeader, GateBatch};
use cynosure::hints::{likely, prefetch_read_data, unlikely};
use std::io::{Read, Result, Seek};

/// High performance file reader for CKT format from a [monoio::fs::File]
pub struct CircuitReader {
    file: File,
    /// buf used for file reads with monoio
    buffer: Vec<u8>,
    /// gates left to read according to header
    gates_remaining: usize,
    /// how many valid bytes there are in the buffer
    max_valid_bytes: usize,
    header: CircuitHeader,
    /// total bytes in the file
    total_bytes: u64,
    /// how many bytes we've read
    bytes_read: u64,
    /// current position in the buffer offset
    buffer_offset: usize,
}

impl CircuitReader {
    /// Create a new reader
    pub async fn new(file: File, max_batches_in_buf: usize) -> Result<Self> {
        let (res, header_bytes) = file.read_exact_at(Vec::with_capacity(8), 0).await;
        res?;

        let len = file.metadata().await?.len();

        let header = CircuitHeader {
            xor_gates: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
            and_gates: u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()),
        };

        Ok(Self {
            file,
            buffer: vec![0; max_batches_in_buf * GateBatch::SIZE],
            gates_remaining: (header.and_gates + header.xor_gates) as usize,
            header,
            total_bytes: len,
            bytes_read: 8,
            max_valid_bytes: 0,
            buffer_offset: 0,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeader {
        &self.header
    }

    /// Get total number of gates in the circuit
    pub fn total_gates(&self) -> u32 {
        self.header.xor_gates + self.header.and_gates
    }

    /// Get number of XOR gates
    pub fn xor_gates(&self) -> u32 {
        self.header.xor_gates
    }

    /// Get number of AND gates
    pub fn and_gates(&self) -> u32 {
        self.header.and_gates
    }

    /// Read next batch of gates as a zero-copy reference
    ///
    /// The returned reference is valid only as long as you hold the reference
    /// and don't call any other methods on this reader. The borrow checker
    /// enforces this safety guarantee at compile time.
    #[inline]
    pub async fn next_batch(&mut self) -> Result<Option<(&GateBatch, usize)>> {
        if unlikely(self.buffer_offset == self.max_valid_bytes) {
            if unlikely(!self.fill_buffer().await?) {
                return Ok(None);
            };
        }

        // safety: if self.buffer_offset >= self.max_valid_bytes we would've reset
        // self.buffer_offset back to 0
        let batch_ptr = unsafe { self.buffer.as_ptr().add(self.buffer_offset) };
        let batch_slice = unsafe { std::slice::from_raw_parts(batch_ptr, GateBatch::SIZE) };
        // Cast buffer bytes directly to GateBatch reference (zero-copy)
        let batch_ref = GateBatch::from_bytes_ref(batch_slice);

        // move offset forward for next read
        self.buffer_offset += GateBatch::SIZE;

        // if next batch is valid, prefetch it into L1 cache
        if likely(self.buffer_offset != self.max_valid_bytes) {
            // safety: not null pointer
            unsafe { prefetch_read_data(batch_ptr.add(GateBatch::SIZE), 0) };
        }

        // Calculate how many gates are valid in this batch
        let gates_in_batch = if unlikely(self.gates_remaining <= 8) {
            self.gates_remaining
        } else {
            8
        };

        self.gates_remaining -= gates_in_batch;

        Ok(Some((batch_ref, gates_in_batch)))
    }

    /// Fill buffer with more raw gates. Only call when self.buffer_offset == self.max_valid_bytes
    ///
    /// This will read bytes into self.buffer. It guarantees that this data's length is a multiple of GateBatch::SIZE.
    async fn fill_buffer(&mut self) -> Result<bool> {
        // how many bytes we've read in this fill_buffer call
        let mut total_bytes_read = 0;
        let mut buf = std::mem::take(&mut self.buffer);

        // Keep reading until we get a multiple of GateBatch::SIZE bytes
        Ok(loop {
            if unlikely(self.bytes_read == self.total_bytes) {
                break false;
            }
            let (res, returned_buf) = self.file.read_at(buf, self.bytes_read).await;
            let bytes_read = res?;
            total_bytes_read += bytes_read;

            // have we read a number of complete batches?
            if likely(total_bytes_read % GateBatch::SIZE == 0) {
                // return the buffer back to the reader
                self.buffer = returned_buf;
                // the buffer has been filled with some data
                self.max_valid_bytes = total_bytes_read;
                // for tracking if we're at the end of the file
                self.bytes_read += total_bytes_read as u64;
                // for r
                self.buffer_offset = 0;
                break true;
            } else {
                // keep going until we get a proper number of batches
                buf = returned_buf;
            }
        })
    }
}

/// Read circuit header (works with any reader)
pub fn read_header<R: Read>(reader: &mut R) -> Result<CircuitHeader> {
    let mut header_bytes = [0u8; 8];
    reader.read_exact(&mut header_bytes)?;

    Ok(CircuitHeader {
        xor_gates: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
        and_gates: u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()),
    })
}

/// Read circuit header from seekable stream and reset position
pub fn read_header_seekable<S: Read + Seek>(reader: &mut S) -> Result<CircuitHeader> {
    use std::io::SeekFrom;

    let current_pos = reader.stream_position()?;
    reader.seek(SeekFrom::Start(0))?;
    let header = read_header(reader)?;
    reader.seek(SeekFrom::Start(current_pos))?;

    Ok(header)
}

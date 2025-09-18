use super::{CircuitHeader, GateBatch};
use std::io::{Read, Result, Seek};

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
    /// Create a new compressed reader
    pub fn new(mut reader: R, total_bytes: usize) -> Result<Self> {
        // Read header first (8 bytes)
        let mut header_bytes = [0u8; 8];
        reader.read_exact(&mut header_bytes)?;

        let header = CircuitHeader {
            xor_gates: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
            and_gates: u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()),
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
            bytes_read: 8,
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

    /// Get total gates read so far
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }

    /// Read next batch of gates
    /// Returns the batch and the number of valid gates in it (1-8)
    #[inline]
    pub fn next_batch(&mut self) -> Result<Option<(GateBatch, usize)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            return Ok(None);
        }

        // Ensure we have a full batch worth of data
        self.ensure_bytes_available(GateBatch::SIZE)?;

        // Check if we actually got enough data
        if self.available_bytes() < GateBatch::SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected end of circuit data",
            ));
        }

        // Extract batch from buffer
        let mut batch_bytes = [0u8; GateBatch::SIZE];
        batch_bytes
            .copy_from_slice(&self.buffer[self.valid_start..self.valid_start + GateBatch::SIZE]);
        let batch = GateBatch::from_bytes(&batch_bytes);
        self.valid_start += GateBatch::SIZE;

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
    pub fn next_batch_ref(&mut self) -> Result<Option<(&GateBatch, usize)>> {
        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            return Ok(None);
        }

        // Ensure we have a full batch worth of data
        self.ensure_bytes_available(GateBatch::SIZE)?;

        // Check if we actually got enough data
        if self.available_bytes() < GateBatch::SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected end of circuit data",
            ));
        }

        // Cast buffer bytes directly to GateBatch reference (zero-copy)
        let batch_slice = &self.buffer[self.valid_start..self.valid_start + GateBatch::SIZE];
        let batch_ref = GateBatch::from_bytes_ref(batch_slice);
        self.valid_start += GateBatch::SIZE;

        // Calculate how many gates are valid in this batch
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_in_batch = gates_remaining.min(8);
        self.total_gates_read += gates_in_batch;

        Ok(Some((batch_ref, gates_in_batch)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{CompactGate, GateType, writer::CircuitWriter};
    use std::io::Cursor;

    #[test]
    fn test_batch_reader() -> Result<()> {
        // Create test data
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = CircuitWriter::new(cursor)?;

            // Write test gates
            for i in 0..1000 {
                writer.write_gate(
                    CompactGate::new(i, i + 1, i + 2),
                    if i % 2 == 0 {
                        GateType::XOR
                    } else {
                        GateType::AND
                    },
                )?;
            }

            writer.finish()?;
        }

        let len = buffer.len();
        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor, len)?;

        assert_eq!(reader.total_gates(), 1000);
        assert_eq!(reader.xor_gates(), 500);
        assert_eq!(reader.and_gates(), 500);

        let mut total_gates = 0;
        let mut gate_index = 0;

        while let Some((batch, count)) = reader.next_batch()? {
            assert!(count > 0 && count <= 8);

            for i in 0..count {
                let (gate, gate_type) = batch.get_gate(i);
                assert_eq!(gate.input1, gate_index as u32);
                assert_eq!(gate.input2, (gate_index + 1) as u32);
                assert_eq!(gate.output, (gate_index + 2) as u32);

                if gate_index % 2 == 0 {
                    assert_eq!(gate_type, GateType::XOR);
                } else {
                    assert_eq!(gate_type, GateType::AND);
                }

                gate_index += 1;
            }

            total_gates += count;
        }

        assert_eq!(total_gates, 1000);
        assert_eq!(reader.gates_read(), 1000);

        Ok(())
    }

    #[test]
    fn test_incomplete_last_batch() -> Result<()> {
        // Create circuit with 10 gates (1 full batch + 2 gates)
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = CircuitWriter::new(cursor)?;

            for i in 0..10 {
                writer.write_gate(CompactGate::new(i, i, i), GateType::AND)?;
            }

            writer.finish()?;
        }

        let len = buffer.len();
        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor, len)?;

        // First batch should have 8 gates
        let (batch1, count1) = reader.next_batch()?.unwrap();
        assert_eq!(count1, 8);
        for i in 0..8 {
            let (gate, _) = batch1.get_gate(i);
            assert_eq!(gate.input1, i as u32);
        }

        // Second batch should have 2 gates
        let (batch2, count2) = reader.next_batch()?.unwrap();
        assert_eq!(count2, 2);
        for i in 0..2 {
            let (gate, _) = batch2.get_gate(i);
            assert_eq!(gate.input1, (8 + i) as u32);
        }

        // No more batches
        assert!(reader.next_batch()?.is_none());

        Ok(())
    }

    #[test]
    fn test_large_circuit_streaming() -> Result<()> {
        // Create a large test circuit
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = CircuitWriter::new(cursor)?;

            // Write 100k gates
            for i in 0..100_000 {
                writer.write_gate(CompactGate::new(i * 3, i * 3 + 1, i * 3 + 2), GateType::XOR)?;
            }

            writer.finish()?;
        }

        let len = buffer.len();
        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor, len)?;

        let mut total_gates = 0;
        while let Some((_, count)) = reader.next_batch()? {
            total_gates += count;
        }

        assert_eq!(total_gates, 100_000);

        Ok(())
    }

    #[test]
    fn test_zero_copy_batch_ref() -> Result<()> {
        // Create test data
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = CircuitWriter::new(cursor)?;

            // Write test gates
            for i in 0..50 {
                writer.write_gate(
                    CompactGate::new(i * 2, i * 2 + 1, i * 2 + 2),
                    if i % 3 == 0 {
                        GateType::AND
                    } else {
                        GateType::XOR
                    },
                )?;
            }

            writer.finish()?;
        }

        let len = buffer.len();
        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor, len)?;

        let mut total_gates = 0;
        let mut gate_index = 0;

        while let Some((batch_ref, count)) = reader.next_batch_ref()? {
            assert!(count > 0 && count <= 8);

            for i in 0..count {
                let (gate, gate_type) = batch_ref.get_gate(i);
                assert_eq!(gate.input1, (gate_index * 2) as u32);
                assert_eq!(gate.input2, (gate_index * 2 + 1) as u32);
                assert_eq!(gate.output, (gate_index * 2 + 2) as u32);

                if gate_index % 3 == 0 {
                    assert_eq!(gate_type, GateType::AND);
                } else {
                    assert_eq!(gate_type, GateType::XOR);
                }

                gate_index += 1;
            }

            total_gates += count;
        }

        assert_eq!(total_gates, 50);
        assert_eq!(reader.gates_read(), 50);

        Ok(())
    }
}

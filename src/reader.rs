use std::io::{BufReader, Read, Result, Seek};
use zstd::Decoder;

use crate::{CircuitHeader, GateBatch};

/// Reader for compressed circuit format with batch API
pub struct CircuitReader<R: Read> {
    decoder: Decoder<'static, BufReader<R>>,
    buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_len: usize,
    total_gates_read: usize,
    header: CircuitHeader,
    finished: bool,
}

impl<R: Read> CircuitReader<R> {
    /// Create a new compressed reader
    pub fn new(mut reader: R) -> Result<Self> {
        // Read header first (8 bytes)
        let mut header_bytes = [0u8; 8];
        reader.read_exact(&mut header_bytes)?;

        // Parse header
        let xor_gates = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let and_gates = u32::from_le_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);

        let header = CircuitHeader {
            xor_gates,
            and_gates,
        };

        // Use 64MB buffer for better throughput
        const BUFFER_SIZE: usize = 256 * 1024 * 1024;

        // Simple allocation without manual alignment (let allocator handle it)
        let buffer = vec![0u8; BUFFER_SIZE];

        Ok(Self {
            decoder: Decoder::new(reader)?,
            buffer,
            buffer_pos: 0,
            buffer_len: 0,
            total_gates_read: 0,
            header,
            finished: false,
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
    /// Returns the batch and the number of valid gates in it (0-8)
    #[inline]
    pub fn next_batch(&mut self) -> Result<Option<(GateBatch, usize)>> {
        if self.finished {
            return Ok(None);
        }

        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            self.finished = true;
            return Ok(None);
        }

        // Ensure we have enough data for a batch
        const BATCH_SIZE: usize = 97;
        if !self.ensure_bytes_available(BATCH_SIZE)? {
            self.finished = true;
            return Ok(None);
        }

        // Extract batch directly from buffer
        // Use the safe version to avoid issues
        let end = self.buffer_pos + BATCH_SIZE;
        let batch_slice = &self.buffer[self.buffer_pos..end];
        let mut batch_bytes = [0u8; 97];
        batch_bytes.copy_from_slice(batch_slice);
        let batch = GateBatch::from_bytes(&batch_bytes);
        self.buffer_pos += BATCH_SIZE;

        // Calculate how many gates are in this batch
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_in_batch = gates_remaining.min(8);

        self.total_gates_read += gates_in_batch;

        Ok(Some((batch, gates_in_batch)))
    }

    /// Read next batch of gates as a zero-copy reference
    /// Returns a reference to the batch and the number of valid gates in it (0-8)
    #[inline]
    pub fn next_batch_ref(&mut self) -> Result<Option<(&GateBatch, usize)>> {
        if self.finished {
            return Ok(None);
        }

        // Check if we've read all gates
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            self.finished = true;
            return Ok(None);
        }

        // Ensure we have enough data for a batch
        const BATCH_SIZE: usize = 97;
        if !self.ensure_bytes_available(BATCH_SIZE)? {
            self.finished = true;
            return Ok(None);
        }

        // Cast buffer bytes directly to GateBatch reference (zero-copy)
        let end = self.buffer_pos + BATCH_SIZE;
        let batch_slice = &self.buffer[self.buffer_pos..end];
        let batch_ref = GateBatch::from_bytes_ref(batch_slice);
        self.buffer_pos += BATCH_SIZE;

        // Calculate how many gates are in this batch
        let gates_remaining = total_gates - self.total_gates_read;
        let gates_in_batch = gates_remaining.min(8);

        self.total_gates_read += gates_in_batch;

        Ok(Some((batch_ref, gates_in_batch)))
    }

    /// Ensure at least `needed` bytes are available in the buffer
    #[inline]
    fn ensure_bytes_available(&mut self, needed: usize) -> Result<bool> {
        let available = self.buffer_len - self.buffer_pos;

        if available >= needed {
            return Ok(true);
        }

        // // Prefetch aggressively: refill when buffer is less than 50% full
        // let buffer_half = self.buffer.len() / 2;
        if available < needed {
            self.refill_buffer()?;
        }

        // Check again after refill
        Ok(self.buffer_len - self.buffer_pos >= needed)
    }

    /// Refill the buffer with more data
    fn refill_buffer(&mut self) -> Result<()> {
        // Move remaining data to start of buffer
        if self.buffer_len > self.buffer_pos {
            let remaining = self.buffer_len - self.buffer_pos;
            self.buffer.copy_within(self.buffer_pos..self.buffer_len, 0);
            self.buffer_len = remaining;
        } else {
            self.buffer_len = 0;
        }
        self.buffer_pos = 0;

        // Fill the rest of the buffer
        let space_available = self.buffer.len() - self.buffer_len;
        if space_available > 0 {
            let bytes_read = self.decoder.read(&mut self.buffer[self.buffer_len..])?;
            self.buffer_len += bytes_read;
        }

        Ok(())
    }
}

/// Read circuit header (works with any reader)
pub fn read_header<R: Read>(reader: &mut R) -> Result<CircuitHeader> {
    let mut header_bytes = [0u8; 8];
    reader.read_exact(&mut header_bytes)?;

    Ok(CircuitHeader {
        xor_gates: u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]),
        and_gates: u32::from_le_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]),
    })
}

/// Read circuit header from seekable stream and reset position
pub fn read_header_seekable<S: Read + Seek>(reader: &mut S) -> Result<CircuitHeader> {
    use std::io::SeekFrom;

    // Save current position
    let current_pos = reader.stream_position()?;

    // Seek to start and read header
    reader.seek(SeekFrom::Start(0))?;
    let header = read_header(reader)?;

    // Restore position
    reader.seek(SeekFrom::Start(current_pos))?;

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompactGate, GateType, writer::CircuitWriter};
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

        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

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

        // Read back with batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

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

        // Read back using batch API
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

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

        // Read back with zero-copy batch reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

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

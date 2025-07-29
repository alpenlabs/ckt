use std::io::{BufReader, Read, Result, Seek};
use zstd::Decoder;

use crate::{CircuitHeader, CompactGate, GateBatch, GateType};

/// Reader for compressed circuit format with optimized ring buffer
pub struct CircuitReader<R: Read> {
    decoder: Decoder<'static, BufReader<R>>,
    ring_buffer: Vec<u8>,
    buffer_mask: usize, // For fast modulo operation (buffer size - 1)
    read_pos: usize,
    write_pos: usize,
    bytes_available: usize,
    current_batch: Option<GateBatch>,
    current_gate_index: usize,
    total_gates_read: usize,
    finished: bool,
    header: CircuitHeader,
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

        // Buffer size must be power of 2 for fast modulo
        // 16MB buffer (16 * 1024 * 1024 = 16777216)
        const BUFFER_SIZE: usize = 16 * 1024 * 1024;

        Ok(Self {
            decoder: Decoder::new(reader)?,
            ring_buffer: vec![0u8; BUFFER_SIZE],
            buffer_mask: BUFFER_SIZE - 1,
            read_pos: 0,
            write_pos: 0,
            bytes_available: 0,
            current_batch: None,
            current_gate_index: 0,
            total_gates_read: 0,
            finished: false,
            header,
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

impl<R: Read> CircuitReader<R> {
    /// Read next gate from stream
    pub fn next_gate(&mut self) -> Result<Option<(CompactGate, GateType)>> {
        if self.finished {
            return Ok(None);
        }

        // Check if we've read all the gates specified in the header
        let total_gates = self.total_gates() as usize;
        if self.total_gates_read >= total_gates {
            self.finished = true;
            return Ok(None);
        }

        // If we need a new batch
        if (self.current_batch.is_none() || self.current_gate_index >= 8)
            && !self.load_next_batch()?
        {
            self.finished = true;
            return Ok(None);
        }

        if let Some(batch) = &self.current_batch {
            let (gate, gate_type) = batch.get_gate(self.current_gate_index);

            self.current_gate_index += 1;
            self.total_gates_read += 1;
            Ok(Some((gate, gate_type)))
        } else {
            Ok(None)
        }
    }

    /// Load next batch from file using ring buffer
    fn load_next_batch(&mut self) -> Result<bool> {
        const BATCH_SIZE: usize = 97;

        // Ensure we have enough bytes for a batch
        while self.bytes_available < BATCH_SIZE && !self.at_eof()? {
            self.fill_buffer()?;
        }

        if self.bytes_available < BATCH_SIZE {
            return Ok(false); // Not enough data for a complete batch
        }

        // Extract batch bytes from ring buffer
        let mut batch_bytes = [0u8; 97];
        self.read_from_ring_buffer(&mut batch_bytes);

        let batch = GateBatch::from_bytes(&batch_bytes);
        self.current_batch = Some(batch);
        self.current_gate_index = 0;
        Ok(true)
    }

    /// Fill the ring buffer with more data from decoder
    fn fill_buffer(&mut self) -> Result<()> {
        let buffer_size = self.ring_buffer.len();

        // Calculate how much contiguous space we have for writing
        let contiguous_space = if self.write_pos >= self.read_pos {
            // Can write from write_pos to end, or from write_pos to read_pos-1
            if self.read_pos == 0 && self.bytes_available > 0 {
                buffer_size - self.write_pos - 1
            } else {
                buffer_size - self.write_pos
            }
        } else {
            // Can write from write_pos to read_pos-1
            self.read_pos - self.write_pos - 1
        };

        if contiguous_space == 0 {
            return Ok(()); // Buffer is full
        }

        // Read data into the buffer
        let bytes_read = self
            .decoder
            .read(&mut self.ring_buffer[self.write_pos..self.write_pos + contiguous_space])?;

        if bytes_read > 0 {
            self.write_pos = (self.write_pos + bytes_read) & self.buffer_mask;
            self.bytes_available += bytes_read;
        }

        Ok(())
    }

    /// Read data from ring buffer
    fn read_from_ring_buffer(&mut self, dest: &mut [u8]) {
        let len = dest.len();
        debug_assert!(len <= self.bytes_available, "Not enough bytes available");

        // Check if we need to wrap around
        let end_pos = self.read_pos + len;
        if end_pos <= self.ring_buffer.len() {
            // Simple case: no wrap needed
            dest.copy_from_slice(&self.ring_buffer[self.read_pos..end_pos]);
            self.read_pos = end_pos & self.buffer_mask;
        } else {
            // Need to wrap around
            let first_part_len = self.ring_buffer.len() - self.read_pos;
            dest[..first_part_len].copy_from_slice(&self.ring_buffer[self.read_pos..]);
            dest[first_part_len..].copy_from_slice(&self.ring_buffer[..len - first_part_len]);
            self.read_pos = (len - first_part_len) & self.buffer_mask;
        }

        self.bytes_available -= len;
    }

    /// Check if we've reached end of compressed stream
    fn at_eof(&mut self) -> Result<bool> {
        // Try to fill buffer to check for EOF
        let write_pos_before = self.write_pos;
        self.fill_buffer()?;
        Ok(self.write_pos == write_pos_before)
    }

    /// Get total gates read so far
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::CircuitWriter;
    use std::io::Cursor;

    #[test]
    fn test_ring_buffer_reader() -> Result<()> {
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

        // Read back with ring buffer reader
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

        assert_eq!(reader.total_gates(), 1000);
        assert_eq!(reader.xor_gates(), 500);
        assert_eq!(reader.and_gates(), 500);

        let mut gates_read = 0;
        while let Some((gate, gate_type)) = reader.next_gate()? {
            assert_eq!(gate.input1, gates_read as u32);
            assert_eq!(gate.input2, (gates_read + 1) as u32);
            assert_eq!(gate.output, (gates_read + 2) as u32);

            if gates_read % 2 == 0 {
                assert_eq!(gate_type, GateType::XOR);
            } else {
                assert_eq!(gate_type, GateType::AND);
            }

            gates_read += 1;
        }

        assert_eq!(gates_read, 1000);
        assert_eq!(reader.gates_read(), 1000);

        Ok(())
    }

    #[test]
    fn test_large_circuit_streaming() -> Result<()> {
        // Create a large test circuit
        let mut buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut buffer);
            let mut writer = CircuitWriter::new(cursor)?;

            // Write 100k gates to test buffer management
            for i in 0..100_000 {
                writer.write_gate(CompactGate::new(i * 3, i * 3 + 1, i * 3 + 2), GateType::XOR)?;
            }

            writer.finish()?;
        }

        // Read back and verify
        let cursor = Cursor::new(buffer);
        let mut reader = CircuitReader::new(cursor)?;

        let mut count = 0;
        while let Some((gate, _)) = reader.next_gate()? {
            assert_eq!(gate.input1, (count * 3) as u32);
            assert_eq!(gate.input2, (count * 3 + 1) as u32);
            assert_eq!(gate.output, (count * 3 + 2) as u32);
            count += 1;
        }

        assert_eq!(count, 100_000);

        Ok(())
    }
}

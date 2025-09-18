use blake3::Hasher;
use std::io::{Result, Seek, SeekFrom, Write};

use super::{CircuitHeader, Gate, GateBatch34};
use crate::{
    GateType,
    v3::{CircuitStats, FormatType, VERSION},
};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// Writer for compressed circuit format with header and checksum
///
/// Format:
/// - 50 bytes: header (1 version + 1 type + 32 checksum + 8 xor_count + 8 and_count)
/// - Stream of 103-byte batches (102 bytes gates + 1 byte types)
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    current_batch: GateBatch34,
    gates_in_batch: usize,
    total_gates_written: usize,
    xor_gates: u64,
    and_gates: u64,
    batches_waiting_for_flush: usize,
    hasher: Hasher,
    bytes_written: u64,
}

impl<W: Write + Seek> CircuitWriter<W> {
    pub fn new(mut writer: W) -> Result<Self> {
        // Write placeholder header (50 bytes)
        writer.write_all(&[0u8; CircuitHeader::SIZE])?;

        Ok(Self {
            writer,
            current_batch: GateBatch34::new(),
            gates_in_batch: 0,
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            batches_waiting_for_flush: 0,
            hasher: Hasher::new(),
            bytes_written: CircuitHeader::SIZE as u64,
        })
    }

    /// Write a single gate
    pub fn write_gate(&mut self, gate: Gate, gate_type: GateType) -> Result<()> {
        // Track gate type counts
        match gate_type {
            GateType::XOR => self.xor_gates += 1,
            GateType::AND => self.and_gates += 1,
        }

        self.current_batch
            .set_gate(self.gates_in_batch, gate, gate_type);
        self.gates_in_batch += 1;
        self.total_gates_written += 1;

        // Write batch when full
        if self.gates_in_batch >= 8 {
            self.write_batch_to_encoder()?;
            self.batches_waiting_for_flush += 1;
        }
        if self.batches_waiting_for_flush >= BATCHES_UNTIL_FLUSH {
            self.writer.flush()?;
            self.batches_waiting_for_flush = 0;
        }

        Ok(())
    }

    /// Write multiple gates
    pub fn write_gates(&mut self, gates: &[(Gate, GateType)]) -> Result<()> {
        for &(gate, gate_type) in gates {
            self.write_gate(gate, gate_type)?;
        }
        Ok(())
    }

    /// Flush current batch to encoder
    fn write_batch_to_encoder(&mut self) -> Result<()> {
        if self.gates_in_batch > 0 {
            let bytes = self.current_batch.to_bytes();

            // Update hasher with batch data
            self.hasher.update(&bytes);

            self.writer.write_all(&bytes)?;
            self.bytes_written += bytes.len() as u64;

            // Reset for next batch
            self.current_batch = GateBatch34::new();
            self.gates_in_batch = 0;
        }
        Ok(())
    }

    /// Get the current number of gates written
    pub fn gates_written(&self) -> usize {
        self.total_gates_written
    }

    /// Get XOR gates written
    pub fn xor_gates_written(&self) -> u64 {
        self.xor_gates
    }

    /// Get AND gates written
    pub fn and_gates_written(&self) -> u64 {
        self.and_gates
    }

    /// Finish writing and update header with actual gate counts and checksum
    /// Returns the writer and circuit statistics including the computed checksum
    pub fn finish(mut self) -> Result<(W, CircuitStats)> {
        // Flush any remaining gates
        self.write_batch_to_encoder()?;

        // Hash is computed as: hash(gate_data || header_fields_after_checksum)
        // Add the header fields after checksum to the hash
        self.hasher.update(&self.xor_gates.to_le_bytes());
        self.hasher.update(&self.and_gates.to_le_bytes());

        // Compute final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Store checksum for return
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_bytes);

        // Seek back to beginning and write actual header with checksum
        self.writer.seek(SeekFrom::Start(0))?;
        self.writer.write_all(&[VERSION])?;
        self.writer.write_all(&[FormatType::TypeA.to_byte()])?;
        self.writer.write_all(checksum_bytes)?;
        self.writer.write_all(&self.xor_gates.to_le_bytes())?;
        self.writer.write_all(&self.and_gates.to_le_bytes())?;

        // Seek to end for any subsequent operations
        self.writer.seek(SeekFrom::End(0))?;
        self.writer.flush()?;

        let stats = CircuitStats {
            total_gates: self.xor_gates + self.and_gates,
            xor_gates: self.xor_gates,
            and_gates: self.and_gates,
            primary_inputs: 0, // v3a doesn't track primary inputs
            total_levels: 0,   // v3a doesn't have levels
            bytes_written: self.bytes_written,
            checksum,
        };

        Ok((self.writer, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::a::reader::{self, CircuitReader};
    use std::io::Cursor;

    #[test]
    fn test_writer_reader_roundtrip() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer)?;

        // Write some test gates
        for i in 0..100u64 {
            let gate = Gate::new(i, i + 1, i + 1000);
            let gate_type = if i % 2 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            };
            writer.write_gate(gate, gate_type)?;
        }

        let (cursor, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 100);
        assert_eq!(stats.xor_gates, 50);
        assert_eq!(stats.and_gates, 50);

        // Read back and verify
        let data = cursor.into_inner();
        let cursor = Cursor::new(data.clone());
        let mut reader = CircuitReader::new(cursor, data.len())?;

        assert_eq!(reader.total_gates(), 100);
        assert_eq!(reader.xor_gates(), 50);
        assert_eq!(reader.and_gates(), 50);

        let mut gate_count = 0;
        while let Some((batch, count)) = reader.next_batch()? {
            for i in 0..count {
                let (gate, gate_type) = batch.get_gate(i);
                let expected_i = gate_count as u64;
                assert_eq!(gate.in1, expected_i);
                assert_eq!(gate.in2, expected_i + 1);
                assert_eq!(gate.out, expected_i + 1000);

                if expected_i % 2 == 0 {
                    assert_eq!(gate_type, GateType::XOR);
                } else {
                    assert_eq!(gate_type, GateType::AND);
                }

                gate_count += 1;
            }
        }

        assert_eq!(gate_count, 100);

        // Verify checksum
        let cursor = Cursor::new(data);
        let checksum = reader::verify_checksum(cursor)?;
        assert_eq!(checksum, stats.checksum);

        Ok(())
    }

    #[test]
    fn test_write_gates_batch() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer)?;

        let gates = vec![
            (Gate::new(0, 1, 2), GateType::XOR),
            (Gate::new(2, 3, 4), GateType::AND),
            (Gate::new(4, 5, 6), GateType::XOR),
        ];

        writer.write_gates(&gates)?;

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);

        Ok(())
    }
}

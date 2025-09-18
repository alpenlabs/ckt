use blake3::Hasher;
use cynosure::hints::likely;
use monoio::fs::File;
use std::io::Result;

use crate::GateType;
use crate::v3::a::{CircuitHeader, Gate, GateBatch34};
use crate::v3::{CircuitStats, FormatType, VERSION};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// High-performance async writer for CKT v3a format using monoio
pub struct CircuitWriter {
    file: File,
    buffer: Vec<u8>,
    current_batch: GateBatch34,
    gates_in_batch: usize,
    total_gates_written: usize,
    xor_gates: u64,
    and_gates: u64,
    batches_waiting_for_flush: usize,
    bytes_written: u64,
    hasher: Hasher,
}

impl CircuitWriter {
    /// Create a new v3a writer
    pub async fn new(file: File) -> Result<Self> {
        // Write placeholder header (50 bytes)
        let placeholder = vec![0u8; CircuitHeader::SIZE];
        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        Ok(Self {
            file,
            buffer: Vec::with_capacity(1024 * 1024), // 1MB buffer
            current_batch: GateBatch34::new(),
            gates_in_batch: 0,
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            batches_waiting_for_flush: 0,
            bytes_written: CircuitHeader::SIZE as u64,
            hasher: Hasher::new(),
        })
    }

    /// Write a single gate
    pub async fn write_gate(&mut self, gate: Gate, gate_type: GateType) -> Result<()> {
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
            self.write_batch_to_buffer()?;
            self.batches_waiting_for_flush += 1;

            if self.batches_waiting_for_flush >= BATCHES_UNTIL_FLUSH {
                self.flush_buffer().await?;
                self.batches_waiting_for_flush = 0;
            }
        }

        Ok(())
    }

    /// Write multiple gates
    pub async fn write_gates(&mut self, gates: &[(Gate, GateType)]) -> Result<()> {
        for &(gate, gate_type) in gates {
            self.write_gate(gate, gate_type).await?;
        }
        Ok(())
    }

    /// Flush current batch to buffer
    fn write_batch_to_buffer(&mut self) -> Result<()> {
        if self.gates_in_batch > 0 {
            let bytes = self.current_batch.to_bytes();
            self.buffer.extend_from_slice(&bytes);

            // Update hasher with batch data
            self.hasher.update(&bytes);

            // Reset for next batch
            self.current_batch = GateBatch34::new();
            self.gates_in_batch = 0;
        }
        Ok(())
    }

    /// Flush buffer to file
    async fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            let buf = std::mem::take(&mut self.buffer);
            let (result, returned_buf) = self.file.write_all_at(buf, self.bytes_written).await;
            result?;

            let bytes_written = returned_buf.len() as u64;
            self.bytes_written += bytes_written;

            // Reuse the buffer
            self.buffer = returned_buf;
            self.buffer.clear();
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
    pub async fn finish(mut self) -> Result<(File, CircuitStats)> {
        // Flush any remaining gates in the current batch
        self.write_batch_to_buffer()?;

        // Flush buffer to file
        self.flush_buffer().await?;

        // Hash is computed as: hash(gate_data || header_fields_after_checksum)
        // Add the header fields after checksum to the hash
        self.hasher.update(&self.xor_gates.to_le_bytes());
        self.hasher.update(&self.and_gates.to_le_bytes());

        // Compute final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Build complete header
        let mut header_bytes = Vec::with_capacity(CircuitHeader::SIZE);
        header_bytes.push(VERSION);
        header_bytes.push(FormatType::TypeA.to_byte());
        header_bytes.extend_from_slice(checksum_bytes);
        header_bytes.extend_from_slice(&self.xor_gates.to_le_bytes());
        header_bytes.extend_from_slice(&self.and_gates.to_le_bytes());

        // Update header at the beginning of the file
        let (res, _) = self.file.write_all_at(header_bytes, 0).await;
        res?;

        // Sync file to ensure all data is written
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates + self.and_gates,
            xor_gates: self.xor_gates,
            and_gates: self.and_gates,
            primary_inputs: 0, // v3a doesn't track primary inputs
            total_levels: 0,   // v3a doesn't have levels
            bytes_written: self.bytes_written,
        };

        Ok((self.file, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::a::hp::reader::CircuitReader;
    use monoio::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_writer_reader_roundtrip() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Write test data
        {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .await?;

            let mut writer = CircuitWriter::new(file).await?;

            // Write some test gates
            for i in 0..100u64 {
                let gate = Gate::new(i, i + 1, i + 1000);
                let gate_type = if i % 2 == 0 {
                    GateType::XOR
                } else {
                    GateType::AND
                };
                writer.write_gate(gate, gate_type).await?;
            }

            let (_, stats) = writer.finish().await?;
            assert_eq!(stats.total_gates, 100);
            assert_eq!(stats.xor_gates, 50);
            assert_eq!(stats.and_gates, 50);
        }

        // Read back and verify
        {
            let file = OpenOptions::new().read(true).open(&path).await?;

            let mut reader = CircuitReader::new(file, 64 * 1024).await?;

            assert_eq!(reader.total_gates(), 100);
            assert_eq!(reader.xor_gates(), 50);
            assert_eq!(reader.and_gates(), 50);

            let mut gate_count = 0;
            while let Some((batch, count)) = reader.next_batch().await? {
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
        }

        // Verify checksum
        {
            let file = OpenOptions::new().read(true).open(&path).await?;

            let valid = super::super::reader::verify_checksum_async(file).await?;
            assert!(valid, "Checksum verification failed");
        }

        Ok(())
    }

    #[monoio::test]
    async fn test_large_circuit() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file).await?;

        // Write 1M gates to test performance and correctness
        const TOTAL_GATES: u64 = 1_000_000;

        for i in 0..TOTAL_GATES {
            let gate = Gate::new(i * 2, i * 2 + 1, i + TOTAL_GATES);
            writer.write_gate(gate, GateType::XOR).await?;
        }

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, TOTAL_GATES);
        assert_eq!(stats.xor_gates, TOTAL_GATES);
        assert_eq!(stats.and_gates, 0);

        Ok(())
    }
}

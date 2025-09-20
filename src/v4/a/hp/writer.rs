use blake3::Hasher;
use cynosure::hints::likely;
use monoio::fs::File;
use std::io::Result;

use crate::GateType;
use crate::v4::a::{
    CircuitHeader, Gate, GateBatch,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v4::{CircuitStats, FormatType, VERSION};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// High-performance async writer for CKT v4a format using monoio
pub struct CircuitWriter {
    file: File,
    buffer: Vec<u8>,
    current_batch: GateBatch,
    total_gates_written: usize,
    xor_gates: u64,
    and_gates: u64,
    primary_inputs: u64,
    outputs: Vec<u64>,
    batches_waiting_for_flush: usize,
    bytes_written: u64,
    wire_counter: u64,
    outputs_size: usize,
    hasher: Hasher,
}

impl CircuitWriter {
    /// Create a new v4a writer with specified primary inputs and outputs
    pub async fn new(file: File, primary_inputs: u64, outputs: Vec<u64>) -> Result<Self> {
        // Wire counter starts at 2 + primary_inputs (0=false, 1=true, then primary inputs)
        let wire_counter = 2 + primary_inputs;

        // Calculate output wire IDs size
        let mut output_buffer = Vec::with_capacity(outputs.len() * 8);
        for &output_id in &outputs {
            let varint = StandardVarInt::new(output_id)?;
            let mut temp_buf = [0u8; 8];
            let size = varint.encode(&mut temp_buf)?;
            output_buffer.extend_from_slice(&temp_buf[..size]);
        }
        let outputs_size = output_buffer.len();

        // Write placeholder header (66 bytes fixed)
        let placeholder = vec![0u8; CircuitHeader::FIXED_SIZE];
        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        // Write output wire IDs immediately after fixed header
        let (res, _) = file
            .write_all_at(output_buffer, CircuitHeader::FIXED_SIZE as u64)
            .await;
        res?;

        Ok(Self {
            file,
            buffer: Vec::with_capacity(1024 * 1024), // 1MB buffer
            current_batch: GateBatch::new(),
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            primary_inputs,
            outputs,
            batches_waiting_for_flush: 0,
            bytes_written: (CircuitHeader::FIXED_SIZE + outputs_size) as u64,
            wire_counter,
            outputs_size,
            hasher: Hasher::new(),
        })
    }

    /// Write a single gate with credits
    pub async fn write_gate(&mut self, gate: Gate, gate_type: GateType) -> Result<()> {
        // Track gate type counts
        match gate_type {
            GateType::XOR => self.xor_gates += 1,
            GateType::AND => self.and_gates += 1,
        }

        // Encode gate to batch buffer
        let mut temp_buf = [0u8; 32]; // Enough for worst case
        let mut offset = 0;

        // Encode input1
        let size =
            FlaggedVarInt::encode_wire_id(gate.in1, self.wire_counter, &mut temp_buf[offset..])?;
        offset += size;

        // Encode input2
        let size =
            FlaggedVarInt::encode_wire_id(gate.in2, self.wire_counter, &mut temp_buf[offset..])?;
        offset += size;

        // Encode output
        let size =
            FlaggedVarInt::encode_wire_id(gate.out, self.wire_counter, &mut temp_buf[offset..])?;
        offset += size;

        // Encode credits
        let credits_varint = StandardVarInt::new(gate.credits as u64)?;
        let size = credits_varint.encode(&mut temp_buf[offset..])?;
        offset += size;

        // Add encoded gate to batch
        self.current_batch
            .gates_buffer
            .extend_from_slice(&temp_buf[..offset]);

        // Set gate type
        match gate_type {
            GateType::XOR => self.current_batch.gate_types &= !(1 << self.current_batch.gate_count),
            GateType::AND => self.current_batch.gate_types |= 1 << self.current_batch.gate_count,
        }

        self.current_batch.gate_count += 1;
        self.total_gates_written += 1;

        // Update wire counter to output wire ID + 1
        self.wire_counter = gate.out + 1;

        // Write batch when full
        if self.current_batch.is_full() {
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
        if !self.current_batch.is_empty() {
            // Serialize batch
            let bytes = self.current_batch.to_bytes();
            self.buffer.extend_from_slice(&bytes);

            // Update hasher with batch data
            self.hasher.update(&bytes);

            // Reset batch for next use
            self.current_batch.clear();
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
    /// Returns the file handle and circuit stats including the computed checksum
    pub async fn finish(mut self) -> Result<(File, CircuitStats)> {
        // Flush any remaining gates in the current batch
        self.write_batch_to_buffer()?;

        // Flush buffer to file
        self.flush_buffer().await?;

        // Hash is computed as: hash(batches || header_fields_after_checksum)
        // Add the header fields after checksum to the hash
        self.hasher.update(&self.xor_gates.to_le_bytes());
        self.hasher.update(&self.and_gates.to_le_bytes());
        self.hasher.update(&self.primary_inputs.to_le_bytes());
        self.hasher
            .update(&(self.outputs.len() as u64).to_le_bytes());

        // Also hash the output wire IDs
        for &output_id in &self.outputs {
            let varint = StandardVarInt::new(output_id)?;
            let mut temp_buf = [0u8; 8];
            let size = varint.encode(&mut temp_buf)?;
            self.hasher.update(&temp_buf[..size]);
        }

        // Compute final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Store checksum for return
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_bytes);

        // Build complete header
        let mut header_bytes = Vec::with_capacity(CircuitHeader::FIXED_SIZE);
        header_bytes.push(VERSION);
        header_bytes.push(FormatType::TypeA.to_byte());
        header_bytes.extend_from_slice(checksum_bytes);
        header_bytes.extend_from_slice(&self.xor_gates.to_le_bytes());
        header_bytes.extend_from_slice(&self.and_gates.to_le_bytes());
        header_bytes.extend_from_slice(&self.primary_inputs.to_le_bytes());
        header_bytes.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());

        // Update header at the beginning of the file
        let (res, _) = self.file.write_all_at(header_bytes, 0).await;
        res?;

        // Sync file to ensure all data is written
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates + self.and_gates,
            xor_gates: self.xor_gates,
            and_gates: self.and_gates,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
            total_levels: 0, // v4a doesn't have levels yet
            bytes_written: self.bytes_written,
            checksum,
            max_scratch_space: 0, // Will be computed by v4b conversion
        };

        Ok((self.file, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::a::hp::reader::CircuitReader;
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

            let outputs = vec![100, 101];
            let mut writer = CircuitWriter::new(file, 4, outputs).await?;

            // Write some test gates with credits
            for i in 0..100u64 {
                let gate = Gate::new(i + 2, i + 3, i + 100, (i % 5) as u32 + 1);
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
            assert_eq!(reader.outputs().len(), 2);

            let mut gate_count = 0;
            while let Some(batch) = reader.next_batch().await? {
                for (gate, gate_type) in batch {
                    let expected_i = gate_count as u64;
                    assert_eq!(gate.in1, expected_i + 2);
                    assert_eq!(gate.in2, expected_i + 3);
                    assert_eq!(gate.out, expected_i + 100);
                    assert_eq!(gate.credits, (expected_i % 5) as u32 + 1);

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
            let _checksum = super::super::reader::verify_checksum_async(file).await?;
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

        let mut writer = CircuitWriter::new(file, 0, vec![]).await?;

        // Write 1M gates to test performance and correctness
        const TOTAL_GATES: u64 = 1_000_000;

        for i in 0..TOTAL_GATES {
            let gate = Gate::new(i * 2, i * 2 + 1, i + TOTAL_GATES, 1);
            writer.write_gate(gate, GateType::XOR).await?;
        }

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, TOTAL_GATES);
        assert_eq!(stats.xor_gates, TOTAL_GATES);
        assert_eq!(stats.and_gates, 0);

        Ok(())
    }

    #[monoio::test]
    async fn test_credits_encoding() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 0, vec![]).await?;

        // Test various credit values
        let credit_tests = vec![
            0,      // No further uses
            1,      // Single use
            2,      // Two uses
            63,     // Edge of 1-byte varint
            64,     // Start of 2-byte varint
            1000,   // Larger credit value
            100000, // Very large credits
        ];

        for credits in &credit_tests {
            writer
                .write_gate(
                    Gate::new(0, 1, writer.wire_counter, *credits),
                    GateType::XOR,
                )
                .await?;
        }

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, credit_tests.len() as u64);

        Ok(())
    }
}

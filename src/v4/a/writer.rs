use blake3::Hasher;
use std::io::{Result, Seek, SeekFrom, Write};

use super::varints::{FlaggedVarInt, StandardVarInt};
use super::{CircuitHeader, Gate, GateBatch};
use crate::{
    GateType,
    v4::{CircuitStats, FormatType, VERSION},
};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// Writer for v4a format with credits for wire garbage collection
///
/// Format:
/// - Header: 66 bytes fixed + variable output wire IDs
/// - Batches: Variable-length encoded gates with credits
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    current_batch: GateBatch,
    total_gates_written: usize,
    xor_gates: u64,
    and_gates: u64,
    primary_inputs: u64,
    outputs: Vec<u64>,
    batches_waiting_for_flush: usize,
    hasher: Hasher,
    bytes_written: u64,
    wire_counter: u64,
    header_position: u64,
    outputs_size: usize, // Size of encoded output wire IDs
}

impl<W: Write + Seek> CircuitWriter<W> {
    /// Create a new v4a writer
    pub fn new(mut writer: W, primary_inputs: u64, outputs: Vec<u64>) -> Result<Self> {
        // Wire counter starts at 2 + primary_inputs (0=false, 1=true, then primary inputs)
        let wire_counter = 2 + primary_inputs;

        // Remember header position
        let header_position = writer.stream_position()?;

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
        writer.write_all(&[0u8; CircuitHeader::FIXED_SIZE])?;

        // Write output wire IDs immediately after fixed header
        writer.write_all(&output_buffer)?;

        Ok(Self {
            writer,
            current_batch: GateBatch::new(),
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            primary_inputs,
            outputs,
            batches_waiting_for_flush: 0,
            hasher: Hasher::new(),
            bytes_written: (CircuitHeader::FIXED_SIZE + outputs_size) as u64,
            wire_counter,
            header_position,
            outputs_size,
        })
    }

    /// Write a single gate with credits
    pub fn write_gate(&mut self, gate: Gate, gate_type: GateType) -> Result<()> {
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
            self.write_batch()?;
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

    /// Write current batch to writer
    fn write_batch(&mut self) -> Result<()> {
        if !self.current_batch.is_empty() {
            // Serialize batch
            let bytes = self.current_batch.to_bytes();

            // Update hasher with batch data
            self.hasher.update(&bytes);

            // Write to file
            self.writer.write_all(&bytes)?;
            self.bytes_written += bytes.len() as u64;

            // Reset batch for next use
            self.current_batch.clear();
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
    pub fn finish(mut self) -> Result<(W, CircuitStats)> {
        // Flush any remaining gates
        self.write_batch()?;

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

        // Seek back to beginning and write actual header with checksum
        self.writer.seek(SeekFrom::Start(self.header_position))?;
        self.writer.write_all(&[VERSION])?;
        self.writer.write_all(&[FormatType::TypeA.to_byte()])?;
        self.writer.write_all(checksum_bytes)?;
        self.writer.write_all(&self.xor_gates.to_le_bytes())?;
        self.writer.write_all(&self.and_gates.to_le_bytes())?;
        self.writer.write_all(&self.primary_inputs.to_le_bytes())?;
        self.writer
            .write_all(&(self.outputs.len() as u64).to_le_bytes())?;

        // Seek to end for any subsequent operations
        self.writer.seek(SeekFrom::End(0))?;
        self.writer.flush()?;

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

        Ok((self.writer, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_writer_basic() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let outputs = vec![100, 101];
        let mut writer = CircuitWriter::new(buffer, 4, outputs)?;

        // Write some test gates with credits
        let gates = vec![
            (Gate::new(2, 3, 6, 2), GateType::XOR), // Credits: 2 (used twice)
            (Gate::new(4, 5, 7, 1), GateType::AND), // Credits: 1 (used once)
            (Gate::new(6, 7, 8, 0), GateType::XOR), // Credits: 0 (final output)
        ];

        for (gate, gate_type) in gates {
            writer.write_gate(gate, gate_type)?;
        }

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);
        assert_eq!(stats.num_outputs, 2);

        Ok(())
    }

    #[test]
    fn test_wire_counter_tracking() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 2, vec![10])?;

        // Initial wire counter should be 2 + primary_inputs = 4
        assert_eq!(writer.wire_counter, 4);

        // Write a gate and check wire counter updates
        writer.write_gate(Gate::new(2, 3, 100, 1), GateType::XOR)?;
        assert_eq!(writer.wire_counter, 101); // Updated to output + 1

        writer.write_gate(Gate::new(100, 3, 200, 2), GateType::AND)?;
        assert_eq!(writer.wire_counter, 201);

        Ok(())
    }

    #[test]
    fn test_batch_encoding() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 0, vec![])?;

        // Write exactly 8 gates to fill a batch
        for i in 0..8 {
            let gate = Gate::new(i as u64, i as u64 + 1, i as u64 + 100, i as u32 + 1);
            writer.write_gate(
                gate,
                if i % 2 == 0 {
                    GateType::XOR
                } else {
                    GateType::AND
                },
            )?;
        }

        assert_eq!(writer.gates_written(), 8);
        assert_eq!(writer.xor_gates_written(), 4);
        assert_eq!(writer.and_gates_written(), 4);

        // Write one more to start a new batch
        writer.write_gate(Gate::new(1000, 1001, 2000, 5), GateType::XOR)?;
        assert_eq!(writer.gates_written(), 9);

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, 9);

        Ok(())
    }

    #[test]
    fn test_relative_encoding_efficiency() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 0, vec![10])?;

        // Write gates with wire IDs close to counter (should use relative encoding)
        writer.wire_counter = 1000;
        writer.write_gate(Gate::new(998, 999, 1001, 1), GateType::XOR)?;

        // Write gate with distant wire ID (should use absolute encoding)
        writer.write_gate(Gate::new(5, 10, 1002, 1), GateType::AND)?;

        let (cursor, _) = writer.finish()?;
        let data = cursor.into_inner();

        // The encoding should be efficient (exact size depends on varint encoding)
        // but should be reasonable for this small circuit
        assert!(data.len() < 200); // Reasonable upper bound

        Ok(())
    }

    #[test]
    fn test_credits_encoding() -> Result<()> {
        let buffer = Cursor::new(Vec::new());
        let mut writer = CircuitWriter::new(buffer, 0, vec![])?;

        // Test various credit values
        let credit_tests = vec![
            0,    // No further uses
            1,    // Single use
            2,    // Two uses
            63,   // Edge of 1-byte varint
            64,   // Start of 2-byte varint
            1000, // Larger credit value
        ];

        for credits in &credit_tests {
            writer.write_gate(
                Gate::new(0, 1, writer.wire_counter, *credits),
                GateType::XOR,
            )?;
        }

        let (_, stats) = writer.finish()?;
        assert_eq!(stats.total_gates, credit_tests.len() as u64);

        Ok(())
    }
}

use std::io::{Result, Seek, Write};

use super::{CircuitHeader, Gate, GateBatch34};
use crate::{
    GateType,
    v3::{FormatType, VERSION},
};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// Writer for compressed circuit format with header
///
/// Format:
/// - 18 bytes: header (1 version + 1 type + 8 xor_count + 8 and_count)
/// - Stream of 103-byte batches (102 bytes gates + 1 byte types)
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    current_batch: GateBatch34,
    gates_in_batch: usize,
    total_gates_written: usize,
    xor_gates: u64,
    and_gates: u64,
    batches_waiting_for_flush: usize,
}

impl<W: Write + Seek> CircuitWriter<W> {
    pub fn new(mut writer: W) -> Result<Self> {
        // Write placeholder header (18 bytes: version + type + xor_count + and_count)
        writer.write_all(&[0u8; CircuitHeader::SIZE])?;

        Ok(Self {
            writer,
            current_batch: GateBatch34::new(),
            gates_in_batch: 0,
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            batches_waiting_for_flush: 0,
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

    /// Flush current batch to encoder
    fn write_batch_to_encoder(&mut self) -> Result<()> {
        if self.gates_in_batch > 0 {
            let bytes = self.current_batch.to_bytes();
            self.writer.write_all(&bytes)?;

            // Reset for next batch
            self.current_batch = GateBatch34::new();
            self.gates_in_batch = 0;
        }
        Ok(())
    }

    /// Finish writing and update header
    pub fn finish(mut self) -> Result<(W, usize)> {
        // Flush any remaining gates
        self.write_batch_to_encoder()?;

        // Seek back to beginning and write actual header with version and type
        self.writer.seek(std::io::SeekFrom::Start(0))?;
        self.writer.write_all(&[VERSION])?;
        self.writer.write_all(&[FormatType::TypeA.to_byte()])?;
        self.writer.write_all(&self.xor_gates.to_le_bytes())?;
        self.writer.write_all(&self.and_gates.to_le_bytes())?;

        // Seek to end for any subsequent operations
        self.writer.seek(std::io::SeekFrom::End(0))?;
        self.writer.flush()?;

        Ok((self.writer, self.total_gates_written))
    }
}

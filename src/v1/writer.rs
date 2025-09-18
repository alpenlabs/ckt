use std::io::{Result, Seek, Write};

use super::{CompactGate, GateBatch, GateType};

const BATCHES_UNTIL_FLUSH: usize = 1000;

/// Writer for compressed circuit format with header
///
/// Format:
/// - 8 bytes: header (xor_count, and_count as u32 little-endian)
/// - Compressed zstd stream of 97-byte batches
pub struct CircuitWriter<W: Write + Seek> {
    writer: W,
    current_batch: GateBatch,
    gates_in_batch: usize,
    total_gates_written: usize,
    xor_gates: u32,
    and_gates: u32,
    batches_waiting_for_flush: usize,
}

impl<W: Write + Seek> CircuitWriter<W> {
    pub fn new(mut writer: W) -> Result<Self> {
        // Write placeholder header (8 bytes: xor_count, and_count)
        writer.write_all(&[0u8; 8])?;

        Ok(Self {
            writer,
            current_batch: GateBatch::new(),
            gates_in_batch: 0,
            total_gates_written: 0,
            xor_gates: 0,
            and_gates: 0,
            batches_waiting_for_flush: 0,
        })
    }

    /// Write a single gate
    pub fn write_gate(&mut self, gate: CompactGate, gate_type: GateType) -> Result<()> {
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
            self.current_batch = GateBatch::new();
            self.gates_in_batch = 0;
        }
        Ok(())
    }

    /// Finish writing and update header
    pub fn finish(mut self) -> Result<(W, usize)> {
        // Flush any remaining gates
        self.write_batch_to_encoder()?;

        // Seek back to beginning and write actual counts
        self.writer.seek(std::io::SeekFrom::Start(0))?;
        self.writer.write_all(&self.xor_gates.to_le_bytes())?;
        self.writer.write_all(&self.and_gates.to_le_bytes())?;

        // Seek to end for any subsequent operations
        self.writer.seek(std::io::SeekFrom::End(0))?;
        self.writer.flush()?;

        Ok((self.writer, self.total_gates_written))
    }
}

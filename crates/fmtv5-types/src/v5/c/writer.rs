//! v5c Writer - Flat production format with 256 KiB block buffering
//!
//! API:
//! - new() → write_gate()* → finalize()
//!
//! Behavior:
//! - Buffers gates in 256 KiB blocks (21,620 gates per block)
//! - Auto-flushes when block is full
//! - Gates stored in execution order with bit-packed types
//! - Writes header placeholder + zeroed output placeholders, streams blocks,
//!   later overwrites outputs and backpatches the header with checksum
//! - Computes checksum in order: blocks || outputs || header_tail
//! - Uses monoio for async I/O

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::GateType;
use crate::v5::c::{
    ALIGNMENT, BLOCK_SIZE, CircuitStats, GATE_SIZE, GATES_PER_BLOCK, GateV5c, HEADER_SIZE,
    HeaderV5c, MAX_MEMORY_ADDRESS, TYPES_OFFSET, padded_size, set_gate_type,
};

/// Default I/O aggregation buffer capacity (tunable)
const DEFAULT_IO_BUFFER_CAP: usize = 8 * 1024 * 1024; // 8 MiB

/// v5c Circuit Writer
pub struct WriterV5c {
    file: File,

    // Metadata
    primary_inputs: u64,
    num_outputs: u64,

    // File offsets
    outputs_offset: u64, // Start of outputs section
    next_offset: u64,    // Current write position

    // Current block buffer (exactly 256 KiB)
    block_buffer: Box<[u8; BLOCK_SIZE]>,
    gates_in_block: usize,

    // I/O aggregation buffer
    io_buf: Vec<u8>,
    io_buf_cap: usize,

    // Checksum (stream-hash blocks as we write them)
    hasher: Hasher,

    // Statistics
    xor_gates_written: u64,
    and_gates_written: u64,
    max_addr_seen: u32,
}

impl WriterV5c {
    /// Create a new writer. Writes placeholder header and zeroed outputs.
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        num_outputs: u64,
    ) -> Result<Self> {
        // Open/truncate file
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        let file = opts.open(path.as_ref()).await?;

        // Write header placeholder (88 bytes) padded to 256 KiB
        let header_padded_size = ALIGNMENT;
        let header_placeholder = vec![0u8; header_padded_size];
        {
            let (res, _) = file.write_all_at(header_placeholder, 0).await;
            res?;
        }

        let outputs_offset = ALIGNMENT as u64;

        // Write outputs placeholder: num_outputs × 4 bytes, padded to 256 KiB boundary
        let outputs_bytes_len = num_outputs
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "num_outputs too large"))?
            as usize;
        let outputs_padded_size = padded_size(outputs_bytes_len);
        let outputs_placeholder = vec![0u8; outputs_padded_size];
        {
            let (res, _) = file.write_all_at(outputs_placeholder, outputs_offset).await;
            res?;
        }

        let blocks_start_offset = outputs_offset + outputs_padded_size as u64;

        Ok(Self {
            file,
            primary_inputs,
            num_outputs,
            outputs_offset,
            next_offset: blocks_start_offset,
            block_buffer: Box::new([0u8; BLOCK_SIZE]),
            gates_in_block: 0,
            io_buf: Vec::with_capacity(DEFAULT_IO_BUFFER_CAP),
            io_buf_cap: DEFAULT_IO_BUFFER_CAP,
            hasher: Hasher::new(),
            xor_gates_written: 0,
            and_gates_written: 0,
            max_addr_seen: 0,
        })
    }

    /// Optionally tune the I/O aggregation buffer capacity (bytes)
    pub fn set_io_buffer_capacity(&mut self, cap: usize) {
        self.io_buf_cap = cap.max(BLOCK_SIZE);
        if self.io_buf.capacity() < self.io_buf_cap {
            self.io_buf
                .reserve(self.io_buf_cap - self.io_buf.capacity());
        }
    }

    /// Write a gate to the current block. Auto-flushes when block is full.
    pub async fn write_gate(&mut self, gate: GateV5c, gate_type: GateType) -> Result<()> {
        // Validate addresses
        if gate.in1 as u64 >= MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "in1 address exceeds maximum",
            ));
        }
        if gate.in2 as u64 >= MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "in2 address exceeds maximum",
            ));
        }
        if gate.out as u64 >= MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "out address exceeds maximum",
            ));
        }

        // Flush block if full
        if self.gates_in_block >= GATES_PER_BLOCK {
            self.flush_block().await?;
        }

        // Write gate to block buffer (gates section: offset = gates_in_block × 12)
        let gate_offset = self.gates_in_block * GATE_SIZE;
        self.block_buffer[gate_offset..gate_offset + 4].copy_from_slice(&gate.in1.to_le_bytes());
        self.block_buffer[gate_offset + 4..gate_offset + 8]
            .copy_from_slice(&gate.in2.to_le_bytes());
        self.block_buffer[gate_offset + 8..gate_offset + 12]
            .copy_from_slice(&gate.out.to_le_bytes());

        // Set gate type bit in types section
        set_gate_type(
            &mut self.block_buffer[TYPES_OFFSET..],
            self.gates_in_block,
            gate_type,
        );

        // Update statistics
        match gate_type {
            GateType::XOR => self.xor_gates_written += 1,
            GateType::AND => self.and_gates_written += 1,
        }
        self.max_addr_seen = self.max_addr_seen.max(gate.in1).max(gate.in2).max(gate.out);
        self.gates_in_block += 1;

        Ok(())
    }

    /// Flush the current block to disk and hash it
    async fn flush_block(&mut self) -> Result<()> {
        if self.gates_in_block == 0 {
            return Ok(());
        }

        // Hash FULL 256 KiB block (including all padding)
        self.hasher.update(&self.block_buffer[..]);

        // Write FULL 256 KiB block to disk
        let block_copy = self.block_buffer.to_vec();
        self.enqueue_bytes(&block_copy).await?;

        // Reset block buffer for next block
        self.block_buffer.fill(0);
        self.gates_in_block = 0;

        Ok(())
    }

    /// Finalize: flush remaining gates, overwrite outputs, complete checksum, write header
    pub async fn finalize(mut self, scratch_space: u64, outputs: Vec<u32>) -> Result<CircuitStats> {
        // Validate outputs length
        if outputs.len() as u64 != self.num_outputs {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "finalize outputs length does not match num_outputs",
            ));
        }

        // Flush any remaining gates in current block
        self.flush_block().await?;

        // Flush I/O aggregation buffer (ensure all hashed blocks are on disk)
        self.flush_io_buffer().await?;

        // Validate scratch space
        if scratch_space > MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "scratch_space exceeds maximum addressable memory",
            ));
        }

        // Encode and validate outputs
        let (outputs_bytes, max_output_addr) = encode_outputs_le32(&outputs)?;
        self.max_addr_seen = self.max_addr_seen.max(max_output_addr);

        // Validate all addresses fit in scratch space
        if (self.max_addr_seen as u64) >= scratch_space {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "some addresses are >= scratch_space",
            ));
        }

        // Calculate padded outputs size
        let outputs_padded_size = padded_size(outputs_bytes.len());
        let mut outputs_padded = vec![0u8; outputs_padded_size];
        outputs_padded[..outputs_bytes.len()].copy_from_slice(&outputs_bytes);

        // Overwrite outputs section (full padded section)
        {
            let (res, _) = self
                .file
                .write_all_at(outputs_padded.clone(), self.outputs_offset)
                .await;
            res?;
        }

        // Continue checksum: hash outputs section (WITH padding to 256 KiB boundary)
        self.hasher.update(&outputs_padded);

        // Hash header: before checksum + after checksum + all padding to 256 KiB
        // Build complete header first
        let mut temp_header = HeaderV5c::new();
        temp_header.xor_gates = self.xor_gates_written;
        temp_header.and_gates = self.and_gates_written;
        temp_header.primary_inputs = self.primary_inputs;
        temp_header.scratch_space = scratch_space;
        temp_header.num_outputs = self.num_outputs;
        // checksum field stays zero for now

        let temp_header_bytes = temp_header.to_bytes();

        // Hash header before checksum field (bytes 0-10: magic, version, format_type, nkas)
        self.hasher.update(&temp_header_bytes[0..10]);
        // Skip checksum field (bytes 10-42)
        // Hash header after checksum field (bytes 42-88: all metadata)
        self.hasher.update(&temp_header_bytes[42..88]);
        // Hash header padding (88 bytes to 256 KiB)
        let header_padding = vec![0u8; ALIGNMENT - HEADER_SIZE];
        self.hasher.update(&header_padding);

        // Finalize checksum
        let checksum = *self.hasher.finalize().as_bytes();

        // Build complete header
        let mut header = HeaderV5c::new();
        header.xor_gates = self.xor_gates_written;
        header.and_gates = self.and_gates_written;
        header.primary_inputs = self.primary_inputs;
        header.scratch_space = scratch_space;
        header.num_outputs = self.num_outputs;
        header.checksum = checksum;

        // Write header at offset 0 (only 88 bytes, not padding)
        let header_bytes = header.to_bytes();
        {
            let (res, _) = self.file.write_all_at(header_bytes.to_vec(), 0).await;
            res?;
        }

        // Sync to disk and close
        self.file.sync_all().await?;
        self.file.close().await?;

        Ok(CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            scratch_space,
            num_outputs: self.num_outputs,
            checksum,
        })
    }

    /// Append bytes to I/O aggregation buffer, flushing if needed
    async fn enqueue_bytes(&mut self, data: &[u8]) -> Result<()> {
        if self.io_buf.len() + data.len() > self.io_buf_cap {
            self.flush_io_buffer().await?;
        }
        self.io_buf.extend_from_slice(data);
        Ok(())
    }

    /// Flush I/O aggregation buffer to disk
    async fn flush_io_buffer(&mut self) -> Result<()> {
        if self.io_buf.is_empty() {
            return Ok(());
        }
        let len = self.io_buf.len();
        let (res, buf) = self
            .file
            .write_all_at(std::mem::take(&mut self.io_buf), self.next_offset)
            .await;
        res?;
        self.io_buf = buf;
        self.io_buf.clear();
        self.next_offset = self
            .next_offset
            .checked_add(len as u64)
            .expect("file offset overflow");
        Ok(())
    }
}

/// Encode outputs as little-endian u32 array, return bytes and max address
fn encode_outputs_le32(outputs: &[u32]) -> Result<(Vec<u8>, u32)> {
    let mut bytes = Vec::with_capacity(outputs.len() * 4);
    let mut max_addr = 0u32;

    for &addr in outputs {
        if addr as u64 >= MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "output address exceeds maximum",
            ));
        }
        bytes.extend_from_slice(&addr.to_le_bytes());
        max_addr = max_addr.max(addr);
    }

    Ok((bytes, max_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v5::c::ALIGNMENT;

    async fn write_simple_circuit() -> Result<Vec<u8>> {
        let path = "/tmp/test_v5c_write_simple.ckt";

        // Create writer
        let mut writer = WriterV5c::new(path, 2, 1).await?;

        // Write 4 gates in execution order
        writer
            .write_gate(GateV5c::new(2, 3, 4), GateType::XOR)
            .await?;
        writer
            .write_gate(GateV5c::new(4, 3, 5), GateType::XOR)
            .await?;
        writer
            .write_gate(GateV5c::new(2, 4, 6), GateType::AND)
            .await?;
        writer
            .write_gate(GateV5c::new(5, 6, 7), GateType::AND)
            .await?;

        // Finalize with outputs
        let stats = writer.finalize(1000, vec![7]).await?;

        assert_eq!(stats.total_gates, 4);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 2);
        assert_eq!(stats.num_outputs, 1);

        // Read file back
        let bytes = std::fs::read(path)?;
        std::fs::remove_file(path)?;
        Ok(bytes)
    }

    #[monoio::test]
    async fn test_writer_simple() {
        let bytes = write_simple_circuit().await.unwrap();

        // Check file size: header (256 KiB) + outputs (256 KiB) + 1 block (256 KiB) = 768 KiB
        let expected_size = 3 * ALIGNMENT;
        assert_eq!(bytes.len(), expected_size);

        // Verify header magic
        assert_eq!(&bytes[0..4], b"Zk2u");
        assert_eq!(bytes[4], 0x05); // version
        assert_eq!(bytes[5], 0x02); // format_type v5c
    }

    #[monoio::test]
    async fn test_writer_validates_scratch_space() {
        let path = "/tmp/test_v5c_scratch_space.ckt";

        let mut writer = WriterV5c::new(path, 2, 1).await.unwrap();
        writer
            .write_gate(GateV5c::new(2, 3, 100), GateType::XOR)
            .await
            .unwrap();

        // Try to finalize with scratch_space = 50 (but gate uses address 100)
        let result = writer.finalize(50, vec![100]).await;
        assert!(result.is_err());

        let _ = std::fs::remove_file(path);
    }
}

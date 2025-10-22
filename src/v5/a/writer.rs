//! v5a Writer
//!
//! - Accepts gates individually or in batches.
//! - Packs blocks (256 gates) with SoA layout and fixed-width fields.
//! - Writes header placeholder + outputs, then blocks, then backpatches header with checksum.
//! - Computes checksum in modified order: blocks || outputs || header[after checksum].
//! - Uses monoio for async I/O.
//! - Handles partial blocks safely: zero-padded, readers rely on header counts.

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::GateType;
use crate::v5::a::{
    CREDITS_OFFSET, CREDITS_SIZE, FORMAT_TYPE_A, HEADER_SIZE_V5A, IN_STREAM_SIZE, IN1_OFFSET,
    IN2_OFFSET, MAGIC, OUT_OFFSET, TYPES_OFFSET, VERSION,
};
use crate::v5::avx512::BlockV5a;

use super::{BLOCK_SIZE_BYTES, GATES_PER_BLOCK, GateV5a, MAX_CREDITS, MAX_WIRE_ID};

// Default I/O aggregation buffer size (tunable).
const DEFAULT_IO_BUFFER_CAP: usize = 8 * 1024 * 1024; // 8 MiB

/// Statistics returned after finalization
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub num_outputs: u64,
    pub checksum: [u8; 32],
}

/// Internal fixed-capacity block builder (no clones/allocs per block).
pub struct BlockBuilder {
    len: usize,
    in1: [u64; GATES_PER_BLOCK],
    in2: [u64; GATES_PER_BLOCK],
    out: [u64; GATES_PER_BLOCK],
    credits: [u32; GATES_PER_BLOCK],
    gate_types: [GateType; GATES_PER_BLOCK], // 0 = XOR, 1 = AND
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            len: 0,
            in1: [0; GATES_PER_BLOCK],
            in2: [0; GATES_PER_BLOCK],
            out: [0; GATES_PER_BLOCK],
            credits: [0; GATES_PER_BLOCK],
            gate_types: [GateType::XOR; GATES_PER_BLOCK],
        }
    }

    pub fn is_full(&self) -> bool {
        self.len >= GATES_PER_BLOCK
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, gate: GateV5a) -> Result<()> {
        if self.is_full() {
            return Err(Error::new(
                ErrorKind::Other,
                "internal error: push into full block",
            ));
        }
        // Validate wire IDs and credits
        if gate.in1 > MAX_WIRE_ID || gate.in2 > MAX_WIRE_ID || gate.out > MAX_WIRE_ID {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "wire ID exceeds 34-bit limit",
            ));
        }
        if gate.credits > MAX_CREDITS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "credits exceed 24-bit limit",
            ));
        }

        let idx = self.len;
        self.in1[idx] = gate.in1 & MAX_WIRE_ID;
        self.in2[idx] = gate.in2 & MAX_WIRE_ID;
        self.out[idx] = gate.out & MAX_WIRE_ID;
        self.credits[idx] = gate.credits & MAX_CREDITS;
        self.gate_types[idx] = gate.gate_type;
        self.len += 1;
        Ok(())
    }

    /// Encode current gates into the provided block buffer (must be 4064 bytes).
    /// Padding for unused gates is zero-filled.
    pub fn encode_into(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), BLOCK_SIZE_BYTES);
        // Zero the whole block
        block.fill(0);

        // Pack streams
        pack_34_bits(
            &self.in1[..self.len],
            &mut block[IN1_OFFSET..IN1_OFFSET + IN_STREAM_SIZE],
        );
        pack_34_bits(
            &self.in2[..self.len],
            &mut block[IN2_OFFSET..IN2_OFFSET + IN_STREAM_SIZE],
        );
        pack_34_bits(
            &self.out[..self.len],
            &mut block[OUT_OFFSET..OUT_OFFSET + IN_STREAM_SIZE],
        );
        pack_24_bits(
            &self.credits[..self.len],
            &mut block[CREDITS_OFFSET..CREDITS_OFFSET + CREDITS_SIZE],
        );

        // Pack gate types bitset
        // Byte 0 bit 0 => gate 0, ..., byte 31 bit 7 => gate 255
        for i in 0..self.len {
            if self.gate_types[i] != GateType::XOR {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                block[TYPES_OFFSET + byte_idx] |= 1u8 << bit_idx;
            }
        }
        // Padding remains zero
    }

    pub fn encode(&self) -> BlockV5a {
        let mut block = BlockV5a::new();

        // Pack streams
        pack_34_bits(&self.in1[..self.len], &mut block.in1_packed);
        pack_34_bits(&self.in2[..self.len], &mut block.in2_packed);
        pack_34_bits(&self.out[..self.len], &mut block.out_packed);
        pack_24_bits(&self.credits[..self.len], &mut block.credits_packed);

        // Pack gate types bitset
        // Byte 0 bit 0 => gate 0, ..., byte 31 bit 7 => gate 255
        for i in 0..self.len {
            if self.gate_types[i] != GateType::XOR {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                block.gate_types[byte_idx] |= 1u8 << bit_idx;
            }
        }
        block
    }

    pub fn clear(&mut self) {
        // Just reset len; content will be overwritten next time.
        self.len = 0;
    }
}

/// v5a Circuit Writer
pub struct CircuitWriterV5a {
    file: File,

    // Metadata
    primary_inputs: u64,
    outputs: Vec<u64>, // original outputs (for validation), we also store serialized bytes

    // Offsets and aggregation
    next_offset: u64, // where the next write after outputs will go
    io_buf: Vec<u8>,  // aggregation buffer
    io_buf_cap: usize,

    // Block builder
    block: BlockBuilder,

    // Stats
    xor_gates_written: u64,
    and_gates_written: u64,

    // Checksum
    hasher: Hasher,
}

impl CircuitWriterV5a {
    /// Create a new v5a writer. Writes a placeholder header, then outputs.
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        outputs: Vec<u64>,
    ) -> Result<Self> {
        // Validate outputs and encode to bytes (5 bytes per output, lower 34 bits)
        let outputs_bytes = encode_outputs_le34(&outputs)?;

        // Open/truncate file (buffered; no O_DIRECT)
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        let file = opts.open(path.as_ref()).await?;

        // Write header placeholder (72 bytes of zero) and outputs
        let header_placeholder = vec![0u8; HEADER_SIZE_V5A];
        let outputs_offset = HEADER_SIZE_V5A as u64;
        {
            let (res, _) = file.write_all_at(header_placeholder, 0).await;
            res?;
        }
        {
            let (res, _) = file
                .write_all_at(outputs_bytes.clone(), outputs_offset)
                .await;
            res?;
        }

        // Initialize hasher (blocks will be hashed as written)
        let hasher = Hasher::new();

        // Compute the next offset after outputs
        let next_offset = outputs_offset + outputs_bytes.len() as u64;

        Ok(Self {
            file,
            primary_inputs,
            outputs,
            next_offset,
            io_buf: Vec::with_capacity(DEFAULT_IO_BUFFER_CAP),
            io_buf_cap: DEFAULT_IO_BUFFER_CAP,
            block: BlockBuilder::new(),
            xor_gates_written: 0,
            and_gates_written: 0,
            hasher,
        })
    }

    /// Optionally tune the I/O aggregation buffer capacity (bytes).
    /// Call this before writing gates for effect.
    pub fn set_io_buffer_capacity(&mut self, cap: usize) {
        self.io_buf_cap = cap.max(BLOCK_SIZE_BYTES);
        if self.io_buf.capacity() < self.io_buf_cap {
            self.io_buf
                .reserve(self.io_buf_cap - self.io_buf.capacity());
        }
    }

    /// Write a single gate.
    pub async fn write_gate(&mut self, gate: GateV5a) -> Result<()> {
        self.block.push(gate)?;
        match gate.gate_type {
            GateType::AND => self.and_gates_written += 1,
            GateType::XOR => self.xor_gates_written += 1,
        }

        if self.block.is_full() {
            self.flush_block().await?;
        }
        Ok(())
    }

    /// Write multiple gates (slice).
    pub async fn write_gates(&mut self, gates: &[GateV5a]) -> Result<()> {
        for &g in gates {
            self.write_gate(g).await?;
        }
        Ok(())
    }

    /// Write multiple gates (generic iterator).
    pub async fn write_gates_iter<I: IntoIterator<Item = GateV5a>>(
        &mut self,
        gates: I,
    ) -> Result<()> {
        for g in gates {
            self.write_gate(g).await?;
        }
        Ok(())
    }

    /// Finalize: flush pending data, compute checksum, and write header.
    pub async fn finalize(mut self) -> Result<CircuitStats> {
        // Flush any partial block
        if !self.block.is_empty() {
            self.flush_block().await?;
        }
        // Flush aggregation buffer
        self.flush_io_buffer().await?;

        // Hash outputs (after blocks have been hashed)
        let outputs_bytes = encode_outputs_le34(&self.outputs)?;
        self.hasher.update(&outputs_bytes);

        // Hash header fields after checksum
        // Order: xor_gates, and_gates, primary_inputs, num_outputs (all LE)
        let mut header_tail = [0u8; 32];
        header_tail[0..8].copy_from_slice(&self.xor_gates_written.to_le_bytes());
        header_tail[8..16].copy_from_slice(&self.and_gates_written.to_le_bytes());
        header_tail[16..24].copy_from_slice(&self.primary_inputs.to_le_bytes());
        header_tail[24..32].copy_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        self.hasher.update(&header_tail);

        let checksum = *self.hasher.finalize().as_bytes();

        // Build header bytes (explicit LE encoding, no unsafe)
        let header_bytes = encode_header_v5a_le(
            &checksum,
            self.xor_gates_written,
            self.and_gates_written,
            self.primary_inputs,
            self.outputs.len() as u64,
        );

        // Write header back at offset 0
        {
            let (res, _) = self.file.write_all_at(header_bytes.to_vec(), 0).await;
            res?;
        }
        // Ensure all data is on disk
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
            checksum,
        };
        Ok(stats)
    }

    // Encode and queue the current full block for writing and hashing.
    async fn flush_block(&mut self) -> Result<()> {
        let mut block = [0u8; BLOCK_SIZE_BYTES];
        self.block.encode_into(&mut block);
        self.block.clear();

        // Hash the block as it's written
        self.hasher.update(&block);

        // Append to IO buffer; flush if needed
        if self.io_buf.len() + BLOCK_SIZE_BYTES > self.io_buf_cap {
            self.flush_io_buffer().await?;
        }
        self.io_buf.extend_from_slice(&block);
        Ok(())
    }

    // Flush aggregation buffer to disk at current offset.
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
        self.io_buf = buf; // reuse allocation
        self.io_buf.clear(); // clear the buffer after reuse
        self.next_offset += len as u64;
        Ok(())
    }
}

/// Encode v5a header to bytes (72 bytes total, LE).
fn encode_header_v5a_le(
    checksum: &[u8; 32],
    xor_gates: u64,
    and_gates: u64,
    primary_inputs: u64,
    num_outputs: u64,
) -> [u8; HEADER_SIZE_V5A] {
    let mut h = [0u8; HEADER_SIZE_V5A];
    // Identification
    h[0..4].copy_from_slice(&MAGIC);
    h[4] = VERSION;
    h[5] = FORMAT_TYPE_A;
    // h[6..8] reserved zeros
    // Checksum
    h[8..40].copy_from_slice(checksum);
    // Metadata (LE)
    h[40..48].copy_from_slice(&xor_gates.to_le_bytes());
    h[48..56].copy_from_slice(&and_gates.to_le_bytes());
    h[56..64].copy_from_slice(&primary_inputs.to_le_bytes());
    h[64..72].copy_from_slice(&num_outputs.to_le_bytes());
    h
}

/// Encode outputs to 5-byte little-endian entries (lower 34 bits used, upper 6 must be zero).
fn encode_outputs_le34(outputs: &[u64]) -> Result<Vec<u8>> {
    let capacity = outputs
        .len()
        .checked_mul(5)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "outputs length overflow"))?;
    let mut buf = Vec::with_capacity(capacity);
    for &w in outputs {
        if w > MAX_WIRE_ID {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "output wire ID exceeds 34-bit limit",
            ));
        }
        let v = w & MAX_WIRE_ID;
        let le = v.to_le_bytes();
        buf.extend_from_slice(&le[..5]); // contains the lower 34 bits in LE order
    }
    Ok(buf)
}

/// Pack 34-bit values tightly into output. Output must be large enough for values.len() × 34 bits.
fn pack_34_bits(values: &[u64], output: &mut [u8]) {
    // Expected length: ceil(values.len() * 34 / 8)
    // We rely on caller to pass the correct 1088-sized slice for 256, or exact for partial usage.
    let mut bit_offset = 0usize;
    for &raw in values {
        let v = raw & MAX_WIRE_ID; // 34 bits
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            // aligned: 5 bytes
            output[byte_offset] = v as u8;
            output[byte_offset + 1] = (v >> 8) as u8;
            output[byte_offset + 2] = (v >> 16) as u8;
            output[byte_offset + 3] = (v >> 24) as u8;
            output[byte_offset + 4] = (v >> 32) as u8;
        } else {
            // unaligned: up to 6 bytes spanned
            let shifted = v << bit_shift;
            output[byte_offset] |= shifted as u8;
            output[byte_offset + 1] |= (shifted >> 8) as u8;
            output[byte_offset + 2] |= (shifted >> 16) as u8;
            output[byte_offset + 3] |= (shifted >> 24) as u8;
            output[byte_offset + 4] |= (shifted >> 32) as u8;
            let sixth = (shifted >> 40) as u8;
            if sixth != 0 {
                output[byte_offset + 5] |= sixth;
            }
        }
        bit_offset += 34;
    }
}

/// Pack 24-bit values tightly into output. Output must be large enough for values.len() × 24 bits.
fn pack_24_bits(values: &[u32], output: &mut [u8]) {
    let mut bit_offset = 0usize;
    for &raw in values {
        let v = raw & MAX_CREDITS; // 24 bits
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            // aligned: 3 bytes
            output[byte_offset] = v as u8;
            output[byte_offset + 1] = (v >> 8) as u8;
            output[byte_offset + 2] = (v >> 16) as u8;
        } else {
            // unaligned: up to 4 bytes spanned
            let shifted = (v as u32) << bit_shift;
            output[byte_offset] |= shifted as u8;
            output[byte_offset + 1] |= (shifted >> 8) as u8;
            output[byte_offset + 2] |= (shifted >> 16) as u8;
            let fourth = (shifted >> 24) as u8;
            if fourth != 0 {
                output[byte_offset + 3] |= fourth;
            }
        }
        bit_offset += 24;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions as StdOpen;
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::tempdir;

    // Helper: extract 34-bit value starting at bit_offset from data slice.
    fn extract_34_bits(data: &[u8], bit_offset: usize) -> u64 {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let mut bytes = [0u8; 8];
        let to_copy = std::cmp::min(8, data.len().saturating_sub(byte_offset));
        if to_copy > 0 {
            bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);
        }
        let val = u64::from_le_bytes(bytes);
        (val >> bit_shift) & MAX_WIRE_ID
    }

    // Helper: extract 24-bit value starting at bit_offset from data slice.
    fn extract_24_bits(data: &[u8], bit_offset: usize) -> u32 {
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let mut bytes = [0u8; 4];
        let to_copy = std::cmp::min(4, data.len().saturating_sub(byte_offset));
        if to_copy > 0 {
            bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);
        }
        let val = u32::from_le_bytes(bytes);
        ((val >> bit_shift) & 0xFF_FFFF) as u32
    }

    #[test]
    fn test_pack_34_bits_basic() {
        let vals = vec![0, 1, 2, 3, MAX_WIRE_ID, 0x123456789 & MAX_WIRE_ID];
        let need = (vals.len() * 34 + 7) / 8;
        let mut out = vec![0u8; need];
        pack_34_bits(&vals, &mut out);

        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(extract_34_bits(&out, i * 34), v);
        }
    }

    #[test]
    fn test_pack_24_bits_basic() {
        let vals = vec![0, 1, 2, 3, MAX_CREDITS, 0x00BBCCDD & MAX_CREDITS];
        let need = (vals.len() * 24 + 7) / 8;
        let mut out = vec![0u8; need];
        pack_24_bits(&vals, &mut out);

        for (i, &v) in vals.iter().enumerate() {
            assert_eq!(extract_24_bits(&out, i * 24), v);
        }
    }

    #[test]
    fn test_block_builder_encode() {
        let mut bb = BlockBuilder::new();
        // Create < GATES_PER_BLOCK gates to test partial
        for i in 0..100 {
            let g = GateV5a {
                in1: (2 + i as u64) & MAX_WIRE_ID,
                in2: (3 + i as u64) & MAX_WIRE_ID,
                out: (100 + i as u64) & MAX_WIRE_ID,
                credits: (i as u32) & MAX_CREDITS,
                gate_type: match i % 2 {
                    0 => GateType::XOR,
                    _ => GateType::AND,
                },
            };
            bb.push(g).unwrap();
        }
        let mut block = vec![0u8; BLOCK_SIZE_BYTES];
        bb.encode_into(&mut block);

        // Verify first few in1 values
        for i in 0..10 {
            let got = extract_34_bits(&block[IN1_OFFSET..IN1_OFFSET + IN_STREAM_SIZE], i * 34);
            assert_eq!(got, 2 + i as u64);
        }
        // Verify types for first 16
        for i in 0..16 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (block[TYPES_OFFSET + byte_idx] >> bit_idx) & 1;
            assert_eq!(bit, (i % 2) as u8);
        }
        // Verify padding area is zeroed (spot-check some entries)
        for gate_idx in [120usize, 200, 255] {
            let bit = {
                let byte_idx = gate_idx / 8;
                let bit_idx = gate_idx % 8;
                (block[TYPES_OFFSET + byte_idx] >> bit_idx) & 1
            };
            assert_eq!(bit, 0);
        }
    }

    #[monoio::test]
    async fn test_writer_empty_circuit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.v5a");

        let writer = CircuitWriterV5a::new(&path, 10, vec![2, 3, 4])
            .await
            .unwrap();
        let stats = writer.finalize().await.unwrap();

        assert_eq!(stats.total_gates, 0);
        assert_eq!(stats.primary_inputs, 10);
        assert_eq!(stats.num_outputs, 3);

        // Verify checksum independently by reading file and recomputing
        assert!(verify_file_checksum(&path).unwrap());
    }

    #[monoio::test]
    async fn test_writer_with_gates_and_partial_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("gates.v5a");

        let mut writer = CircuitWriterV5a::new(&path, 2, vec![6]).await.unwrap();

        let gates = vec![
            GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: 2,
                gate_type: GateType::XOR,
            },
            GateV5a {
                in1: 2,
                in2: 4,
                out: 5,
                credits: 1,
                gate_type: GateType::AND,
            },
            GateV5a {
                in1: 4,
                in2: 5,
                out: 6,
                credits: 0,
                gate_type: GateType::XOR,
            },
        ];
        writer.write_gates(&gates).await.unwrap();
        let stats = writer.finalize().await.unwrap();

        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);

        // Verify checksum
        assert!(verify_file_checksum(&path).unwrap());

        // Also verify padding of partial block (by reading types tail area is zero)
        let mut f = StdOpen::new().read(true).open(&path).unwrap();
        let mut header = [0u8; HEADER_SIZE_V5A];
        f.read_exact(&mut header).unwrap();
        let num_outputs = u64::from_le_bytes(header[64..72].try_into().unwrap()) as usize;
        let outputs_size = num_outputs * 5;
        f.seek(SeekFrom::Start((HEADER_SIZE_V5A + outputs_size) as u64))
            .unwrap();

        let mut block = vec![0u8; BLOCK_SIZE_BYTES];
        f.read_exact(&mut block).unwrap();

        for i in 3..GATES_PER_BLOCK {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (block[TYPES_OFFSET + byte_idx] >> bit_idx) & 1;
            assert_eq!(bit, 0, "padding gate type bit not zero at {}", i);
        }
    }

    #[monoio::test]
    async fn test_writer_rejects_bad_output_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad_out.v5a");
        let too_big = MAX_WIRE_ID + 1;

        let res = CircuitWriterV5a::new(&path, 2, vec![too_big]).await;
        assert!(res.is_err());
    }

    #[monoio::test]
    async fn test_verify_checksum_corruption_detection() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.v5a");

        {
            let mut writer = CircuitWriterV5a::new(&path, 3, vec![100, 101])
                .await
                .unwrap();
            let gates = vec![
                GateV5a {
                    in1: 2,
                    in2: 3,
                    out: 100,
                    credits: 0,
                    gate_type: GateType::XOR,
                },
                GateV5a {
                    in1: 3,
                    in2: 4,
                    out: 101,
                    credits: 0,
                    gate_type: GateType::AND,
                },
            ];
            writer.write_gates(&gates).await.unwrap();
            writer.finalize().await.unwrap();
        }

        assert!(verify_file_checksum(&path).unwrap());

        // Corrupt a byte in the blocks area
        let mut f = StdOpen::new().read(true).write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(100)).unwrap();
        f.write_all(&[0xFF]).unwrap();

        assert!(!verify_file_checksum(&path).unwrap());
    }

    // Reference checksum verifier for tests (pure std I/O).
    fn verify_file_checksum(path: &Path) -> Result<bool> {
        let mut f = StdOpen::new().read(true).open(path)?;

        // Read header
        let mut header = [0u8; HEADER_SIZE_V5A];
        f.read_exact(&mut header)?;
        if &header[0..4] != b"Zk2u" || header[4] != 0x05 || header[5] != 0x00 {
            return Err(Error::new(ErrorKind::InvalidData, "invalid header"));
        }
        let file_checksum = &header[8..40];
        let num_outputs = u64::from_le_bytes(header[64..72].try_into().unwrap()) as usize;
        let outputs_size = num_outputs * 5;

        let mut hasher = Hasher::new();

        // Checksum order: blocks || outputs || header tail

        // 1. Hash blocks (seek past outputs to blocks region)
        f.seek(SeekFrom::Start((HEADER_SIZE_V5A + outputs_size) as u64))?;
        let mut blocks = Vec::new();
        f.read_to_end(&mut blocks)?;
        hasher.update(&blocks);

        // 2. Hash outputs (seek back to after header)
        if outputs_size > 0 {
            f.seek(SeekFrom::Start(HEADER_SIZE_V5A as u64))?;
            let mut outputs = vec![0u8; outputs_size];
            f.read_exact(&mut outputs)?;
            hasher.update(&outputs);
        }

        // 3. Hash header tail
        hasher.update(&header[40..72]);

        Ok(hasher.finalize().as_bytes() == file_checksum)
    }
}

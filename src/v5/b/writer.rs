// src/v5/b/writer.rs

//! v5b Writer (safe, spec-compliant, performant)
//!
//! - Level API: start_level → add_gate(GateType, GateV5b)* → finish_level
//! - You may intersperse XOR and AND gates in any order when adding.
//!   The writer reorders per-level to XORs-first then ANDs, as required by the format.
//!   Blocks naturally may contain both XORs and ANDs at the boundary (e.g., if num_xor % 504 != 0).
//! - Packs gates into 504-gate blocks with SoA layout (24-bit fields).
//! - Writes header placeholder + outputs, streams levels, then backpatches header with checksum.
//! - Computes checksum in spec order: outputs || (level_header || blocks...) || header[40..].
//! - Uses monoio for async I/O. No O_DIRECT.
//! - Handles partial blocks safely: zero-padded; readers rely on header fields.

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::GateType;
use crate::v5::b::{
    BLOCK_SIZE, GATES_PER_BLOCK, HEADER_SIZE, IN1_STREAM_SIZE, IN2_STREAM_SIZE, LEVEL_HEADER_SIZE,
    MAX_MEMORY_ADDRESS, OUT_STREAM_SIZE,
};

// Identification constants (fixed by spec)
const MAGIC: [u8; 4] = *b"Zk2u";
const VERSION: u8 = 0x05;
const FORMAT_TYPE_B: u8 = 0x01;

// Default I/O aggregation buffer size (tunable)
const DEFAULT_IO_BUFFER_CAP: usize = 8 * 1024 * 1024; // 8 MiB

/// A single gate in v5b format (24-bit addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateV5b {
    pub in1: u32,
    pub in2: u32,
    pub out: u32,
}

impl GateV5b {
    pub fn new(in1: u32, in2: u32, out: u32) -> Result<Self> {
        validate_addr(in1)?;
        validate_addr(in2)?;
        validate_addr(out)?;
        Ok(GateV5b { in1, in2, out })
    }
}

#[inline]
fn validate_addr(addr: u32) -> Result<()> {
    if addr >= MAX_MEMORY_ADDRESS {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "address exceeds 24-bit maximum",
        ));
    }
    Ok(())
}

/// Writer statistics returned after writing
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub scratch_space: u64,
    pub num_outputs: u64,
    pub num_levels: u32,
    pub checksum: [u8; 32],
}

/// Internal: buffers a level’s gates, keeping XOR and AND in separate vectors.
/// Allows adding in any order; on write, they are concatenated XORs first, then ANDs.
struct LevelBuilder {
    xors: Vec<GateV5b>,
    ands: Vec<GateV5b>,
    // Track max address seen for later validation against scratch_space
    max_addr_seen: u32,
}

impl LevelBuilder {
    fn new() -> Self {
        Self {
            xors: Vec::new(),
            ands: Vec::new(),
            max_addr_seen: 0,
        }
    }

    fn add_gate(&mut self, gate_type: GateType, gate: GateV5b) {
        self.max_addr_seen = self.max_addr_seen.max(gate.in1).max(gate.in2).max(gate.out);
        match gate_type {
            GateType::XOR => self.xors.push(gate),
            GateType::AND => self.ands.push(gate),
        }
    }

    fn num_xor(&self) -> u32 {
        self.xors.len() as u32
    }

    fn num_and(&self) -> u32 {
        self.ands.len() as u32
    }

    fn clear(&mut self) {
        self.xors.clear();
        self.ands.clear();
        self.max_addr_seen = 0;
    }
}

/// v5b Circuit Writer
pub struct CircuitWriterV5b {
    file: File,

    // Metadata
    primary_inputs: u64,
    outputs: Vec<u32>,

    // Aggregation & offsets
    next_offset: u64,
    io_buf: Vec<u8>,
    io_buf_cap: usize,

    // Checksum
    hasher: Hasher,

    // Global stats
    xor_gates_written: u64,
    and_gates_written: u64,
    num_levels: u32,

    // Global max address seen across all outputs and gates (for scratch_space validation)
    max_addr_seen: u32,

    // Level state
    in_level: bool,
    level: LevelBuilder,
}

impl CircuitWriterV5b {
    /// Create a new v5b writer. Writes a placeholder header and outputs.
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        outputs: Vec<u32>,
    ) -> Result<Self> {
        // Validate and encode outputs
        let (outputs_bytes, max_out_addr) = encode_outputs_le24(&outputs)?;

        // Open/truncate file (buffered)
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        let file = opts.open(path.as_ref()).await?;

        // Header placeholder
        let header_placeholder = vec![0u8; HEADER_SIZE];
        let outputs_offset = HEADER_SIZE as u64;
        {
            let (res, _) = file.write_all_at(header_placeholder, 0).await;
            res?;
        }
        // Outputs section
        {
            let (res, _) = file
                .write_all_at(outputs_bytes.clone(), outputs_offset)
                .await;
            res?;
        }

        // Initialize checksum with outputs (spec step 1)
        let mut hasher = Hasher::new();
        hasher.update(&outputs_bytes);

        let next_offset = outputs_offset + outputs_bytes.len() as u64;

        Ok(Self {
            file,
            primary_inputs,
            outputs,
            next_offset,
            io_buf: Vec::with_capacity(DEFAULT_IO_BUFFER_CAP),
            io_buf_cap: DEFAULT_IO_BUFFER_CAP,
            hasher,
            xor_gates_written: 0,
            and_gates_written: 0,
            num_levels: 0,
            max_addr_seen: max_out_addr,
            in_level: false,
            level: LevelBuilder::new(),
        })
    }

    /// Optionally tune the I/O aggregation buffer capacity (bytes).
    pub fn set_io_buffer_capacity(&mut self, cap: usize) {
        self.io_buf_cap = cap.max(BLOCK_SIZE);
        if self.io_buf.capacity() < self.io_buf_cap {
            self.io_buf
                .reserve(self.io_buf_cap - self.io_buf.capacity());
        }
    }

    /// Begin a new level. Returns error if a level is already in progress.
    pub fn start_level(&mut self) -> Result<()> {
        if self.in_level {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "level already started; finish_level() before starting another",
            ));
        }
        self.in_level = true;
        self.level.clear();
        Ok(())
    }

    /// Add a gate (XOR or AND) to the current level in any order.
    /// Assumes `GateType` is bool-like: false = XOR, true = AND (as used in v5a).
    pub fn add_gate(&mut self, gate_type: GateType, gate: GateV5b) -> Result<()> {
        if !self.in_level {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "add_gate() called without start_level()",
            ));
        }
        validate_addr(gate.in1)?;
        validate_addr(gate.in2)?;
        validate_addr(gate.out)?;
        self.level.add_gate(gate_type, gate);
        Ok(())
    }

    /// Finish the current level: writes LevelHeader + blocks, hashes them, and updates counters.
    pub async fn finish_level(&mut self) -> Result<()> {
        if !self.in_level {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "finish_level() called without start_level()",
            ));
        }

        let num_xor = self.level.num_xor();
        let num_and = self.level.num_and();
        let num_gates = num_xor + num_and;

        // Update global stats
        self.xor_gates_written += num_xor as u64;
        self.and_gates_written += num_and as u64;
        self.num_levels = self
            .num_levels
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::Other, "num_levels overflow"))?;
        self.max_addr_seen = self.max_addr_seen.max(self.level.max_addr_seen);

        // Write LevelHeader (num_xor, num_and) as 8 bytes LE
        let level_header = encode_level_header_le(num_xor, num_and);
        self.hasher.update(&level_header);
        self.enqueue_bytes(&level_header).await?;

        // Move vectors out to avoid borrow across await, then write blocks in XOR-then-AND order
        if num_gates > 0 {
            let xors = std::mem::take(&mut self.level.xors);
            let ands = std::mem::take(&mut self.level.ands);

            self.write_level_blocks_and_hash_segments(&xors, &ands)
                .await?;

            // keep allocations for reuse
            let mut x = xors;
            let mut a = ands;
            x.clear();
            a.clear();
            self.level.xors = x;
            self.level.ands = a;
        }

        // Reset level state
        self.in_level = false;
        self.level.max_addr_seen = 0;

        Ok(())
    }

    /// Finalize: flush pending data, compute checksum, and write header.
    pub async fn finalize(mut self, scratch_space: u64) -> Result<CircuitStats> {
        if self.in_level {
            // Auto-finish current level to avoid dangling state (allows empty levels)
            self.finish_level().await?;
        }

        if scratch_space > MAX_MEMORY_ADDRESS as u64 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "scratch_space exceeds 24-bit addressable memory",
            ));
        }

        // Validate that all addresses fit into scratch_space (outputs + gates)
        if (self.max_addr_seen as u64) >= scratch_space {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "some addresses are >= scratch_space",
            ));
        }

        // Flush aggregation buffer
        self.flush_io_buffer().await?;

        // Hash header fields after checksum (spec step 3)
        // 40..48: xor_gates (u64 LE)
        // 48..56: and_gates (u64 LE)
        // 56..64: primary_inputs (u64 LE)
        // 64..72: scratch_space (u64 LE)
        // 72..80: num_outputs (u64 LE)
        // 80..84: num_levels (u32 LE)
        // 84..88: reserved2 (u32 LE) == 0
        let mut header_tail = [0u8; (HEADER_SIZE - 40)];
        let mut off = 0usize;
        header_tail[off..off + 8].copy_from_slice(&self.xor_gates_written.to_le_bytes());
        off += 8;
        header_tail[off..off + 8].copy_from_slice(&self.and_gates_written.to_le_bytes());
        off += 8;
        header_tail[off..off + 8].copy_from_slice(&self.primary_inputs.to_le_bytes());
        off += 8;
        header_tail[off..off + 8].copy_from_slice(&scratch_space.to_le_bytes());
        off += 8;
        header_tail[off..off + 8].copy_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        off += 8;
        header_tail[off..off + 4].copy_from_slice(&self.num_levels.to_le_bytes());
        off += 4;
        header_tail[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        self.hasher.update(&header_tail);

        let checksum = *self.hasher.finalize().as_bytes();

        // Build header bytes (explicit LE encoding)
        let header_bytes = encode_header_v5b_le(
            &checksum,
            self.xor_gates_written,
            self.and_gates_written,
            self.primary_inputs,
            scratch_space,
            self.outputs.len() as u64,
            self.num_levels,
        );

        // Write header at offset 0 and sync
        {
            let (res, _) = self.file.write_all_at(header_bytes.to_vec(), 0).await;
            res?;
        }
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            scratch_space,
            num_outputs: self.outputs.len() as u64,
            num_levels: self.num_levels,
            checksum,
        };
        Ok(stats)
    }

    // Internal: write and hash all blocks for a level using XOR-then-AND segments.
    async fn write_level_blocks_and_hash_segments(
        &mut self,
        xors: &[GateV5b],
        ands: &[GateV5b],
    ) -> Result<()> {
        let total = xors.len() + ands.len();
        let mut global_idx = 0usize;

        while global_idx < total {
            let take = std::cmp::min(GATES_PER_BLOCK, total - global_idx);

            // Prepare block buffers (SoA, zero-filled)
            let mut in1 = [0u8; IN1_STREAM_SIZE];
            let mut in2 = [0u8; IN2_STREAM_SIZE];
            let mut out = [0u8; OUT_STREAM_SIZE];

            // Pack 24-bit values for this block
            for j in 0..take {
                let gate = get_gate_by_concatenated_index(xors, ands, global_idx + j);
                pack_24bit_at(&mut in1, j, gate.in1);
                pack_24bit_at(&mut in2, j, gate.in2);
                pack_24bit_at(&mut out, j, gate.out);
            }

            // Append to IO buffer
            self.enqueue_bytes(&in1).await?;
            self.enqueue_bytes(&in2).await?;
            self.enqueue_bytes(&out).await?;

            // Hash exactly the bytes we wrote for this block, in order
            self.hasher.update(&in1);
            self.hasher.update(&in2);
            self.hasher.update(&out);

            global_idx += take;
        }

        Ok(())
    }

    // Append bytes to aggregation buffer, flushing if needed
    async fn enqueue_bytes(&mut self, data: &[u8]) -> Result<()> {
        if self.io_buf.len() + data.len() > self.io_buf_cap {
            self.flush_io_buffer().await?;
        }
        self.io_buf.extend_from_slice(data);
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
        self.next_offset += len as u64;
        Ok(())
    }
}

/// Encode v5b header to bytes (HEADER_SIZE: 88 bytes total).
fn encode_header_v5b_le(
    checksum: &[u8; 32],
    xor_gates: u64,
    and_gates: u64,
    primary_inputs: u64,
    scratch_space: u64,
    num_outputs: u64,
    num_levels: u32,
) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    // Identification
    h[0..4].copy_from_slice(&MAGIC);
    h[4] = VERSION;
    h[5] = FORMAT_TYPE_B;
    // h[6..8] reserved zeros

    // Checksum
    h[8..40].copy_from_slice(checksum);

    // Metadata (LE)
    h[40..48].copy_from_slice(&xor_gates.to_le_bytes());
    h[48..56].copy_from_slice(&and_gates.to_le_bytes());
    h[56..64].copy_from_slice(&primary_inputs.to_le_bytes());
    h[64..72].copy_from_slice(&scratch_space.to_le_bytes());
    h[72..80].copy_from_slice(&num_outputs.to_le_bytes());
    h[80..84].copy_from_slice(&num_levels.to_le_bytes());
    // h[84..88] reserved2 zeros

    h
}

/// Encode a LevelHeader (8 bytes) as little-endian:
/// [0..4): num_xor (u32 LE)
/// [4..8): num_and (u32 LE)
#[inline]
fn encode_level_header_le(num_xor: u32, num_and: u32) -> [u8; LEVEL_HEADER_SIZE] {
    let mut buf = [0u8; LEVEL_HEADER_SIZE];
    buf[0..4].copy_from_slice(&num_xor.to_le_bytes());
    buf[4..8].copy_from_slice(&num_and.to_le_bytes());
    buf
}

/// Encode outputs to 3-byte little-endian entries (lower 24 bits).
fn encode_outputs_le24(outputs: &[u32]) -> Result<(Vec<u8>, u32)> {
    let mut buf = Vec::with_capacity(outputs.len() * 3);
    let mut max_addr = 0u32;
    for &addr in outputs {
        validate_addr(addr)?;
        let le = addr.to_le_bytes(); // we only use 3 bytes
        buf.extend_from_slice(&le[..3]);
        max_addr = max_addr.max(addr);
    }
    Ok((buf, max_addr))
}

/// Get gate by global index from the conceptual concatenation of `xors || ands`.
#[inline]
fn get_gate_by_concatenated_index<'a>(
    xors: &'a [GateV5b],
    ands: &'a [GateV5b],
    idx: usize,
) -> &'a GateV5b {
    if idx < xors.len() {
        &xors[idx]
    } else {
        &ands[idx - xors.len()]
    }
}

/// Pack a 24-bit value at position `gate_idx` in a packed stream.
#[inline]
fn pack_24bit_at(stream: &mut [u8], gate_idx: usize, value: u32) {
    debug_assert!(stream.len() == IN1_STREAM_SIZE); // also valid for IN2/OUT sizes
    debug_assert!(gate_idx < GATES_PER_BLOCK);
    debug_assert!(value < MAX_MEMORY_ADDRESS);

    let bit_offset = gate_idx * 24;
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;

    if bit_shift == 0 {
        stream[byte_offset] = (value & 0xFF) as u8;
        stream[byte_offset + 1] = ((value >> 8) & 0xFF) as u8;
        stream[byte_offset + 2] = ((value >> 16) & 0xFF) as u8;
    } else {
        // Merge bits into up to 4 bytes
        let shifted = (value as u32) << bit_shift;
        stream[byte_offset] |= shifted as u8;
        stream[byte_offset + 1] |= (shifted >> 8) as u8;
        stream[byte_offset + 2] |= (shifted >> 16) as u8;

        let b3 = (shifted >> 24) as u8;
        if b3 != 0 && (byte_offset + 3) < stream.len() {
            stream[byte_offset + 3] |= b3;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions as StdOpen;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::tempdir;

    // Helper: unpack 24-bit at index from a packed stream
    fn unpack_24bit(stream: &[u8], gate_idx: usize) -> u32 {
        let bit_offset = gate_idx * 24;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;

        if bit_shift == 0 {
            let mut b = [0u8; 4];
            b[0..3].copy_from_slice(&stream[byte_offset..byte_offset + 3]);
            u32::from_le_bytes(b) & 0xFF_FFFF
        } else {
            let mut b = [0u8; 4];
            let end = std::cmp::min(byte_offset + 4, stream.len());
            let len = end - byte_offset;
            b[0..len].copy_from_slice(&stream[byte_offset..end]);
            (u32::from_le_bytes(b) >> bit_shift) & 0xFF_FFFF
        }
    }

    // Verify checksum by recomputing from file (outputs || rest || header[40..])
    fn verify_file_checksum(path: &Path) -> Result<bool> {
        let mut f = StdOpen::new().read(true).open(path)?;
        let mut header = vec![0u8; HEADER_SIZE];
        f.read_exact(&mut header)?;
        if &header[0..4] != b"Zk2u" || header[4] != VERSION || header[5] != FORMAT_TYPE_B {
            return Err(Error::new(ErrorKind::InvalidData, "invalid header"));
        }
        let file_checksum = &header[8..40];
        let num_outputs = u64::from_le_bytes(header[72..80].try_into().unwrap()) as usize;

        let outputs_size = num_outputs * 3;

        let mut hasher = Hasher::new();

        // Outputs
        if outputs_size > 0 {
            let mut outputs = vec![0u8; outputs_size];
            f.read_exact(&mut outputs)?;
            hasher.update(&outputs);
        }

        // Remainder (levels and blocks)
        let mut rest = Vec::new();
        f.read_to_end(&mut rest)?;
        hasher.update(&rest);

        // Header tail
        hasher.update(&header[40..HEADER_SIZE]);

        Ok(hasher.finalize().as_bytes() == file_checksum)
    }

    #[test]
    fn test_pack_24_bits_pack_unaligned_consistency() {
        let mut stream = vec![0u8; IN1_STREAM_SIZE];
        // 10 sample values
        for i in 0..10usize {
            pack_24bit_at(&mut stream, i, (i as u32) & 0xFF_FFFF);
        }
        for i in 0..10usize {
            assert_eq!(unpack_24bit(&stream, i), (i as u32) & 0xFF_FFFF);
        }
        // Ensure padding zeros beyond written gates (spot check)
        for i in [100usize, 200, GATES_PER_BLOCK - 1] {
            assert_eq!(unpack_24bit(&stream, i), 0);
        }
    }

    #[monoio::test]
    async fn test_writer_mixed_order_in_level_and_boundary_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v5b_mixed.v5b");

        let mut w = CircuitWriterV5b::new(&path, 2, vec![2, 3]).await.unwrap();
        w.start_level().unwrap();

        // Interspersed adds: create 300 XOR and 300 AND in mixed order
        // Final order for writing should be: 300 XORs first, then 300 ANDs.
        // This means the first block of 504 will contain 300 XORs + 204 ANDs (boundary mix).
        for i in 0..300u32 {
            let gx = GateV5b::new(2, 3, 1_000 + i).unwrap();
            w.add_gate(GateType::XOR, gx).unwrap();
            let ga = GateV5b::new(2, 3, 2_000 + i).unwrap();
            w.add_gate(GateType::AND, ga).unwrap();
        }

        w.finish_level().await.unwrap();

        let stats = w.finalize(10_000).await.unwrap();
        assert_eq!(stats.num_levels, 1);
        assert_eq!(stats.total_gates, 600);
        assert_eq!(stats.xor_gates, 300);
        assert_eq!(stats.and_gates, 300);
        assert!(verify_file_checksum(&path).unwrap());

        // Inspect boundary: first block has indices 0..503
        // We expect indices 0..299 = XOR outs in 1000-range, 300..503 = AND outs in 2000-range.
        let mut f = StdOpen::new().read(true).open(&path).unwrap();
        let mut header = vec![0u8; HEADER_SIZE];
        f.read_exact(&mut header).unwrap();
        let num_outputs = u64::from_le_bytes(header[72..80].try_into().unwrap()) as usize;
        let outputs_bytes = num_outputs * 3;
        f.seek(SeekFrom::Start((HEADER_SIZE + outputs_bytes) as u64))
            .unwrap();

        // Level header
        let mut level_hdr = [0u8; LEVEL_HEADER_SIZE];
        f.read_exact(&mut level_hdr).unwrap();
        let num_xor = u32::from_le_bytes(level_hdr[0..4].try_into().unwrap());
        let num_and = u32::from_le_bytes(level_hdr[4..8].try_into().unwrap());
        assert_eq!(num_xor, 300);
        assert_eq!(num_and, 300);

        // First block (full)
        let mut block1 = vec![0u8; BLOCK_SIZE];
        f.read_exact(&mut block1).unwrap();

        // Check outs for boundary expectations
        let out_stream = &block1[(IN1_STREAM_SIZE + IN2_STREAM_SIZE)
            ..(IN1_STREAM_SIZE + IN2_STREAM_SIZE + OUT_STREAM_SIZE)];
        for i in 0..300usize {
            let v = unpack_24bit(out_stream, i);
            assert_eq!(v, 1_000 + i as u32);
        }
        for i in 300..GATES_PER_BLOCK {
            let v = unpack_24bit(out_stream, i);
            // First block continues with ANDs starting at index 0..203 (204 entries)
            let and_idx = i - 300;
            assert_eq!(v, 2_000 + and_idx as u32);
        }
    }

    #[monoio::test]
    async fn test_writer_validates_outputs_and_scratch_space() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v5b_val.v5b");

        // Invalid output address
        let res = CircuitWriterV5b::new(&path, 0, vec![MAX_MEMORY_ADDRESS]).await;
        assert!(res.is_err());

        // Valid outputs but too small scratch space at finalize
        let path2 = dir.path().join("v5b_val2.v5b");
        let mut w = CircuitWriterV5b::new(&path2, 0, vec![10]).await.unwrap();
        w.start_level().unwrap();
        w.add_gate(GateType::XOR, GateV5b::new(0, 1, 20).unwrap())
            .unwrap(); // XOR
        w.finish_level().await.unwrap();

        let res = w.finalize(10).await; // scratch_space=10 < max addr used (20)
        assert!(res.is_err());
    }
}

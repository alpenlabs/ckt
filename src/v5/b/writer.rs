//! v5b Writer (32-bit addresses, AoS layout) with modified checksum order
//!
//! API:
//! - start_level → add_gate(GateType, GateV5b)* → finish_level
//!
//! Behavior:
//! - You may intersperse XOR and AND gates in any order when adding.
//!   The writer reorders per-level to XORs-first then ANDs, as required by the format.
//! - Writes gates in Array-of-Structures (AoS) layout: [in1, in2, out] as 3 u32s (12 bytes).
//! - Writes header placeholder + zeroed output placeholders, streams levels,
//!   later overwrites outputs and backpatches the header with checksum.
//! - Computes checksum in this order (modified): levels || outputs || header_tail.
//!   This allows streaming-hash of levels as they're written without a second pass.
//! - Uses monoio for async I/O. No O_DIRECT.
//! - Zero-parse format: gates can be directly cast to &[GateV5b] on read.

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use crate::GateType;
use crate::v5::b::{GATE_SIZE, HEADER_SIZE, LEVEL_HEADER_SIZE, MAX_MEMORY_ADDRESS};

// Identification constants (fixed by spec)
const MAGIC: [u8; 4] = *b"Zk2u";
const VERSION: u8 = 0x05;
const FORMAT_TYPE_B: u8 = 0x01;

// Default I/O aggregation buffer size (tunable)
const DEFAULT_IO_BUFFER_CAP: usize = 8 * 1024 * 1024; // 8 MiB

/// A single gate in v5b format (32-bit addresses).
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

    /// Convert gate to bytes (12 bytes: 3 × u32 LE)
    fn as_bytes(&self) -> [u8; GATE_SIZE] {
        let mut bytes = [0u8; GATE_SIZE];
        bytes[0..4].copy_from_slice(&self.in1.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.in2.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.out.to_le_bytes());
        bytes
    }
}

#[inline]
fn validate_addr(addr: u32) -> Result<()> {
    if addr as u64 >= MAX_MEMORY_ADDRESS {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "address exceeds maximum addressable memory",
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

/// Internal: buffers a level's gates, keeping XOR and AND in separate vectors.
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

/// v5b Circuit Writer (checksum order: levels || outputs || header_tail)
pub struct CircuitWriterV5b {
    file: File,

    // Metadata
    primary_inputs: u64,
    num_outputs: u64,

    // Offsets
    outputs_offset: u64, // start of outputs (immediately after header)
    next_offset: u64,    // current end-of-file offset for streaming writes

    // Aggregation buffer for writes
    io_buf: Vec<u8>,
    io_buf_cap: usize,

    // Checksum (we stream-hash levels as we write them)
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
    /// Create a new writer. Writes a placeholder header and zeroed outputs.
    /// Does not hash outputs; checksum begins with levels region as they are written.
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        num_outputs: u64,
    ) -> Result<Self> {
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

        // Outputs placeholder: num_outputs entries of 4 bytes each, all zeros
        let outputs_len_bytes = num_outputs
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "num_outputs too large"))?
            as usize;
        let outputs_placeholder = vec![0u8; outputs_len_bytes];
        {
            let (res, _) = file.write_all_at(outputs_placeholder, outputs_offset).await;
            res?;
        }

        let levels_start_offset = outputs_offset + outputs_len_bytes as u64;
        let next_offset = levels_start_offset;

        Ok(Self {
            file,
            primary_inputs,
            num_outputs,
            outputs_offset,
            next_offset,
            io_buf: Vec::with_capacity(DEFAULT_IO_BUFFER_CAP),
            io_buf_cap: DEFAULT_IO_BUFFER_CAP,
            hasher: Hasher::new(), // Start hashing from empty; levels will be hashed as written
            xor_gates_written: 0,
            and_gates_written: 0,
            num_levels: 0,
            max_addr_seen: 0, // outputs unknown yet
            in_level: false,
            level: LevelBuilder::new(),
        })
    }

    /// Optionally tune the I/O aggregation buffer capacity (bytes).
    pub fn set_io_buffer_capacity(&mut self, cap: usize) {
        self.io_buf_cap = cap.max(GATE_SIZE);
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

    /// Finish the current level: writes LevelHeader + gates, hashes them, and updates counters.
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

        // Reject empty levels at write time
        if num_gates == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "empty levels are not allowed; level must contain at least one gate",
            ));
        }

        // Update global stats
        self.xor_gates_written += num_xor as u64;
        self.and_gates_written += num_and as u64;
        self.num_levels = self
            .num_levels
            .checked_add(1)
            .ok_or_else(|| Error::other("num_levels overflow"))?;
        self.max_addr_seen = self.max_addr_seen.max(self.level.max_addr_seen);

        // Write LevelHeader (num_xor, num_and) as 8 bytes LE and hash it now
        let level_header = encode_level_header_le(num_xor, num_and);
        self.hasher.update(&level_header);
        self.enqueue_bytes(&level_header).await?;

        // Write gates in XOR-then-AND order (AoS layout)
        if num_gates > 0 {
            let xors = std::mem::take(&mut self.level.xors);
            let ands = std::mem::take(&mut self.level.ands);

            self.write_and_hash_gates(&xors, &ands).await?;

            // Keep allocations for reuse
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

    /// Finalize: overwrite outputs, flush pending data, finish checksum (levels || outputs || header tail), and write header.
    pub async fn finalize(mut self, scratch_space: u64, outputs: Vec<u32>) -> Result<CircuitStats> {
        if self.in_level {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "cannot finalize with level in progress; call finish_level() first",
            ));
        }

        // Validate outputs length matches placeholder count
        if outputs.len() as u64 != self.num_outputs {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "finalize outputs length does not match the initial num_outputs",
            ));
        }

        // Validate and encode outputs; track max addr
        let (outputs_bytes, max_out_addr) = encode_outputs_le32(&outputs)?;
        self.max_addr_seen = self.max_addr_seen.max(max_out_addr);

        if scratch_space > MAX_MEMORY_ADDRESS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "scratch_space exceeds maximum addressable memory",
            ));
        }

        // Validate that all addresses fit into scratch_space (outputs + gates)
        if (self.max_addr_seen as u64) >= scratch_space {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "some addresses are >= scratch_space",
            ));
        }

        // Flush aggregation buffer (ensures all level bytes already hashed are on disk too)
        self.flush_io_buffer().await?;

        // Overwrite outputs placeholders with real outputs
        {
            let (res, _) = self
                .file
                .write_all_at(outputs_bytes.clone(), self.outputs_offset)
                .await;
            res?;
        }

        // Continue checksum: after levels, hash outputs and then header tail
        self.hasher.update(&outputs_bytes);

        // Build header tail and hash it
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
        header_tail[off..off + 8].copy_from_slice(&self.num_outputs.to_le_bytes());
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
            self.num_outputs,
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
            num_outputs: self.num_outputs,
            num_levels: self.num_levels,
            checksum,
        };
        Ok(stats)
    }

    // Internal: write and hash all gates for a level in XOR-then-AND order (AoS layout).
    async fn write_and_hash_gates(&mut self, xors: &[GateV5b], ands: &[GateV5b]) -> Result<()> {
        // Write XOR gates
        for gate in xors {
            let gate_bytes = gate.as_bytes();
            self.enqueue_bytes(&gate_bytes).await?;
            self.hasher.update(&gate_bytes);
        }

        // Write AND gates
        for gate in ands {
            let gate_bytes = gate.as_bytes();
            self.enqueue_bytes(&gate_bytes).await?;
            self.hasher.update(&gate_bytes);
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
        self.io_buf.clear(); // clear the buffer after reuse
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

/// Encode outputs to 4-byte little-endian u32 entries.
fn encode_outputs_le32(outputs: &[u32]) -> Result<(Vec<u8>, u32)> {
    let capacity = outputs
        .len()
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "outputs length overflow"))?;
    let mut buf = Vec::with_capacity(capacity);
    let mut max_addr = 0u32;
    for &addr in outputs {
        validate_addr(addr)?;
        buf.extend_from_slice(&addr.to_le_bytes());
        max_addr = max_addr.max(addr);
    }
    Ok((buf, max_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions as StdOpen;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::tempdir;

    // Verify checksum by recomputing from file (levels || outputs || header[40..])
    fn verify_file_checksum(path: &Path) -> Result<bool> {
        let mut f = StdOpen::new().read(true).open(path)?;
        let mut header = vec![0u8; HEADER_SIZE];
        f.read_exact(&mut header)?;
        if &header[0..4] != b"Zk2u" || header[4] != VERSION || header[5] != FORMAT_TYPE_B {
            return Err(Error::new(ErrorKind::InvalidData, "invalid header"));
        }
        let file_checksum = &header[8..40];
        let num_outputs = u64::from_le_bytes(header[72..80].try_into().unwrap()) as usize;
        let outputs_size = num_outputs * 4;

        let mut hasher = Hasher::new();

        // File layout: header || outputs || levels
        // We need to hash: levels || outputs || header tail
        // Seek to start of levels (after outputs)
        if outputs_size > 0 {
            f.seek(SeekFrom::Start((HEADER_SIZE + outputs_size) as u64))?;
        } else {
            f.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        }

        // Read all levels to EOF and hash them
        let mut levels = Vec::new();
        f.read_to_end(&mut levels)?;
        hasher.update(&levels);

        // Go back and read outputs, then hash them
        if outputs_size > 0 {
            f.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
            let mut outputs = vec![0u8; outputs_size];
            f.read_exact(&mut outputs)?;
            hasher.update(&outputs);
        }

        // Header tail
        hasher.update(&header[40..HEADER_SIZE]);

        Ok(hasher.finalize().as_bytes() == file_checksum)
    }

    #[monoio::test]
    async fn test_writer_simple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("simple.v5b");

        let mut w = CircuitWriterV5b::new(&path, 2, 2).await.unwrap();
        w.start_level().unwrap();

        // Add some gates
        for i in 0..10u32 {
            let gx = GateV5b::new(2, 3, 100 + i).unwrap();
            w.add_gate(GateType::XOR, gx).unwrap();
            let ga = GateV5b::new(2, 3, 200 + i).unwrap();
            w.add_gate(GateType::AND, ga).unwrap();
        }

        w.finish_level().await.unwrap();

        let stats = w.finalize(300, vec![102, 202]).await.unwrap();
        assert_eq!(stats.num_levels, 1);
        assert_eq!(stats.total_gates, 20);
        assert_eq!(stats.xor_gates, 10);
        assert_eq!(stats.and_gates, 10);
        assert!(verify_file_checksum(&path).unwrap());
    }

    #[monoio::test]
    async fn test_writer_validates_outputs_and_scratch_space() {
        let dir = tempdir().unwrap();

        // Valid outputs but too small scratch space at finalize
        let path = dir.path().join("v5b_val.v5b");
        let mut w = CircuitWriterV5b::new(&path, 0, 1).await.unwrap();
        w.start_level().unwrap();
        w.add_gate(GateType::XOR, GateV5b::new(0, 1, 20).unwrap())
            .unwrap(); // uses address 20
        w.finish_level().await.unwrap();

        // outputs contain 10, but max addr across outputs+gates is 20; scratch_space=10 -> error
        let res = w.finalize(10, vec![10]).await;
        assert!(res.is_err());
    }
}

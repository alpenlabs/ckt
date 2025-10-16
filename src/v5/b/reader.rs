// CKT v5b – production format (24-bit addresses, levelled)
//
// The design mirrors v5a::reader:
//
// 1. Parse & validate header + outputs
// 2. Spawn an I/O thread with triple-buffered O_DIRECT reads
// 3. Expose a two-level iterator hierarchy
//      • CircuitReaderV5b::next_level()  ->  Option<Level<'_>>
//      • Level<'_>::next_block_soa() / next_block()
// 4. Zero-allocation SoA decoding; reuses reader-owned scratch buffers

#![allow(clippy::let_unit_value)] // for select! branches

use std::{
    io::{Error, ErrorKind, Read, Result},
    mem,
    path::{Path, PathBuf},
    pin::pin,
    thread,
};

use crate::v5::avx512 as avx;
use crate::v5::b::{
    BLOCK_SIZE, GATES_PER_BLOCK, HEADER_SIZE, HeaderV5b, IN1_STREAM_SIZE, IN2_STREAM_SIZE,
    LEVEL_HEADER_SIZE, LevelHeader, OUTPUT_ENTRY_SIZE,
};
use blake3::Hasher;
use cynosure::site_d::triplebuffer::{
    AlignedBuffer, BUFFER_ALIGN, BufferStats, TripleBufReader, TripleBufWriter, triple_buffer,
};
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use monoio::{FusionDriver, select};

// -----------------------------------------------------------------------------
// Public decoded views
// -----------------------------------------------------------------------------

pub struct DecodedBlockSoA<'a> {
    pub in1: &'a [u32],
    pub in2: &'a [u32],
    pub out: &'a [u32],
    pub xor_gates: usize, // leading XORs; rest are ANDs
    pub block_index: u64,
    pub gates_in_block: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GateV5b {
    pub in1: u32,
    pub in2: u32,
    pub out: u32,
    // gate_type inferred by caller (see xor_gates in DecodedBlockSoA)
}

// -----------------------------------------------------------------------------
// CircuitReaderV5b – top-level object
// -----------------------------------------------------------------------------
pub struct CircuitReaderV5b {
    header: HeaderV5b,
    outputs: Vec<u32>,

    // Streaming-state ----------------------------------------------------------
    reader: TripleBufReader,
    stop_tx: Option<AsyncSender<()>>,
    io_jh: Option<thread::JoinHandle<()>>,

    cur_buf: Option<AlignedBuffer>,
    cur_pos: usize,       // cursor in current buffer
    bytes_remaining: u64, // gate-area bytes (levels+blocks) left

    // Per-file accounting
    levels_remaining: u32,
    block_index: u64, // global across file (debug/metrics only)

    // Decode scratch -----------------------------------------------------------
    block_staging: [u8; BLOCK_SIZE],
    in1: [u32; GATES_PER_BLOCK],
    in2: [u32; GATES_PER_BLOCK],
    out: [u32; GATES_PER_BLOCK],

    // Alignment handling
    prefix_skip: usize,
    first_chunk: bool,
}

impl CircuitReaderV5b {
    // -------------------------------------------------------------------------
    // Opening / header parsing
    // -------------------------------------------------------------------------
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut f = std::fs::OpenOptions::new().read(true).open(path.as_ref())?;

        // ---- Header ----------------------------------------------------------
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        f.read_exact(&mut hdr_bytes)?;
        let header = HeaderV5b::from_bytes(&hdr_bytes);
        header.validate().map_err(io_err)?;

        // ---- Outputs ---------------------------------------------------------
        let outputs_bytes_len = header
            .num_outputs
            .checked_mul(OUTPUT_ENTRY_SIZE as u64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "outputs length overflow"))?
            as usize;

        let mut outputs_raw = vec![0u8; outputs_bytes_len];
        if outputs_bytes_len > 0 {
            f.read_exact(&mut outputs_raw)?;
        }
        let outputs = decode_outputs_le24(&outputs_raw)?;

        // ---- Gate region bookkeeping ----------------------------------------
        //   [ level headers ][ blocks             ]
        // Note: We can't know the exact block count without reading level headers,
        // since each level rounds up its block count independently.
        // Instead, use the actual file size to determine the gate region size.
        let file_metadata = f.metadata()?;
        let file_size = file_metadata.len();

        // File offsets
        let gate_region_start = HEADER_SIZE as u64 + outputs_bytes_len as u64;
        let gate_region_end = file_size; // Read to end of file
        let gate_region_bytes = gate_region_end - gate_region_start;

        // O_DIRECT alignment
        let aligned_mask = (BUFFER_ALIGN as u64) - 1;
        let aligned_start = gate_region_start & !aligned_mask;
        let aligned_end = gate_region_end & !aligned_mask;
        let prefix_skip = (gate_region_start - aligned_start) as usize;
        let tail_len = (gate_region_end - aligned_end) as usize;

        // Triple buffer + I/O thread ------------------------------------------
        let (mut writer, reader, writer_buf) = triple_buffer();
        let (stop_tx, stop_rx) = bounded_async(1);
        let path_buf = path.as_ref().to_path_buf();

        let jh = thread::spawn(move || {
            if let Err(e) = io_thread_run(
                path_buf,
                aligned_start,
                aligned_end,
                tail_len,
                &mut writer,
                stop_rx,
                writer_buf,
            ) {
                eprintln!("v5b I/O thread error: {e}");
            }
        });

        Ok(Self {
            header,
            outputs,
            reader,
            stop_tx: Some(stop_tx),
            io_jh: Some(jh),

            cur_buf: None,
            cur_pos: 0,
            bytes_remaining: gate_region_bytes,
            levels_remaining: header.num_levels,
            block_index: 0,

            block_staging: [0u8; BLOCK_SIZE],
            in1: [0u32; GATES_PER_BLOCK],
            in2: [0u32; GATES_PER_BLOCK],
            out: [0u32; GATES_PER_BLOCK],

            prefix_skip,
            first_chunk: prefix_skip > 0,
        })
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------
    pub fn header(&self) -> HeaderV5b {
        self.header
    }
    pub fn outputs(&self) -> &[u32] {
        &self.outputs
    }

    // -------------------------------------------------------------------------
    // Level iteration
    // -------------------------------------------------------------------------
    pub async fn next_level<'r>(&'r mut self) -> Result<Option<Level<'r>>> {
        loop {
            if self.levels_remaining == 0 {
                return Ok(None);
            }
            // Read next 8-byte LevelHeader
            let mut hdr_buf = [0u8; LEVEL_HEADER_SIZE];
            self.read_exact_into(&mut hdr_buf).await?;
            let lvl = LevelHeader::from_bytes(&hdr_buf);
            lvl.validate().map_err(io_err)?;

            self.levels_remaining -= 1;

            // Skip empty levels if encountered during read
            if lvl.num_gates() == 0 {
                continue;
            }

            return Ok(Some(Level {
                reader: self,
                gates_remaining: lvl.num_gates(),
                xor_remaining: lvl.num_xor_gates,
            }));
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------
    async fn read_exact_into(&mut self, dst: &mut [u8]) -> Result<()> {
        let mut filled = 0usize;
        while filled < dst.len() {
            if self.cur_buf.is_none() || self.cur_pos >= self.cur_buf.as_ref().unwrap().len() {
                let prev = self.cur_buf.take();
                let next = self.reader.next(prev).await;
                self.cur_buf = Some(next);
                self.cur_pos = 0;

                // initial unaligned prefix
                while self.first_chunk && self.prefix_skip > 0 {
                    let b = self.cur_buf.as_ref().unwrap();
                    if b.len() <= self.prefix_skip {
                        self.prefix_skip -= b.len();
                        let prev = self.cur_buf.take();
                        let next = self.reader.next(prev).await;
                        self.cur_buf = Some(next);
                        self.cur_pos = 0;
                    } else {
                        self.cur_pos = self.prefix_skip;
                        self.prefix_skip = 0;
                        self.first_chunk = false;
                    }
                }
            }

            let b = self.cur_buf.as_ref().unwrap();
            let avail = b.len() - self.cur_pos;
            if avail == 0 {
                continue;
            }
            let want = (dst.len() - filled).min(avail);
            dst[filled..filled + want].copy_from_slice(&b[self.cur_pos..self.cur_pos + want]);
            self.cur_pos += want;
            filled += want;
            self.bytes_remaining -= want as u64;
        }
        Ok(())
    }

    // Read the next packed block into a temporary local buffer, decode it into
    // the reader's SoA arrays, and place the buffer back. No references to
    // self-fields live across the await.
    async fn read_and_decode_block(&mut self, gates_in_block: usize) -> Result<()> {
        // Handle empty blocks (no gates to read)
        if gates_in_block == 0 {
            return Ok(());
        }

        if self.bytes_remaining < BLOCK_SIZE as u64 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "truncated gate region",
            ));
        }

        // Move the staging buffer out to avoid holding a field-borrow across await.
        let mut tmp = mem::replace(&mut self.block_staging, [0u8; BLOCK_SIZE]);
        self.read_exact_into(&mut tmp).await?;

        // Decode from the local buffer into reader-owned SoA arrays.
        if avx::is_x86_avx512f() {
            unsafe {
                // Safe layout cast: avx::BlockV5b is a POD of three [u8; 1512] fields.
                debug_assert_eq!(core::mem::size_of::<avx::BlockV5b>(), BLOCK_SIZE);
                let blk_ref: &avx::BlockV5b = &*(tmp.as_ptr() as *const avx::BlockV5b);
                avx::decode_block_v5b_avx512(
                    blk_ref,
                    gates_in_block,
                    &mut self.in1,
                    &mut self.in2,
                    &mut self.out,
                );
            }
        } else {
            decode_block_scalar(
                &tmp,
                gates_in_block,
                &mut self.in1,
                &mut self.in2,
                &mut self.out,
            );
        }

        // Move the buffer back for reuse.
        self.block_staging = tmp;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn triple_buffer_stats(&self) -> BufferStats {
        self.reader.stats()
    }
}

impl Drop for CircuitReaderV5b {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.io_jh.take() {
            let _ = jh.join();
        }
    }
}

// -----------------------------------------------------------------------------
// Level<'r> – borrows the parent reader & yields blocks
// -----------------------------------------------------------------------------
pub struct Level<'r> {
    reader: &'r mut CircuitReaderV5b,
    gates_remaining: u32,
    xor_remaining: u32,
}

impl<'r> Level<'r> {
    pub async fn next_block_soa(&mut self) -> Result<Option<DecodedBlockSoA<'_>>> {
        if self.gates_remaining == 0 {
            return Ok(None);
        }

        let gates_in_block = std::cmp::min(self.gates_remaining as usize, GATES_PER_BLOCK);
        self.reader.read_and_decode_block(gates_in_block).await?;

        let xor_here = std::cmp::min(self.xor_remaining as usize, gates_in_block);
        self.xor_remaining -= xor_here as u32;
        self.gates_remaining -= gates_in_block as u32;
        let idx = self.reader.block_index;
        self.reader.block_index += 1;

        Ok(Some(DecodedBlockSoA {
            in1: &self.reader.in1[..gates_in_block],
            in2: &self.reader.in2[..gates_in_block],
            out: &self.reader.out[..gates_in_block],
            xor_gates: xor_here,
            block_index: idx,
            gates_in_block,
        }))
    }

    pub async fn next_block(&mut self) -> Result<Option<Vec<GateV5b>>> {
        let soa = match self.next_block_soa().await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let mut v = Vec::with_capacity(soa.gates_in_block);
        for i in 0..soa.gates_in_block {
            v.push(GateV5b {
                in1: soa.in1[i],
                in2: soa.in2[i],
                out: soa.out[i],
            });
        }
        Ok(Some(v))
    }
}

// -----------------------------------------------------------------------------
// Scalar unpacker (24-bit fixed-width)
// -----------------------------------------------------------------------------
fn decode_block_scalar(
    block: &[u8; BLOCK_SIZE],
    gates: usize,
    out_in1: &mut [u32; GATES_PER_BLOCK],
    out_in2: &mut [u32; GATES_PER_BLOCK],
    out_out: &mut [u32; GATES_PER_BLOCK],
) {
    let in1 = &block[0..IN1_STREAM_SIZE];
    let in2 = &block[IN1_STREAM_SIZE..IN1_STREAM_SIZE + IN2_STREAM_SIZE];
    let out = &block[IN1_STREAM_SIZE + IN2_STREAM_SIZE..];

    for i in 0..gates {
        out_in1[i] = unpack_24(in1, i);
        out_in2[i] = unpack_24(in2, i);
        out_out[i] = unpack_24(out, i);
    }
}

#[inline]
fn unpack_24(stream: &[u8], idx: usize) -> u32 {
    let bit_off = idx * 24;
    let byte_off = bit_off / 8;
    let shift = bit_off % 8;

    let mut buf = [0u8; 4];
    let end = std::cmp::min(byte_off + 4, stream.len());
    buf[..end - byte_off].copy_from_slice(&stream[byte_off..end]);

    (u32::from_le_bytes(buf) >> shift) & 0xFF_FFFF
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
fn decode_outputs_le24(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.len() % 3 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "outputs length not multiple of 3",
        ));
    }
    let n = bytes.len() / 3;
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let base = i * 3;
        let val = u32::from_le_bytes([bytes[base], bytes[base + 1], bytes[base + 2], 0]);
        v.push(val);
    }
    Ok(v)
}

#[inline]
fn io_err<E: ToString>(e: E) -> Error {
    Error::new(ErrorKind::InvalidData, e.to_string())
}

#[inline]
fn div_round_up(n: usize, d: usize) -> usize {
    (n + d - 1) / d
}

/// Verifies the checksum of a v5b file.
///
/// Hash order (spec):
/// 1) outputs section
/// 2) gate blocks section (for v5b: all level headers + all packed blocks)
/// 3) header tail (bytes after the checksum field)
///
/// Returns:
/// - Ok(true) if checksum matches,
/// - Ok(false) if checksum mismatch or structural mismatch (e.g. level gate sum),
/// - Err(io::Error) on I/O failures or malformed file reads.
///
/// This implementation reuses a single buffer for block reads to minimize allocations.
pub async fn verify_v5b_checksum(path: impl AsRef<std::path::Path>) -> std::io::Result<bool> {
    use crate::v5::b::{HeaderV5b, LevelHeader};

    // Open
    let mut opts = monoio::fs::OpenOptions::new();
    opts.read(true);
    let file = opts.open(path.as_ref()).await?;

    // Read header
    let (res, header_vec) = file.read_exact_at(vec![0u8; HEADER_SIZE], 0).await;
    res?;
    let header_arr: [u8; HEADER_SIZE] = header_vec.as_slice().try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "header size mismatch")
    })?;
    let hdr = HeaderV5b::from_bytes(&header_arr);
    hdr.validate().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid header: {}", e),
        )
    })?;

    let file_checksum = &header_arr[8..40]; // 32 bytes starting after magic/version/type/reserved

    let outputs_len = (hdr.num_outputs as usize)
        .checked_mul(OUTPUT_ENTRY_SIZE)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "outputs length overflow")
        })?;

    let mut hasher = Hasher::new();

    // 1) Gate blocks section = all level headers + all blocks, in order
    // Walk levels, hash each 8-byte LevelHeader, then hash N full blocks.
    let mut off = (HEADER_SIZE + outputs_len) as u64;
    let mut total_level_gates: u64 = 0;

    // Reusable buffer for block reads (one block at a time to minimize allocations)
    let mut block_buf = vec![0u8; BLOCK_SIZE];

    for _ in 0..hdr.num_levels {
        // Read and hash level header
        let (res, lvl_bytes) = file.read_exact_at(vec![0u8; LEVEL_HEADER_SIZE], off).await;
        res?;
        hasher.update(&lvl_bytes);
        off += LEVEL_HEADER_SIZE as u64;

        let lvl_hdr = LevelHeader::from_bytes(&lvl_bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "level header size")
        })?);
        lvl_hdr.validate().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid level header: {}", e),
            )
        })?;

        let lvl_gates = lvl_hdr.num_gates() as usize;
        total_level_gates = total_level_gates.saturating_add(lvl_gates as u64);

        let lvl_blocks = div_round_up(lvl_gates, GATES_PER_BLOCK);
        let lvl_bytes = lvl_blocks.checked_mul(BLOCK_SIZE).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "level blocks bytes overflow",
            )
        })?;

        // Hash all blocks of this level, reusing block_buf
        let mut remaining = lvl_bytes;
        let mut lvl_off = off;
        while remaining > 0 {
            let take = remaining.min(BLOCK_SIZE);

            // Resize buffer if needed for partial blocks
            if take < BLOCK_SIZE {
                block_buf.resize(take, 0);
            }

            let (res, buf) = file
                .read_exact_at(std::mem::take(&mut block_buf), lvl_off)
                .await;
            res?;
            hasher.update(&buf);
            block_buf = buf; // Reuse the buffer for next iteration

            lvl_off += take as u64;
            remaining -= take;
        }

        off += lvl_bytes as u64;
    }

    // Validate level gate sum matches header total (structural sanity check)
    if total_level_gates != hdr.total_gates() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "level gate sum {} does not match header total {}",
                total_level_gates,
                hdr.total_gates()
            ),
        ));
    }

    // 2) Outputs section
    if outputs_len > 0 {
        let off = HEADER_SIZE as u64;
        let (res, outs) = file.read_exact_at(vec![0u8; outputs_len], off).await;
        res?;
        hasher.update(&outs);
    }

    // 3) Header tail (after checksum field)
    hasher.update(&header_arr[40..HEADER_SIZE]);

    let computed = hasher.finalize();
    Ok(computed.as_bytes() == file_checksum)
}

// -----------------------------------------------------------------------------
// I/O thread – identical to v5a except for region sizes
// -----------------------------------------------------------------------------
fn io_thread_run(
    path: PathBuf,
    aligned_start: u64,
    aligned_end: u64,
    tail_len: usize,
    writer: &mut TripleBufWriter,
    stop_rx: AsyncReceiver<()>,
    write_buf: AlignedBuffer,
) -> Result<()> {
    monoio::RuntimeBuilder::<FusionDriver>::new()
        .enable_timer()
        .build()
        .unwrap()
        .block_on(async move {
            let mut stop_rx = pin!(stop_rx);

            async fn publish_until_stop(
                writer: &mut TripleBufWriter,
                buf: AlignedBuffer,
                stop: &mut AsyncReceiver<()>,
            ) -> Option<AlignedBuffer> {
                select! {
                    _ = stop.recv() => None,
                    next = writer.publish(buf) => Some(next),
                }
            }

            // Try O_DIRECT
            let direct = {
                let mut opts = monoio::fs::OpenOptions::new();
                opts.read(true);
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.custom_flags(libc::O_DIRECT);
                }
                opts.open(&path).await.ok()
            };

            if let Some(file) = direct {
                let mut off = aligned_start;
                let mut buf = write_buf;
                while off < aligned_end {
                    let read_fut = file.read_at(buf, off);
                    let (res, b) = select! {
                        _ = stop_rx.recv() => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF in O_DIRECT"));
                    }
                    off += n as u64;
                    if let Some(next) = publish_until_stop(writer, buf, &mut stop_rx).await {
                        buf = next;
                    } else {
                        return Ok(());
                    }
                }
                if tail_len > 0 {
                    let mut opts = monoio::fs::OpenOptions::new();
                    opts.read(true);
                    let tail = opts.open(&path).await?;
                    let read_fut = tail.read_at(buf, aligned_end);
                    let (res, b) = select! {
                        _ = stop_rx.recv() => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF tail"));
                    }
                    let _ = publish_until_stop(writer, buf, &mut stop_rx).await;
                }
                Ok(())
            } else {
                // Buffered fallback
                let mut opts = monoio::fs::OpenOptions::new();
                opts.read(true);
                let file = opts.open(&path).await?;
                let mut off = aligned_start;
                let end = aligned_end + tail_len as u64;
                let mut buf = write_buf;
                while off < end {
                    let read_fut = file.read_at(buf, off);
                    let (res, b) = select! {
                        _ = stop_rx.recv() => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF fallback"));
                    }
                    off += n as u64;
                    if let Some(next) = publish_until_stop(writer, buf, &mut stop_rx).await {
                        buf = next;
                    } else {
                        return Ok(());
                    }
                }
                Ok(())
            }
        })
}

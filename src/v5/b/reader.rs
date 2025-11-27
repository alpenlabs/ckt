// CKT v5b – production format (32-bit addresses, AoS layout, levelled)
//
// Design:
// 1. Parse & validate header + outputs
// 2. Spawn an I/O thread with triple-buffered O_DIRECT reads
// 3. Expose level iteration with zero-copy access
//      • CircuitReaderV5b::next_level()  ->  Option<Level<'_>>
//      • Level<'_> provides xor_gates: &[GateV5b], and_gates: &[GateV5b]
// 4. Zero-copy via direct pointer cast from bytes to &[GateV5b]

#![allow(clippy::let_unit_value)] // for select! branches

use std::{
    io::{Error, ErrorKind, Read, Result},
    path::{Path, PathBuf},
    pin::pin,
    thread,
};

use crate::v5::b::{
    GATE_SIZE, HEADER_SIZE, HeaderV5b, LEVEL_HEADER_SIZE, LevelHeader, OUTPUT_ENTRY_SIZE,
};
use blake3::Hasher;
use cynosure::site_d::triplebuffer::{
    AlignedBuffer, BUFFER_ALIGN, BufferStats, TripleBufReader, TripleBufWriter, triple_buffer,
};
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use monoio::{FusionDriver, select};

// Re-export GateV5b for public API
pub use crate::v5::b::GateV5b;

// -----------------------------------------------------------------------------
// Public decoded view - zero-copy level data
// -----------------------------------------------------------------------------

/// A level with owned XOR and AND gate data
///
/// The byte vectors are directly reinterpreted as `Vec<GateV5b>` for zero-parse access.
pub struct Level {
    pub xor_gates: Vec<GateV5b>,
    pub and_gates: Vec<GateV5b>,
    pub level_index: u32,
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
    bytes_remaining: u64, // gate-area bytes (levels) left

    // Per-file accounting
    levels_remaining: u32,
    level_index: u32, // current level index for metrics

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
        let outputs = decode_outputs_le32(&outputs_raw)?;

        // ---- Gate region bookkeeping ----------------------------------------
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
            level_index: 0,

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
    // Level iteration with owned gate data
    // -------------------------------------------------------------------------
    pub async fn next_level(&mut self) -> Result<Option<Level>> {
        loop {
            if self.levels_remaining == 0 {
                return Ok(None);
            }

            // Read 8-byte LevelHeader
            let mut hdr_buf = [0u8; LEVEL_HEADER_SIZE];
            self.read_exact_into(&mut hdr_buf).await?;
            let lvl = LevelHeader::from_bytes(&hdr_buf);
            lvl.validate().map_err(io_err)?;

            self.levels_remaining -= 1;
            let current_level_index = self.level_index;
            self.level_index += 1;

            // Skip empty levels
            if lvl.num_gates() == 0 {
                continue;
            }

            let num_xor = lvl.num_xor_gates as usize;
            let num_and = lvl.num_and_gates as usize;
            let total_gates = num_xor + num_and;

            // Read all gate bytes for this level
            let level_bytes_len = total_gates
                .checked_mul(GATE_SIZE)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "level bytes overflow"))?;

            // Use temporary vector to avoid borrow issues
            let mut level_bytes = vec![0u8; level_bytes_len];
            self.read_exact_into(&mut level_bytes).await?;

            // Split bytes into XOR and AND portions
            let xor_bytes_len = num_xor * GATE_SIZE;

            // Reinterpret byte slices as Vec<GateV5b> (zero-parse with proper alignment)
            let xor_gates = bytes_to_gates(&level_bytes[..xor_bytes_len], num_xor)?;
            let and_gates = bytes_to_gates(&level_bytes[xor_bytes_len..], num_and)?;

            return Ok(Some(Level {
                xor_gates,
                and_gates,
                level_index: current_level_index,
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
// Helpers
// -----------------------------------------------------------------------------

/// Convert a byte slice to Vec<GateV5b> with proper alignment
///
/// This function copies bytes into a properly aligned Vec<GateV5b>.
/// GateV5b is repr(C) with 3 u32s in LE format, so we can safely
/// reinterpret the bytes after ensuring proper alignment.
fn bytes_to_gates(bytes: &[u8], num_gates: usize) -> Result<Vec<GateV5b>> {
    // Verify length
    if bytes.len() != num_gates * GATE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "byte length doesn't match gate count",
        ));
    }

    // Allocate Vec<GateV5b> directly (guarantees proper alignment)
    let mut gates: Vec<GateV5b> = Vec::with_capacity(num_gates);

    // Safety: We're copying bytes into properly aligned GateV5b structs.
    // GateV5b is repr(C) with 3 u32s = 12 bytes in LE format.
    // The source bytes are in LE format from the file.
    unsafe {
        // Copy bytes directly into the gate vector's allocation
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), gates.as_mut_ptr() as *mut u8, bytes.len());
        gates.set_len(num_gates);
    }

    Ok(gates)
}

/// Decode outputs from 4-byte little-endian u32 entries
fn decode_outputs_le32(bytes: &[u8]) -> Result<Vec<u32>> {
    if bytes.len() % 4 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "outputs length not multiple of 4",
        ));
    }
    let n = bytes.len() / 4;
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let base = i * 4;
        let val = u32::from_le_bytes([
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
        ]);
        v.push(val);
    }
    Ok(v)
}

#[inline]
fn io_err<E: ToString>(e: E) -> Error {
    Error::new(ErrorKind::InvalidData, e.to_string())
}

/// Verifies the checksum of a v5b file.
///
/// Hash order (spec):
/// 1) gate blocks section (all level headers + all gate bytes)
/// 2) outputs section
/// 3) header tail (bytes after the checksum field)
///
/// Returns:
/// - Ok(true) if checksum matches,
/// - Ok(false) if checksum mismatch or structural mismatch,
/// - Err(io::Error) on I/O failures or malformed file reads.
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

    // 1) Gate blocks section = all level headers + all gate bytes, in order
    let mut off = (HEADER_SIZE + outputs_len) as u64;
    let mut total_level_gates: u64 = 0;

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

        let lvl_bytes_len = lvl_gates.checked_mul(GATE_SIZE).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "level bytes overflow")
        })?;

        // Read and hash all gate bytes for this level
        if lvl_bytes_len > 0 {
            let (res, gate_bytes) = file.read_exact_at(vec![0u8; lvl_bytes_len], off).await;
            res?;
            hasher.update(&gate_bytes);
            off += lvl_bytes_len as u64;
        }
    }

    // Validate level gate sum matches header total (structural sanity check)
    if total_level_gates != hdr.total_gates() {
        return Ok(false);
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
// I/O thread – triple-buffered O_DIRECT reads
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

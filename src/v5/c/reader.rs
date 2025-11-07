//! v5c Reader - Triple-buffered io_uring with Arc-sharing support
//!
//! Provides zero-copy block distribution for parallel garbling workloads.
//! Uses proven v5b triple-buffer architecture for 6.5+ GB/s throughput.

use std::io::{Error, ErrorKind, Read, Result};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::thread;

use blake3::Hasher;
use cynosure::site_d::triplebuffer::{
    AlignedBuffer, BUFFER_ALIGN, TripleBufReader, TripleBufWriter, triple_buffer,
};
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use monoio::{FusionDriver, select};

use crate::v5::c::{
    ALIGNMENT, BLOCK_SIZE, Block, GATE_SIZE, GATES_PER_BLOCK, GATES_SIZE, HEADER_SIZE, HeaderV5c,
    TYPES_OFFSET, TYPES_SIZE, padded_size,
};

/// Reader for v5c format files with triple-buffered io_uring
pub struct ReaderV5c {
    header: HeaderV5c,
    outputs: Vec<u32>,

    // Triple-buffered io_uring reader
    reader: TripleBufReader,
    stop_tx: Option<AsyncSender<()>>,
    io_jh: Option<thread::JoinHandle<()>>,

    // Current state
    cur_buf: Option<AlignedBuffer>,
    bytes_remaining: u64, // Always multiple of BLOCK_SIZE
}

impl ReaderV5c {
    /// Open a v5c file with triple-buffered io_uring
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut f = std::fs::OpenOptions::new().read(true).open(path.as_ref())?;

        // Read and parse header (88 bytes)
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        f.read_exact(&mut hdr_bytes)?;
        let header = HeaderV5c::from_bytes(&hdr_bytes)?;
        header
            .validate()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        // Calculate outputs section offset (header padded to 256 KiB)
        let outputs_offset = ALIGNMENT;
        let outputs_bytes_len = (header.num_outputs as usize)
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "outputs length overflow"))?;

        // Read outputs
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(outputs_offset as u64))?;
        let mut outputs_raw = vec![0u8; outputs_bytes_len];
        if outputs_bytes_len > 0 {
            f.read_exact(&mut outputs_raw)?;
        }
        let outputs = decode_outputs_le32(&outputs_raw)?;

        // Validate outputs against scratch space
        let scratch_space = header.scratch_space;
        for (i, &addr) in outputs.iter().enumerate() {
            if addr as u64 >= scratch_space {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Output {} address {} exceeds scratch_space {}",
                        i, addr, scratch_space
                    ),
                ));
            }
        }

        // Calculate gate region
        let file_metadata = f.metadata()?;
        let file_size = file_metadata.len();

        let outputs_padded_size = padded_size(outputs_bytes_len);
        let gate_region_start = ALIGNMENT as u64 + outputs_padded_size as u64;
        let gate_region_end = file_size;
        let gate_region_bytes = gate_region_end - gate_region_start;

        // Validate that gate region is multiple of BLOCK_SIZE
        if gate_region_bytes % BLOCK_SIZE as u64 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "gate region size is not a multiple of 256 KiB",
            ));
        }

        // O_DIRECT alignment
        let aligned_mask = (BUFFER_ALIGN as u64) - 1;
        let aligned_start = gate_region_start & !aligned_mask;
        let aligned_end = gate_region_end & !aligned_mask;
        let tail_len = (gate_region_end - aligned_end) as usize;

        // Spawn I/O thread with triple buffer
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
                eprintln!("v5c I/O thread error: {e}");
            }
        });

        Ok(Self {
            header,
            outputs,
            reader,
            stop_tx: Some(stop_tx),
            io_jh: Some(jh),
            cur_buf: None,
            bytes_remaining: gate_region_bytes,
        })
    }

    /// Get the next 4 MiB buffer as Box<[Block; 16]> for distribution to workers
    ///
    /// # Safety
    /// Casts copied buffer to Box<[Block; 16]>. Buffer must contain valid Block data.
    ///
    /// Returns:
    /// - Box<[Block; 16]>: Heap-allocated array of 16 blocks
    /// - end_block: Index one past last valid block (exclusive, always starts from 0)
    ///
    /// Caller can convert to Arc for sharing: `Arc::from(box)`
    pub async unsafe fn next_blocks(&mut self) -> Result<Option<(Box<[Block; 16]>, usize)>> {
        if self.bytes_remaining == 0 {
            return Ok(None);
        }

        // Get next buffer from triple-buffer reader
        let prev_buf = self.cur_buf.take();
        let aligned_buf = self.reader.next(prev_buf).await;

        // Calculate end_block based on bytes_remaining
        // We always allocate 16 blocks (4 MiB), so blocks_in_buffer is always 16
        let blocks_in_buffer = 16;
        let buffer_size = aligned_buf.len() as u64;
        let valid_bytes = self.bytes_remaining.min(buffer_size);
        let valid_blocks = (valid_bytes / BLOCK_SIZE as u64) as usize;

        let end_block = valid_blocks.min(blocks_in_buffer);

        // Always allocate exactly 4 MiB (16 × 256 KiB blocks) and copy what we have
        let mut heap_buf = vec![0u8; BLOCK_SIZE * 16].into_boxed_slice();
        let copy_len = aligned_buf.len().min(heap_buf.len());
        heap_buf[..copy_len].copy_from_slice(&aligned_buf[..copy_len]);

        // Return AlignedBuffer back to triple buffer
        self.cur_buf = Some(aligned_buf);

        // Update bytes_remaining
        let bytes_consumed = (end_block as u64)
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "bytes consumed overflow"))?;
        self.bytes_remaining = self
            .bytes_remaining
            .checked_sub(bytes_consumed)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "bytes_consumed exceeds bytes_remaining",
                )
            })?;

        // Cast Box<[u8]> to Box<[Block; 16]>
        // Verify size and alignment invariants
        if heap_buf.len() != BLOCK_SIZE * 16 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Buffer size mismatch: expected {}, got {}",
                    BLOCK_SIZE * 16,
                    heap_buf.len()
                ),
            ));
        }
        if heap_buf.as_ptr() as usize % std::mem::align_of::<Block>() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Buffer is not aligned to Block alignment",
            ));
        }

        let blocks: Box<[Block; 16]> = unsafe {
            // SAFETY:
            // - Size is exactly BLOCK_SIZE * 16 bytes (checked above)
            // - Alignment matches Block requirements (checked above)
            // - Block is repr(C) with well-defined layout
            // - Buffer contains valid block data from triple buffer
            let raw = Box::into_raw(heap_buf);
            let ptr = raw as *mut [Block; 16];
            Box::from_raw(ptr)
        };

        Ok(Some((blocks, end_block)))
    }

    /// Get the header
    pub fn header(&self) -> &HeaderV5c {
        &self.header
    }

    /// Get outputs as a slice
    pub fn outputs(&self) -> &[u32] {
        &self.outputs
    }
}

impl Drop for ReaderV5c {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.as_sync().send(());
        }
        if let Some(jh) = self.io_jh.take() {
            let _ = jh.join();
        }
    }
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

/// Verify the checksum of a v5c file
///
/// Hash order (spec): gate_blocks || outputs || header (skip checksum field only)
pub async fn verify_v5c_checksum(path: impl AsRef<Path>) -> Result<bool> {
    // Open file
    let mut opts = monoio::fs::OpenOptions::new();
    opts.read(true);
    let file = opts.open(path.as_ref()).await?;

    // Read header
    let (res, header_vec) = file.read_exact_at(vec![0u8; HEADER_SIZE], 0).await;
    res?;
    let header_arr: [u8; HEADER_SIZE] = header_vec
        .as_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "header size mismatch"))?;
    let hdr = HeaderV5c::from_bytes(&header_arr)?;
    hdr.validate()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    let file_checksum = &header_arr[10..42];

    let outputs_len = (hdr.num_outputs as usize)
        .checked_mul(4)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "outputs length overflow"))?;

    let mut hasher = Hasher::new();

    // 1. Hash all gate blocks (full 256 KiB blocks including all padding)
    let total_gates = hdr.total_gates();
    let num_full_blocks = total_gates / GATES_PER_BLOCK as u64;
    let partial_gates = (total_gates % GATES_PER_BLOCK as u64) as usize;

    let outputs_padded = padded_size(outputs_len);
    let mut block_offset = (ALIGNMENT + outputs_padded) as u64;

    // Hash full blocks
    for _ in 0..num_full_blocks {
        let (res, block_bytes) = file
            .read_exact_at(vec![0u8; BLOCK_SIZE], block_offset)
            .await;
        res?;

        // Hash full 256 KiB block (including padding)
        hasher.update(&block_bytes);

        block_offset += BLOCK_SIZE as u64;
    }

    // Hash partial block if present (full 256 KiB including padding)
    if partial_gates > 0 {
        let (res, block_bytes) = file
            .read_exact_at(vec![0u8; BLOCK_SIZE], block_offset)
            .await;
        res?;

        // Hash full block including padding
        hasher.update(&block_bytes);
    }

    // 2. Hash outputs section (WITH padding to 256 KiB boundary)
    let outputs_padded_size = padded_size(outputs_len);
    if outputs_padded_size > 0 {
        let (res, outputs_padded) = file
            .read_exact_at(vec![0u8; outputs_padded_size], ALIGNMENT as u64)
            .await;
        res?;
        hasher.update(&outputs_padded);
    }

    // 3. Hash header: before checksum (0-10) + after checksum (42-88) + padding to 256 KiB
    hasher.update(&header_arr[0..10]); // magic, version, format_type, nkas
    // Skip checksum field (bytes 10-42)
    hasher.update(&header_arr[42..HEADER_SIZE]); // all metadata fields
    // Hash header padding (88 bytes to 256 KiB)
    let header_padding = vec![0u8; ALIGNMENT - HEADER_SIZE];
    hasher.update(&header_padding);

    let computed = hasher.finalize();
    Ok(computed.as_bytes() == file_checksum)
}

/// I/O thread for triple-buffered reading (reused from v5b pattern)
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

#[cfg(test)]
mod tests {
    // TODO: Add integration tests with writer once both are complete
}

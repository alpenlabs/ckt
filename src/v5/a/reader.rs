use std::io::{Error, ErrorKind, Read, Result};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::thread;

use blake3::Hasher;
use kanal::{AsyncReceiver, AsyncSender, bounded_async};
use monoio::{FusionDriver, select};

use crate::GateType;
use crate::v5::a::{
    BLOCK_SIZE_BYTES, GATES_PER_BLOCK, GateV5a, HEADER_SIZE_V5A, HeaderV5a, parse_header,
};
use crate::v5::decode_block_v5a;
use cynosure::site_d::triplebuffer::{
    AlignedBuffer, BUFFER_ALIGN, BufferStats, TripleBufReader, TripleBufWriter, triple_buffer,
};

// Outputs are 5-byte little-endian entries that must fit in 34 bits.
// We store them as u64 for convenience.
fn decode_outputs_le40(bytes: &[u8]) -> Result<Vec<u64>> {
    if !bytes.len().is_multiple_of(5) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "outputs length not multiple of 5",
        ));
    }
    let n = bytes.len() / 5;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let base = 5 * i;
        let mut buf = [0u8; 8];
        buf[0..5].copy_from_slice(&bytes[base..base + 5]);
        let v = u64::from_le_bytes(buf);
        if (v >> 34) != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "output wire id has nonzero upper bits",
            ));
        }
        out.push(v);
    }
    Ok(out)
}

// ================= Public decoded view (closure-only borrow) =================

pub struct DecodedBlockSoA<'a> {
    pub in1: &'a [u64],
    pub in2: &'a [u64],
    pub out: &'a [u64],
    pub credits: &'a [u32],
    pub gate_types: &'a [GateType], // XOR/AND
    pub block_index: u64,
    pub gates_in_block: usize,
}

// ================= Reader =================

pub struct CircuitReaderV5a {
    header: HeaderV5a,
    outputs: Vec<u64>,

    // Stream accounting
    gates_remaining: u64,

    // Triple buffer + IO thread
    reader: TripleBufReader,
    stop_tx: Option<AsyncSender<()>>,
    io_jh: Option<thread::JoinHandle<()>>,

    // Current buffer window
    cur_buf: Option<AlignedBuffer>,
    cur_pos: usize,       // current cursor within buffer
    bytes_remaining: u64, // remaining bytes from the gate region to consume

    // O_DIRECT alignment handling
    prefix_skip: usize, // number of bytes to skip at beginning of first chunk (may span multiple)
    first_chunk: bool,  // true until we've handled initial skipping completely

    // Staging and decode scratch
    block_staging: [u8; BLOCK_SIZE_BYTES],
    in1: [u64; GATES_PER_BLOCK],
    in2: [u64; GATES_PER_BLOCK],
    out: [u64; GATES_PER_BLOCK],
    credits: [u32; GATES_PER_BLOCK],
    gate_types_tmp: [bool; GATES_PER_BLOCK],
    gate_types: [GateType; GATES_PER_BLOCK],
    block_index: u64,
}

impl CircuitReaderV5a {
    // Open v5a reader. No checksum verification here.
    // Synchronous open (fast, small I/O), async decoding/streaming.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        let mut f = std::fs::OpenOptions::new().read(true).open(path_ref)?;

        // Header
        let mut hdr_bytes = [0u8; HEADER_SIZE_V5A];
        f.read_exact(&mut hdr_bytes)?;
        let header = parse_header(&hdr_bytes)?;

        // Outputs region
        let outputs_bytes_len = (header.num_outputs as usize)
            .checked_mul(5)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "outputs length overflow"))?;
        let mut outputs_bytes = vec![0u8; outputs_bytes_len];
        if outputs_bytes_len > 0 {
            f.read_exact(&mut outputs_bytes)?;
        }
        let outputs = decode_outputs_le40(&outputs_bytes)?;

        // Stream boundaries for gate region (blocks area)
        let total_gates = header.total_gates();
        let blocks_total = total_gates.div_ceil(GATES_PER_BLOCK as u64);
        let gate_region_bytes = (blocks_total as usize)
            .checked_mul(BLOCK_SIZE_BYTES)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "gate region bytes overflow"))?
            as u64;

        // Triple buffer and IO thread
        let (mut writer, reader, writer_buf) = triple_buffer();

        // Gate region file offsets
        let start_off = HEADER_SIZE_V5A as u64 + outputs_bytes_len as u64;
        let end_off = start_off + gate_region_bytes;

        // Aligned O_DIRECT region [aligned_start, aligned_end)
        let aligned_mask = (BUFFER_ALIGN as u64) - 1;
        let aligned_start = start_off & !aligned_mask;
        let aligned_end = end_off & !aligned_mask;
        let prefix_skip = (start_off - aligned_start) as usize;
        let tail_len = (end_off - aligned_end) as usize;

        // Async stop channel for IO thread
        let (stop_tx, stop_rx) = bounded_async(1);
        let io_path = path_ref.to_path_buf();

        let jh = thread::spawn(move || {
            if let Err(e) = io_thread_run(
                io_path,
                aligned_start,
                aligned_end,
                tail_len,
                &mut writer,
                stop_rx,
                writer_buf,
            ) {
                eprintln!("v5a IO thread error: {e}");
            }
        });

        Ok(Self {
            header,
            outputs,
            gates_remaining: total_gates,
            reader,
            stop_tx: Some(stop_tx),
            io_jh: Some(jh),
            cur_buf: None,
            cur_pos: 0,
            bytes_remaining: gate_region_bytes,
            prefix_skip,
            first_chunk: prefix_skip > 0,
            block_staging: [0u8; BLOCK_SIZE_BYTES],
            in1: [0u64; GATES_PER_BLOCK],
            in2: [0u64; GATES_PER_BLOCK],
            out: [0u64; GATES_PER_BLOCK],
            credits: [0u32; GATES_PER_BLOCK],
            gate_types_tmp: [false; GATES_PER_BLOCK],
            gate_types: [GateType::XOR; GATES_PER_BLOCK],
            block_index: 0,
        })
    }

    pub fn header(&self) -> HeaderV5a {
        self.header
    }

    pub fn outputs(&self) -> &[u64] {
        &self.outputs
    }

    // Async, allocation-free SoA decode.
    // Returns Ok(None) on end-of-stream.
    pub async fn next_block_soa(&mut self) -> Result<Option<DecodedBlockSoA<'_>>> {
        if self.gates_remaining == 0 {
            return Ok(None);
        }

        self.fill_next_block_bytes().await?;

        // Determine valid gates in this block (last may be partial)
        let gates_in_block = if self.gates_remaining >= GATES_PER_BLOCK as u64 {
            GATES_PER_BLOCK
        } else {
            self.gates_remaining as usize
        };

        // Decode - automatically dispatches to AVX-512 or scalar
        decode_block_v5a(
            &self.block_staging,
            gates_in_block,
            &mut self.in1,
            &mut self.in2,
            &mut self.out,
            &mut self.credits,
            &mut self.gate_types_tmp,
        );

        // Map bool -> GateType (false=XOR, true=AND)
        for i in 0..gates_in_block {
            self.gate_types[i] = if self.gate_types_tmp[i] {
                GateType::AND
            } else {
                GateType::XOR
            };
        }

        let idx = self.block_index;
        self.block_index += 1;
        self.gates_remaining -= gates_in_block as u64;

        Ok(Some(DecodedBlockSoA {
            in1: &self.in1[..gates_in_block],
            in2: &self.in2[..gates_in_block],
            out: &self.out[..gates_in_block],
            credits: &self.credits[..gates_in_block],
            gate_types: &self.gate_types[..gates_in_block],
            block_index: idx,
            gates_in_block,
        }))
    }

    // Async convenience: returns owned AoS Vec. Less efficient than next_block_soa.
    pub async fn next_block(&mut self) -> Result<Option<Vec<GateV5a>>> {
        let block = match self.next_block_soa().await {
            Ok(Some(block)) => block,
            Err(e) => return Err(e),
            Ok(None) => return Ok(None),
        };
        let n = block.gates_in_block;
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(GateV5a {
                in1: block.in1[i],
                in2: block.in2[i],
                out: block.out[i],
                credits: block.credits[i],
                gate_type: block.gate_types[i],
            });
        }
        Ok(Some(v))
    }

    // ======== internal: fill the staging buffer with the next packed block ========
    async fn fill_next_block_bytes(&mut self) -> Result<()> {
        if self.bytes_remaining < BLOCK_SIZE_BYTES as u64 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "truncated gate region (incomplete block)",
            ));
        }

        let mut filled = 0usize;
        while filled < BLOCK_SIZE_BYTES {
            // Acquire/refresh current buffer if empty or exhausted
            if self.cur_buf.is_none() || self.cur_pos >= self.cur_buf.as_ref().unwrap().len() {
                let prev = self.cur_buf.take();
                let next = self.reader.next(prev).await;
                self.cur_buf = Some(next);
                self.cur_pos = 0;

                // Handle initial unaligned prefix skipping (may span multiple chunks)
                while self.first_chunk && self.prefix_skip > 0 {
                    let b = self.cur_buf.as_ref().unwrap();
                    if b.len() <= self.prefix_skip {
                        // Entire chunk is prefix; consume it and fetch next
                        self.prefix_skip -= b.len();
                        let prev = self.cur_buf.take();
                        let next = self.reader.next(prev).await;
                        self.cur_buf = Some(next);
                        self.cur_pos = 0;
                        continue;
                    } else {
                        self.cur_pos = self.prefix_skip;
                        self.prefix_skip = 0;
                        self.first_chunk = false;
                        break;
                    }
                }
            }

            let b = self.cur_buf.as_ref().unwrap();
            let avail = b.len().saturating_sub(self.cur_pos);
            if avail == 0 {
                // No data in current chunk; fetch another
                let prev = self.cur_buf.take();
                let next = self.reader.next(prev).await;
                self.cur_buf = Some(next);
                self.cur_pos = 0;
                continue;
            }

            let want = (BLOCK_SIZE_BYTES - filled).min(avail);
            self.block_staging[filled..filled + want]
                .copy_from_slice(&b[self.cur_pos..self.cur_pos + want]);
            self.cur_pos += want;
            filled += want;
            self.bytes_remaining -= want as u64;
        }

        Ok(())
    }

    // Debug visibility if desired
    pub fn triple_buffer_stats(&self) -> BufferStats {
        self.reader.stats()
    }
}

impl Drop for CircuitReaderV5a {
    fn drop(&mut self) {
        // Signal IO thread to stop and join
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.to_sync().send(());
        }
        if let Some(jh) = self.io_jh.take() {
            let _ = jh.join();
        }
    }
}

// ================= IO thread with monoio and O_DIRECT + async stop =================

fn io_thread_run(
    path: PathBuf,
    aligned_start: u64,
    aligned_end: u64,
    tail_len: usize, // < 4096 or 0
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

            // helper: await a publish but abort if stop fires
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

            // Attempt O_DIRECT open
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
                // 1) O_DIRECT aligned region
                let mut off = aligned_start;
                let mut buf = write_buf;

                while off < aligned_end {
                    // race read with stop
                    let read_fut = file.read_at(buf, off);
                    let stop_fut = stop_rx.recv();
                    let (res, b) = select! {
                        _ = stop_fut => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "EOF during O_DIRECT region",
                        ));
                    }
                    off += n as u64;

                    // publish (race with stop)
                    if let Some(next) = publish_until_stop(writer, buf, &mut stop_rx).await {
                        buf = next;
                    } else {
                        return Ok(());
                    }
                }

                // 2) Buffered tail if present (avoid O_DIRECT alignment issues)
                if tail_len > 0 {
                    let mut opts = monoio::fs::OpenOptions::new();
                    opts.read(true);
                    let file_tail = opts.open(&path).await?;

                    let read_fut = file_tail.read_at(buf, aligned_end);
                    let stop_fut = stop_rx.recv();
                    let (res, b) = select! {
                        _ = stop_fut => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EOF on buffered tail"));
                    }
                    // Publish tail; reader will only consume required bytes
                    let _ = publish_until_stop(writer, buf, &mut stop_rx).await;
                }

                Ok(())
            } else {
                // Full fallback: buffered reads for everything
                let mut opts = monoio::fs::OpenOptions::new();
                opts.read(true);
                let file = opts.open(&path).await?;

                let mut off = aligned_start;
                let end = aligned_end + tail_len as u64;
                let mut buf = write_buf;

                while off < end {
                    let read_fut = file.read_at(buf, off);
                    let stop_fut = stop_rx.recv();
                    let (res, b) = select! {
                        _ = stop_fut => return Ok(()),
                        out = read_fut => out,
                    };
                    buf = b;
                    let n = res?;
                    if n == 0 {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "EOF in fallback stream",
                        ));
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

/// Verifies the checksum of a v5a file
pub async fn verify_v5a_checksum(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();

    let mut opts = monoio::fs::OpenOptions::new();
    opts.read(true);
    let file = opts.open(path).await?;

    // Header
    let (res, header_vec) = file.read_exact_at(vec![0u8; HEADER_SIZE_V5A], 0).await;
    res?;
    let header: [u8; HEADER_SIZE_V5A] = header_vec
        .as_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "header size mismatch"))?;
    let hdr = parse_header(&header)?;
    let file_checksum = &header[8..40];
    let outputs_len = (hdr.num_outputs as usize) * 5;

    let mut hasher = Hasher::new();

    // Checksum order: blocks || outputs || header tail

    // 1. Blocks region
    let total_gates = hdr.total_gates();
    let blocks_total = total_gates.div_ceil(GATES_PER_BLOCK as u64);
    let blocks_bytes = (blocks_total as usize)
        .checked_mul(BLOCK_SIZE_BYTES)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "blocks bytes overflow"))?;

    if blocks_bytes > 0 {
        let start = (HEADER_SIZE_V5A + outputs_len) as u64;
        let chunk = 1 << 20;
        let mut off = 0usize;
        while off < blocks_bytes {
            let take = (blocks_bytes - off).min(chunk);
            let (res, buf) = file
                .read_exact_at(vec![0u8; take], start + off as u64)
                .await;
            res?;
            hasher.update(&buf);
            off += take;
        }
    }

    // 2. Outputs
    if outputs_len > 0 {
        let (res, outs) = file
            .read_exact_at(vec![0u8; outputs_len], HEADER_SIZE_V5A as u64)
            .await;
        res?;
        hasher.update(&outs);
    }

    // 3. Header tail
    hasher.update(&header[40..72]);

    Ok(hasher.finalize().as_bytes() == file_checksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v5::a::writer::CircuitWriterV5a;
    use crate::v5::a::{GateV5a, MAX_CREDITS, MAX_WIRE_ID};
    use std::fs::OpenOptions as StdOpen;
    use std::io::{Seek as _, SeekFrom, Write};
    use tempfile::tempdir;

    fn mk_gate(i: u64) -> GateV5a {
        GateV5a {
            in1: (10 + i) & MAX_WIRE_ID,
            in2: (20 + i) & MAX_WIRE_ID,
            out: (30 + i) & MAX_WIRE_ID,
            credits: ((i as u32) * 3) & MAX_CREDITS,
            gate_type: if i.is_multiple_of(2) {
                GateType::XOR
            } else {
                GateType::AND
            },
        }
    }

    async fn write_file(path: &Path, primary_inputs: u64, outputs: Vec<u64>, gates: &[GateV5a]) {
        let mut w = CircuitWriterV5a::new(path, primary_inputs, outputs)
            .await
            .unwrap();
        w.write_gates(gates).await.unwrap();
        w.finalize().await.unwrap();
    }

    #[monoio::test]
    async fn reader_open_header_outputs_and_no_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.v5a");

        let primary_inputs = 12;
        let outputs = vec![2, 3, 4, 5];
        write_file(&path, primary_inputs, outputs.clone(), &[]).await;

        let mut r = CircuitReaderV5a::open(&path).unwrap();
        let h = r.header();

        assert_eq!(h.version, 0x05);
        assert_eq!(h.format_type, 0x00);
        assert_eq!(h.primary_inputs, primary_inputs);
        assert_eq!(h.num_outputs, outputs.len() as u64);
        assert_eq!(r.outputs(), &outputs[..]);

        // No blocks
        let blk = r.next_block_soa().await.unwrap();
        assert!(blk.is_none());
        assert!(verify_v5a_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn reader_next_block_partial_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("partial.v5a");

        let gates: Vec<_> = (0..3u64).map(mk_gate).collect();
        write_file(&path, 7, vec![6, 7], &gates).await;

        let mut r = CircuitReaderV5a::open(&path).unwrap();

        // First block (partial)
        let blk = r.next_block_soa().await.unwrap().expect("some block");
        assert_eq!(blk.gates_in_block, 3);
        for i in 0..3usize {
            assert_eq!(blk.in1[i], (10 + i as u64) & MAX_WIRE_ID);
            assert_eq!(blk.in2[i], (20 + i as u64) & MAX_WIRE_ID);
            assert_eq!(blk.out[i], (30 + i as u64) & MAX_WIRE_ID);
            assert_eq!(blk.credits[i], ((i as u32) * 3) & MAX_CREDITS);
            let want = if (i as u64).is_multiple_of(2) {
                GateType::XOR
            } else {
                GateType::AND
            };
            assert_eq!(blk.gate_types[i], want);
        }

        // End
        assert!(r.next_block_soa().await.unwrap().is_none());
        assert!(verify_v5a_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn reader_next_block_two_blocks_with_partial() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("two_blocks.v5a");

        // 256 + 10 = 266 gates
        let gates: Vec<_> = (0..(GATES_PER_BLOCK as u64 + 10)).map(mk_gate).collect();
        write_file(&path, 0, vec![1], &gates).await;

        let mut r = CircuitReaderV5a::open(&path).unwrap();

        // First block full
        let b0 = r.next_block_soa().await.unwrap().expect("block 0");
        assert_eq!(b0.gates_in_block, GATES_PER_BLOCK);
        for i in 0..GATES_PER_BLOCK {
            let want = if (i as u64).is_multiple_of(2) {
                GateType::XOR
            } else {
                GateType::AND
            };
            assert_eq!(b0.gate_types[i], want);
        }

        // Second block partial (10)
        let b1 = r.next_block_soa().await.unwrap().expect("block 1");
        assert_eq!(b1.gates_in_block, 10);
        for i in 0..10usize {
            let idx = GATES_PER_BLOCK + i;
            assert_eq!(b1.in1[i], (10 + idx as u64) & MAX_WIRE_ID);
            assert_eq!(b1.in2[i], (20 + idx as u64) & MAX_WIRE_ID);
            assert_eq!(b1.out[i], (30 + idx as u64) & MAX_WIRE_ID);
            assert_eq!(b1.credits[i], ((idx as u32) * 3) & MAX_CREDITS);
            let want = if (idx as u64).is_multiple_of(2) {
                GateType::XOR
            } else {
                GateType::AND
            };
            assert_eq!(b1.gate_types[i], want);
        }

        // End
        assert!(r.next_block_soa().await.unwrap().is_none());
        assert!(verify_v5a_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn reader_next_block_aos_matches_soa() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("aos_soa.v5a");

        let gates: Vec<_> = (0..20u64).map(mk_gate).collect();
        write_file(&path, 1, vec![3, 9], &gates).await;

        // Use two independent readers so we compare the SAME block without borrow conflicts.
        let mut r_soa = CircuitReaderV5a::open(&path).unwrap();
        let mut r_aos = CircuitReaderV5a::open(&path).unwrap();

        // Fetch first block via SoA and convert it to AoS locally for comparison.
        let soa = r_soa.next_block_soa().await.unwrap().unwrap();
        let mut from_soa = Vec::with_capacity(soa.gates_in_block);
        for i in 0..soa.gates_in_block {
            from_soa.push(GateV5a {
                in1: soa.in1[i],
                in2: soa.in2[i],
                out: soa.out[i],
                credits: soa.credits[i],
                gate_type: soa.gate_types[i],
            });
        }

        // Fetch first block via AoS API.
        let aos = r_aos.next_block().await.unwrap().unwrap();

        assert_eq!(from_soa.len(), aos.len());
        for i in 0..aos.len() {
            assert_eq!(aos[i].in1, from_soa[i].in1);
            assert_eq!(aos[i].in2, from_soa[i].in2);
            assert_eq!(aos[i].out, from_soa[i].out);
            assert_eq!(aos[i].credits, from_soa[i].credits);
            assert_eq!(aos[i].gate_type, from_soa[i].gate_type);
        }

        // Ensure both readers reach EOF consistently for this small test.
        assert!(r_soa.next_block_soa().await.unwrap().is_none());
        assert!(r_aos.next_block().await.unwrap().is_none());
    }

    // Ensure prefix_skip alignment path works (misaligned start_off due to outputs len)
    #[monoio::test]
    async fn reader_prefix_skip_alignment_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefix_skip.v5a");

        // Use 1 output (5 bytes) -> HEADER 72 + outputs 5 => start_off=77, misaligned.
        let gates: Vec<_> = (0..17u64).map(mk_gate).collect();
        write_file(&path, 0, vec![42], &gates).await;

        let mut r = CircuitReaderV5a::open(&path).unwrap();

        // Consume all gates; ensure totals and order preserved.
        let mut total = 0usize;
        while let Some(b) = r.next_block_soa().await.unwrap() {
            for i in 0..b.gates_in_block {
                let idx = total + i;
                assert_eq!(b.in1[i], (10 + idx as u64) & MAX_WIRE_ID);
                assert_eq!(b.in2[i], (20 + idx as u64) & MAX_WIRE_ID);
                assert_eq!(b.out[i], (30 + idx as u64) & MAX_WIRE_ID);
                assert_eq!(b.credits[i], ((idx as u32) * 3) & MAX_CREDITS);
                let want = if (idx as u64).is_multiple_of(2) {
                    GateType::XOR
                } else {
                    GateType::AND
                };
                assert_eq!(b.gate_types[i], want);
            }
            total += b.gates_in_block;
        }
        assert_eq!(total, gates.len());
        assert!(verify_v5a_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn reader_checksum_verification_independent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("verify.v5a");

        let gates: Vec<_> = (0..5u64).map(mk_gate).collect();
        write_file(&path, 9, vec![7, 8], &gates).await;

        // Verify via standalone async function (no streaming reader needed).
        assert!(verify_v5a_checksum(&path).await.unwrap());

        // Corrupt one byte in blocks area and confirm verify fails
        let mut f = StdOpen::new().read(true).write(true).open(&path).unwrap();
        // Skip header + outputs (2 * 5 = 10 bytes)
        f.seek(SeekFrom::Start((HEADER_SIZE_V5A + 10) as u64))
            .unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Current(-1)).unwrap();
        f.write_all(&[b[0] ^ 0xFF]).unwrap();

        assert!(!verify_v5a_checksum(&path).await.unwrap());
    }
}

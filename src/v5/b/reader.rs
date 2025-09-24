//! High-performance v5b reader using monoio io_uring and AVX-512
//!
//! This implementation uses a two-thread architecture:
//! - Disk reader thread: Uses io_uring with O_DIRECT for optimal NVMe performance
//! - Decoder thread: Uses AVX-512 to decode Structure-of-Arrays gate blocks

use blake3::Hasher;
use cynosure::site_d::triplebuffer::{AlignedBuffer, BUFFER_SIZE, TripleBuffer};
use monoio::fs::OpenOptions;

use std::fs::File as StdFile;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::{
    BlockV5b, GATES_PER_BLOCK, GateType, GateV5b, HEADER_SIZE, HeaderV5b, LEVEL_HEADER_SIZE,
    LevelHeader, OUTPUT_ENTRY_SIZE,
};

/// Result type for reader operations
pub type Result<T> = std::result::Result<T, ReaderError>;

/// Error types for reader operations
#[derive(Debug)]
pub enum ReaderError {
    Io(io::Error),
    InvalidHeader(String),
    InvalidData(String),
    ChecksumMismatch,
    UnexpectedEof,
}

impl From<io::Error> for ReaderError {
    fn from(err: io::Error) -> Self {
        ReaderError::Io(err)
    }
}

impl std::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReaderError::Io(e) => write!(f, "I/O error: {}", e),
            ReaderError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            ReaderError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            ReaderError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            ReaderError::UnexpectedEof => write!(f, "Unexpected end of file"),
        }
    }
}

impl std::error::Error for ReaderError {}

/// State for the current level being read
struct CurrentLevelState {
    header: LevelHeader,
    gates_read: u32,
    xor_gates_read: u32,
    and_gates_read: u32,
}

/// Reader for v5b format circuits
pub struct CircuitReaderV5b {
    /// Triple buffer for lock-free streaming
    triple_buffer: Arc<TripleBuffer>,

    /// Join handle for disk reader thread
    reader_thread: Option<thread::JoinHandle<Result<()>>>,

    /// Current buffer being decoded
    current_buffer: Option<AlignedBuffer>,

    /// Position in current buffer
    buffer_pos: usize,

    /// Available bytes in current buffer
    buffer_len: usize,

    /// Stop signal for reader thread
    stop_flag: Arc<AtomicBool>,

    /// Header of the circuit
    header: HeaderV5b,

    /// Output memory addresses
    outputs: Vec<u32>,

    /// Current level state
    current_level: Option<CurrentLevelState>,

    /// Number of levels read
    levels_read: u32,

    /// Total gates read
    gates_read: u64,

    /// Total bytes read from disk (for tracking buffer sizes)
    total_bytes_read: u64,

    /// Total file size after headers/outputs
    data_size: u64,
}

impl CircuitReaderV5b {
    /// Open a v5b circuit file for reading
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::new(path).await
    }

    /// Create a new reader
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Read header synchronously first
        let mut std_file = StdFile::open(path.as_ref())?;
        let mut header_bytes = [0u8; HEADER_SIZE];
        std_file.read_exact(&mut header_bytes)?;
        let header = HeaderV5b::from_bytes(&header_bytes);

        // Validate header
        header
            .validate()
            .map_err(|e| ReaderError::InvalidHeader(e))?;

        // Read outputs
        let outputs = Self::read_outputs_sync(&mut std_file, header.num_outputs as usize)?;

        // Get file size for buffer tracking
        let file_metadata = std_file.metadata()?;
        let file_size = file_metadata.len();

        // Calculate and verify checksum
        let checksum = Self::calculate_checksum_sync(&mut std_file, &header, &outputs)?;
        if checksum != header.checksum {
            return Err(ReaderError::ChecksumMismatch);
        }

        // Create triple buffer
        let (triple_buffer_inner, writer_initial_buf) = TripleBuffer::new();
        let triple_buffer = Arc::new(triple_buffer_inner);
        let buffer_clone = Arc::clone(&triple_buffer);

        // Create shared state
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        let initial_offset = HEADER_SIZE as u64 + (header.num_outputs * OUTPUT_ENTRY_SIZE as u64);
        let data_size = file_size - initial_offset;

        // Spawn disk reader thread
        let path_clone = path.as_ref().to_path_buf();
        let reader_thread = thread::spawn(move || -> Result<()> {
            monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .with_entries(256)
                .enable_timer()
                .build()
                .expect("Failed to create monoio runtime")
                .block_on(async move {
                    disk_reader_thread(
                        path_clone,
                        buffer_clone,
                        initial_offset,
                        stop_flag_clone,
                        writer_initial_buf,
                    )
                    .await
                })
        });

        Ok(Self {
            triple_buffer,
            reader_thread: Some(reader_thread),
            current_buffer: None,
            buffer_pos: 0,
            buffer_len: 0,
            stop_flag,
            header,
            outputs,
            current_level: None,
            levels_read: 0,
            gates_read: 0,
            total_bytes_read: 0,
            data_size,
        })
    }

    /// Read outputs synchronously
    fn read_outputs_sync(file: &mut StdFile, num_outputs: usize) -> Result<Vec<u32>> {
        let mut outputs = Vec::with_capacity(num_outputs);
        let mut buffer = vec![0u8; num_outputs * OUTPUT_ENTRY_SIZE];
        file.read_exact(&mut buffer)?;

        for i in 0..num_outputs {
            let offset = i * OUTPUT_ENTRY_SIZE;
            let value =
                u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], 0]);
            outputs.push(value);
        }

        Ok(outputs)
    }

    /// Calculate checksum synchronously
    fn calculate_checksum_sync(
        file: &mut StdFile,
        header: &HeaderV5b,
        outputs: &[u32],
    ) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();

        // Hash outputs
        for &output in outputs {
            let bytes = [
                (output & 0xFF) as u8,
                ((output >> 8) & 0xFF) as u8,
                ((output >> 16) & 0xFF) as u8,
            ];
            hasher.update(&bytes);
        }

        // Seek to start of level/gate data
        let data_start = HEADER_SIZE as u64 + (header.num_outputs * OUTPUT_ENTRY_SIZE as u64);
        file.seek(SeekFrom::Start(data_start))?;

        // Hash all level headers and gate blocks
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB chunks
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        // Hash header fields after checksum
        let header_bytes = header.to_bytes();
        hasher.update(&header_bytes[40..]);

        Ok(*hasher.finalize().as_bytes())
    }

    /// Refill buffer from triple buffer
    async fn refill_buffer(&mut self) -> Result<()> {
        let buffer = self
            .triple_buffer
            .reader_next(self.current_buffer.take())
            .await;

        if let Some(buffer) = new_buffer {
            // Calculate actual buffer size based on remaining data
            let remaining_data = self.data_size.saturating_sub(self.total_bytes_read);
            self.buffer_len = std::cmp::min(BUFFER_SIZE, remaining_data as usize);
            self.buffer_pos = 0;
            self.current_buffer = Some(buffer);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Read data from buffer
    fn read_from_buffer(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.buffer_pos >= self.buffer_len && !self.refill_buffer()? {
            return Ok(0);
        }

        let buffer = self
            .current_buffer
            .as_ref()
            .ok_or(ReaderError::UnexpectedEof)?;
        let available = self.buffer_len - self.buffer_pos;
        let to_read = dst.len().min(available);

        dst[..to_read].copy_from_slice(&buffer[self.buffer_pos..self.buffer_pos + to_read]);
        self.buffer_pos += to_read;
        self.total_bytes_read += to_read as u64;

        Ok(to_read)
    }

    /// Read exact amount of data from buffer
    fn read_exact_from_buffer(&mut self, dst: &mut [u8]) -> Result<()> {
        let mut pos = 0;
        while pos < dst.len() {
            let n = self.read_from_buffer(&mut dst[pos..])?;
            if n == 0 {
                return Err(ReaderError::UnexpectedEof);
            }
            pos += n;
        }
        Ok(())
    }

    /// Start reading a new level
    pub fn next_level(&mut self) -> Result<Option<LevelHeader>> {
        if self.levels_read >= self.header.num_levels {
            return Ok(None);
        }

        // Finalize current level if any
        if let Some(current) = &self.current_level {
            let num_gates = current.header.num_gates; // Copy from packed struct
            if current.gates_read != num_gates {
                return Err(ReaderError::InvalidData(format!(
                    "Level incomplete: read {} gates, expected {}",
                    current.gates_read, num_gates
                )));
            }
        }

        // Read level header
        let mut header_bytes = [0u8; LEVEL_HEADER_SIZE];
        self.read_exact_from_buffer(&mut header_bytes)?;
        let level_header = LevelHeader::from_bytes(&header_bytes);

        level_header
            .validate()
            .map_err(|e| ReaderError::InvalidData(format!("Invalid level header: {}", e)))?;

        self.current_level = Some(CurrentLevelState {
            header: level_header,
            gates_read: 0,
            xor_gates_read: 0,
            and_gates_read: 0,
        });

        self.levels_read += 1;
        Ok(Some(level_header))
    }

    /// Read the next batch of gates (up to one block)
    pub fn next_gates(&mut self, gates: &mut Vec<GateV5b>) -> Result<usize> {
        // First check if we have a level and calculate how many gates to read
        let (num_gates_in_level, gates_read_so_far) = {
            let level = self
                .current_level
                .as_ref()
                .ok_or_else(|| ReaderError::InvalidData("No level started".to_string()))?;
            (level.header.num_gates, level.gates_read)
        };

        if gates_read_so_far >= num_gates_in_level {
            return Ok(0);
        }

        // Calculate how many gates to read (up to one block)
        let remaining = num_gates_in_level - gates_read_so_far;
        let gates_to_read = std::cmp::min(remaining as usize, GATES_PER_BLOCK);

        // Read block
        let mut block = BlockV5b::new();
        self.read_exact_from_buffer(&mut block.in1_stream)?;
        self.read_exact_from_buffer(&mut block.in2_stream)?;
        self.read_exact_from_buffer(&mut block.out_stream)?;

        // Unpack gates
        gates.clear();
        gates.reserve(gates_to_read);

        self.unpack_gates_scalar(&block, gates_to_read, gates);

        // Update level state
        if let Some(level) = &mut self.current_level {
            level.gates_read += gates_to_read as u32;
        }
        self.gates_read += gates_to_read as u64;

        Ok(gates_to_read)
    }

    /// Scalar gate unpacking
    fn unpack_gates_scalar(&self, block: &BlockV5b, count: usize, gates: &mut Vec<GateV5b>) {
        for i in 0..count {
            let in1 = BlockV5b::unpack_24bit(&block.in1_stream, i);
            let in2 = BlockV5b::unpack_24bit(&block.in2_stream, i);
            let out = BlockV5b::unpack_24bit(&block.out_stream, i);
            gates.push(GateV5b { in1, in2, out });
        }
    }

    /// Read next gates with type information
    pub fn next_gates_typed(&mut self, gates: &mut Vec<(GateV5b, GateType)>) -> Result<usize> {
        // Extract needed values before calling next_gates
        let num_xor_gates = {
            let level = self
                .current_level
                .as_ref()
                .ok_or_else(|| ReaderError::InvalidData("No level started".to_string()))?;
            level.header.num_xor_gates
        };

        let mut raw_gates = Vec::with_capacity(GATES_PER_BLOCK);
        let count = self.next_gates(&mut raw_gates)?;

        gates.clear();
        gates.reserve(count);

        // Now update the level counters
        let level = self
            .current_level
            .as_mut()
            .ok_or_else(|| ReaderError::InvalidData("No level started".to_string()))?;

        for gate in raw_gates {
            // Determine type based on position in level
            let gate_type = if level.xor_gates_read < num_xor_gates {
                level.xor_gates_read += 1;
                GateType::Xor
            } else {
                level.and_gates_read += 1;
                GateType::And
            };

            gates.push((gate, gate_type));
        }

        Ok(count)
    }

    /// Get header reference
    pub fn header(&self) -> &HeaderV5b {
        &self.header
    }

    /// Get outputs reference
    pub fn outputs(&self) -> &[u32] {
        &self.outputs
    }

    /// Get current level state
    pub fn current_level(&self) -> Option<&LevelHeader> {
        self.current_level.as_ref().map(|l| &l.header)
    }

    /// Get statistics
    pub fn stats(&self) -> ReaderStats {
        ReaderStats {
            gates_read: self.gates_read,
            levels_read: self.levels_read,
            total_gates: self.header.total_gates(),
            total_levels: self.header.num_levels,
        }
    }
}

impl Drop for CircuitReaderV5b {
    fn drop(&mut self) {
        // Signal reader thread to stop
        self.stop_flag.store(true, Ordering::Relaxed);

        // Wait for reader thread
        if let Some(thread) = self.reader_thread.take() {
            let _ = thread.join();
        }
    }
}

/// Disk reader thread using monoio/io_uring
async fn disk_reader_thread(
    path: impl AsRef<Path>,
    triple_buffer: Arc<TripleBuffer>,
    initial_offset: u64,
    stop_flag: Arc<AtomicBool>,
    mut current_buffer: AlignedBuffer,
) -> Result<()> {
    // Open file with O_DIRECT for optimal NVMe performance
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
    }
    let file = opts.open(path.as_ref()).await?;
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    let mut current_offset = initial_offset;

    while current_offset < file_size && !stop_flag.load(Ordering::Relaxed) {
        let to_read = std::cmp::min(BUFFER_SIZE, (file_size - current_offset) as usize);

        // Read into buffer
        let (res, buf) = file
            .read_exact_at(current_buffer[..to_read].to_vec(), current_offset)
            .await;
        res?;

        // Copy back to current buffer
        current_buffer[..to_read].copy_from_slice(&buf);

        // Swap buffer with triple buffer
        current_buffer = triple_buffer.writer_publish(current_buffer).await;

        current_offset += to_read as u64;
    }

    Ok(())
}

/// Reader statistics
#[derive(Debug, Clone)]
pub struct ReaderStats {
    pub gates_read: u64,
    pub levels_read: u32,
    pub total_gates: u64,
    pub total_levels: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v5::b::{CircuitWriterV5b, writer::Level};
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_round_trip() -> Result<()> {
        let temp_file = NamedTempFile::new().map_err(|e| ReaderError::Io(e))?;
        let path = temp_file.path();

        // Write a circuit
        let outputs: Vec<u32> = (0..2).map(|i| 100 + i).collect();
        let mut writer = CircuitWriterV5b::new(path, 4, outputs, 3)
            .await
            .map_err(|e| ReaderError::Io(e))?;

        // Level 1: 10 XOR, 5 AND
        let mut level1 = Level::with_capacity(10, 5);
        for i in 0..10 {
            level1
                .add_xor(GateV5b::new(i + 4, i + 5, i + 100).unwrap())
                .map_err(|e| ReaderError::Io(e))?;
        }
        for i in 0..5 {
            level1
                .add_and(GateV5b::new(i + 200, i + 201, i + 300).unwrap())
                .map_err(|e| ReaderError::Io(e))?;
        }
        writer
            .write_level(level1)
            .await
            .map_err(|e| ReaderError::Io(e))?;

        // Level 2: 5 XOR, 10 AND
        let mut level2 = Level::with_capacity(5, 10);
        for i in 0..5 {
            level2
                .add_xor(GateV5b::new(i + 400, i + 401, i + 500).unwrap())
                .map_err(|e| ReaderError::Io(e))?;
        }
        for i in 0..10 {
            level2
                .add_and(GateV5b::new(i + 600, i + 601, i + 700).unwrap())
                .map_err(|e| ReaderError::Io(e))?;
        }
        writer
            .write_level(level2)
            .await
            .map_err(|e| ReaderError::Io(e))?;

        // Level 3: 0 XOR, 3 AND
        let mut level3 = Level::with_capacity(0, 3);
        for i in 0..3 {
            level3
                .add_and(GateV5b::new(i + 800, i + 801, i + 900).unwrap())
                .map_err(|e| ReaderError::Io(e))?;
        }
        writer
            .write_level(level3)
            .await
            .map_err(|e| ReaderError::Io(e))?;

        let write_stats = writer
            .finalize(1000)
            .await
            .map_err(|e| ReaderError::Io(e))?;

        // Read the circuit back
        let mut reader = CircuitReaderV5b::open(path).await?;
        assert_eq!(reader.header().total_gates(), 33);
        let xor_gates = reader.header().xor_gates;
        assert_eq!(xor_gates, 15);
        let and_gates = reader.header().and_gates;
        assert_eq!(and_gates, 18);
        assert_eq!(reader.outputs(), &[100, 101]);

        // Read level 1
        let level1 = reader.next_level()?.unwrap();
        let level1_num_gates = level1.num_gates;
        assert_eq!(level1_num_gates, 15);
        let level1_num_xor_gates = level1.num_xor_gates;
        assert_eq!(level1_num_xor_gates, 10);

        let mut gates = Vec::new();
        let count = reader.next_gates(&mut gates)?;
        assert_eq!(count, 15);

        // Read level 2
        let level2 = reader.next_level()?.unwrap();
        let level2_num_gates = level2.num_gates;
        assert_eq!(level2_num_gates, 15);
        let level2_num_xor_gates = level2.num_xor_gates;
        assert_eq!(level2_num_xor_gates, 5);

        let count = reader.next_gates(&mut gates)?;
        assert_eq!(count, 15);

        // Read level 3
        let level3 = reader.next_level()?.unwrap();
        let level3_num_gates = level3.num_gates;
        assert_eq!(level3_num_gates, 3);
        let level3_num_xor_gates = level3.num_xor_gates;
        assert_eq!(level3_num_xor_gates, 0);

        let count = reader.next_gates(&mut gates)?;
        assert_eq!(count, 3);

        // No more levels
        assert!(reader.next_level()?.is_none());

        // Verify checksum matches
        let reader_checksum = reader.header().checksum;
        assert_eq!(reader_checksum, write_stats.checksum);

        Ok(())
    }

    #[monoio::test]
    async fn test_bench_decode_comparison() -> Result<()> {
        use std::time::Instant;

        let temp_file = NamedTempFile::new().map_err(|e| ReaderError::Io(e))?;
        let path = temp_file.path();

        // Create a large circuit with multiple levels
        let num_levels = 10;
        let gates_per_level = 10_000;
        let total_gates = num_levels * gates_per_level;

        {
            let outputs: Vec<u32> = (0..10).map(|i| 100 + i).collect();
            let mut writer = CircuitWriterV5b::new(path, 100, outputs, num_levels)
                .await
                .map_err(|e| ReaderError::Io(e))?;

            // Write levels
            for level_idx in 0..num_levels {
                let xor_count = gates_per_level / 2;
                let and_count = gates_per_level - xor_count;

                let mut level = Level::with_capacity(xor_count as usize, and_count as usize);

                for i in 0..gates_per_level {
                    let base = level_idx * gates_per_level + i;
                    let gate = GateV5b::new(
                        (base % 100) as u32 + 100,
                        (base % 100) as u32 + 101,
                        (base % 100) as u32 + 200,
                    )
                    .unwrap();

                    if i < xor_count {
                        level.add_xor(gate).map_err(|e| ReaderError::Io(e))?;
                    } else {
                        level.add_and(gate).map_err(|e| ReaderError::Io(e))?;
                    }
                }

                writer
                    .write_level(level)
                    .await
                    .map_err(|e| ReaderError::Io(e))?;
            }

            let stats = writer
                .finalize(total_gates as u64 + 200)
                .await
                .map_err(|e| ReaderError::Io(e))?;
            println!("\n=== v5b Decode Performance Benchmark ===");
            println!("Circuit size: {} gates", stats.total_gates);
            println!(
                "File size: {} bytes ({:.2} MB)",
                stats.bytes_written,
                stats.bytes_written as f64 / (1024.0 * 1024.0)
            );
            println!(
                "Bytes per gate: {:.2}",
                stats.bytes_written as f64 / stats.total_gates as f64
            );
        }

        // Benchmark reading with scalar decoding
        println!("\n--- Scalar Decoding ---");
        let start = Instant::now();

        {
            let mut reader = CircuitReaderV5b::open(path).await?;
            let mut total_gates_read = 0;
            let mut gates = Vec::with_capacity(GATES_PER_BLOCK);

            for _ in 0..num_levels {
                reader.next_level()?;

                loop {
                    let count = reader.next_gates(&mut gates)?;
                    if count == 0 {
                        break;
                    }
                    total_gates_read += count;
                }
            }

            assert_eq!(total_gates_read, total_gates as usize);
        }

        let duration = start.elapsed();
        let gates_per_sec = total_gates as f64 / duration.as_secs_f64();
        let mb_per_sec = (total_gates as f64 * 9.0) / (duration.as_secs_f64() * 1024.0 * 1024.0);

        println!("Time: {:.3} seconds", duration.as_secs_f64());
        println!("Gates/sec: {:.2}M", gates_per_sec / 1_000_000.0);
        println!("Throughput: {:.2} MB/s", mb_per_sec);

        println!("\n=== Benchmark Complete ===\n");

        Ok(())
    }

    #[monoio::test]
    async fn test_simple_write_read() -> Result<()> {
        let temp_file = NamedTempFile::new().map_err(|e| ReaderError::Io(e))?;
        let path = temp_file.path();

        // Write a minimal circuit
        {
            let mut writer = CircuitWriterV5b::new(path, 2, vec![5], 1)
                .await
                .map_err(|e| ReaderError::Io(e))?;

            let mut level = Level::new();
            level
                .add_xor(GateV5b::new(2, 3, 4).unwrap())
                .map_err(|e| ReaderError::Io(e))?;

            writer
                .write_level(level)
                .await
                .map_err(|e| ReaderError::Io(e))?;
            writer.finalize(10).await.map_err(|e| ReaderError::Io(e))?;
        }

        // Check file was created and has content
        let metadata = std::fs::metadata(path).map_err(|e| ReaderError::Io(e))?;
        assert!(metadata.len() > 0, "File should not be empty");

        // Try to open and read header
        let reader = CircuitReaderV5b::open(path).await?;

        assert_eq!(reader.header().total_gates(), 1);
        assert_eq!(reader.outputs(), &[5]);

        Ok(())
    }
}

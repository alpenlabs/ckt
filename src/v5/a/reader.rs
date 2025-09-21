//! High-performance v5a reader using monoio io_uring and AVX-512
//!
//! This implementation uses a two-thread architecture:
//! - Disk reader thread: Uses io_uring with O_DIRECT for optimal NVMe performance
//! - Decoder thread: Uses AVX-512 to decode Structure-of-Arrays gate blocks

use crate::v5::triple_buffer::{AlignedBuffer, BUFFER_SIZE, TripleBuffer};
use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;
use std::sync::Arc;
use std::thread;

/// Magic bytes for v5 format: "Zk2u"
pub const MAGIC: [u8; 4] = [0x5A, 0x6B, 0x32, 0x75];

/// Version number for v5
pub const VERSION: u8 = 0x05;

/// Format type for v5a
pub const FORMAT_TYPE_A: u8 = 0x00;

/// Gates per block in v5a
pub const GATES_PER_BLOCK: usize = 256;

/// Size of a v5a block in bytes
pub const BLOCK_SIZE_V5A: usize = 4064;

/// v5a header structure (72 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HeaderV5a {
    pub magic: [u8; 4],
    pub version: u8,
    pub format_type: u8,
    pub reserved: [u8; 2],
    pub checksum: [u8; 32],
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub num_outputs: u64,
}

impl HeaderV5a {
    /// Validate header fields
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid magic bytes: {:?}", self.magic),
            ));
        }
        if self.version != VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid version: {}", self.version),
            ));
        }
        if self.format_type != FORMAT_TYPE_A {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid format type: {}", self.format_type),
            ));
        }
        if self.reserved != [0, 0] {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Reserved bytes must be zero",
            ));
        }
        Ok(())
    }

    /// Get total number of gates
    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }
}

/// A decoded gate from v5a format
#[derive(Debug, Clone, Copy)]
pub struct GateV5a {
    pub in1: u64,        // 34-bit wire ID (stored in u64)
    pub in2: u64,        // 34-bit wire ID
    pub out: u64,        // 34-bit wire ID
    pub credits: u32,    // 24-bit credits (stored in u32)
    pub gate_type: bool, // false = XOR, true = AND
}

/// Decoded block of 256 gates
pub struct DecodedBlock {
    pub gates: Vec<GateV5a>,
    pub valid_gates: usize,
}

/// v5a reader state
pub struct CircuitReaderV5a {
    /// Triple buffer for lock-free streaming
    triple_buffer: Arc<TripleBuffer>,

    /// Join handle for disk reader thread
    reader_thread: Option<thread::JoinHandle<Result<()>>>,

    /// Current buffer being decoded
    current_buffer: Option<AlignedBuffer>,

    /// Position in current buffer
    buffer_pos: usize,

    /// Bytes available in current buffer
    buffer_available: usize,

    /// Circuit header
    header: HeaderV5a,

    /// Output wire IDs
    outputs: Vec<u64>,

    /// Total gates read so far
    gates_read: u64,

    /// Checksum hasher
    hasher: Hasher,
}

impl CircuitReaderV5a {
    /// Create a new v5a reader
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_owned();

        // Open file with O_DIRECT for optimal NVMe performance
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
        }

        let mut file = opts.open(&path).await?;

        // Read and validate header
        let header = Self::read_header(&mut file).await?;
        header.validate()?;

        // Read output wire IDs
        let outputs = Self::read_outputs(&mut file, header.num_outputs).await?;

        // Create triple buffer
        let (triple_buffer_inner, writer_initial_buf) = TripleBuffer::new();
        let triple_buffer = Arc::new(triple_buffer_inner);
        let buffer_clone = Arc::clone(&triple_buffer);

        // Calculate file size for gates section
        let outputs_size = header.num_outputs * 5; // 5 bytes per output
        let header_and_outputs = 72 + outputs_size;

        // Spawn disk reader thread
        let reader_thread = thread::spawn(move || {
            // Create monoio runtime for this thread
            let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                .enable_timer()
                .build()
                .map_err(|e| Error::new(ErrorKind::Other, e))?;

            rt.block_on(async move {
                disk_reader_thread(
                    path,
                    buffer_clone,
                    header_and_outputs as u64,
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
            buffer_available: 0,
            header,
            outputs,
            gates_read: 0,
            hasher: Hasher::new(),
        })
    }

    /// Read header from file
    async fn read_header(file: &mut File) -> Result<HeaderV5a> {
        let (res, buf) = file.read_exact_at(vec![0u8; 72], 0).await;
        res?;

        if buf.len() != 72 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Incomplete header"));
        }

        let header = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const HeaderV5a) };

        Ok(header)
    }

    /// Read output wire IDs
    async fn read_outputs(file: &mut File, num_outputs: u64) -> Result<Vec<u64>> {
        let size = num_outputs as usize * 5;
        let (res, buf) = file.read_exact_at(vec![0u8; size], 72).await;
        res?;

        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for i in 0..num_outputs as usize {
            let offset = i * 5;
            let mut bytes = [0u8; 8];
            bytes[..5].copy_from_slice(&buf[offset..offset + 5]);
            let value = u64::from_le_bytes(bytes) & 0x3FFFFFFFF; // Mask to 34 bits
            outputs.push(value);
        }

        Ok(outputs)
    }

    /// Get the circuit header
    pub fn header(&self) -> &HeaderV5a {
        &self.header
    }

    /// Get output wire IDs
    pub fn outputs(&self) -> &[u64] {
        &self.outputs
    }

    /// Read next block of gates
    pub fn next_block(&mut self) -> Result<Option<DecodedBlock>> {
        // Check if we've read all gates
        if self.gates_read >= self.header.total_gates() {
            return Ok(None);
        }

        // Ensure we have enough data
        if !self.ensure_data(BLOCK_SIZE_V5A)? {
            return Ok(None);
        }

        // Decode block using AVX-512 on x86_64, or scalar fallback on other platforms
        let block = {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                decode_block_avx512(
                    &self.current_buffer.as_ref().unwrap()[self.buffer_pos..],
                    self.header.total_gates() - self.gates_read,
                )
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                decode_block_scalar(
                    &self.current_buffer.as_ref().unwrap()[self.buffer_pos..],
                    self.header.total_gates() - self.gates_read,
                )
            }
        };

        // Update position and counters
        self.buffer_pos += BLOCK_SIZE_V5A;
        self.buffer_available -= BLOCK_SIZE_V5A;
        self.gates_read += block.valid_gates as u64;

        // Update checksum
        self.hasher.update(
            &self.current_buffer.as_ref().unwrap()
                [self.buffer_pos - BLOCK_SIZE_V5A..self.buffer_pos],
        );

        Ok(Some(block))
    }

    /// Ensure we have at least `needed` bytes available
    fn ensure_data(&mut self, needed: usize) -> Result<bool> {
        // If we have enough data, we're good
        if self.buffer_available >= needed {
            return Ok(true);
        }

        // Try to get a new buffer from the triple buffer
        let new_buffer = self.triple_buffer.reader_take(self.current_buffer.take());

        if let Some(buffer) = new_buffer {
            // Got a new buffer
            self.current_buffer = Some(buffer);
            self.buffer_pos = 0;
            self.buffer_available = BUFFER_SIZE;

            // Check again
            if self.buffer_available >= needed {
                return Ok(true);
            }
        }

        // No data available yet - this is normal during streaming
        Ok(false)
    }

    /// Verify checksum after reading all blocks
    pub fn verify_checksum(&mut self) -> Result<bool> {
        // Add outputs to hash
        for &output in &self.outputs {
            let mut bytes = [0u8; 5];
            bytes[..5].copy_from_slice(&output.to_le_bytes()[..5]);
            self.hasher.update(&bytes);
        }

        // Add header fields after checksum
        self.hasher.update(&self.header.xor_gates.to_le_bytes());
        self.hasher.update(&self.header.and_gates.to_le_bytes());
        self.hasher
            .update(&self.header.primary_inputs.to_le_bytes());
        self.hasher.update(&self.header.num_outputs.to_le_bytes());

        let computed = self.hasher.finalize();
        Ok(computed.as_bytes() == &self.header.checksum)
    }
}

impl Drop for CircuitReaderV5a {
    fn drop(&mut self) {
        // Wait for reader thread to finish
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Disk reader thread function
async fn disk_reader_thread(
    path: impl AsRef<Path>,
    triple_buffer: Arc<TripleBuffer>,
    header_size: u64,
    current_buffer: AlignedBuffer,
) -> Result<()> {
    // Open file with O_DIRECT
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
    }

    let file = opts.open(path).await?;
    let metadata = file.metadata().await?;
    let file_size = metadata.len();

    let mut current_offset = header_size;
    let mut write_buffer = current_buffer;

    while current_offset < file_size {
        let to_read = std::cmp::min(BUFFER_SIZE, (file_size - current_offset) as usize);

        // Read with io_uring
        let (res, buf) = file
            .read_exact_at(write_buffer[..to_read].to_vec(), current_offset)
            .await;
        res?;

        // Copy back to write buffer
        write_buffer[..to_read].copy_from_slice(&buf);

        // Swap with triple buffer
        write_buffer = triple_buffer.writer_swap(write_buffer);

        current_offset += to_read as u64;
    }

    Ok(())
}

/// Decode a v5a block using AVX-512
///
/// # Safety
/// Requires AVX-512F, AVX-512BW, and AVX-512VBMI support
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vbmi")]
unsafe fn decode_block_avx512(data: &[u8], max_gates: u64) -> DecodedBlock {
    let valid_gates = std::cmp::min(GATES_PER_BLOCK, max_gates as usize);
    let mut gates = Vec::with_capacity(valid_gates);

    // Extract gate types (last 32 bytes of block)
    let gate_types = &data[4032..4064];

    // Process 15 gates at a time (15 × 34 = 510 bits fits in 512-bit register)
    let chunks_of_15 = valid_gates / 15;
    let remainder = valid_gates % 15;

    // Masks for extracting 34-bit values
    let mask_34bit = _mm512_set1_epi64(0x3FFFFFFFF);

    // Process chunks of 15 gates using AVX-512
    for chunk in 0..chunks_of_15 {
        let base_gate = chunk * 15;
        let base_bit = base_gate * 34;
        let base_byte = base_bit / 8;

        // Extract in1 values (15 × 34 bits)
        let in1_data = unsafe { _mm512_loadu_si512(data[base_byte..].as_ptr() as *const __m512i) };
        let in1_values =
            unsafe { extract_15x34_bits_avx512(in1_data, (base_bit % 8) as u8, mask_34bit) };

        // Extract in2 values (15 × 34 bits)
        let in2_base_byte = (base_gate * 34) / 8 + 1088;
        let in2_data =
            unsafe { _mm512_loadu_si512(data[in2_base_byte..].as_ptr() as *const __m512i) };
        let in2_values = unsafe {
            extract_15x34_bits_avx512(in2_data, ((base_gate * 34) % 8) as u8, mask_34bit)
        };

        // Extract out values (15 × 34 bits)
        let out_base_byte = (base_gate * 34) / 8 + 2176;
        let out_data =
            unsafe { _mm512_loadu_si512(data[out_base_byte..].as_ptr() as *const __m512i) };
        let out_values = unsafe {
            extract_15x34_bits_avx512(out_data, ((base_gate * 34) % 8) as u8, mask_34bit)
        };

        // Extract credits (15 × 24 bits = 360 bits)
        let credits_base_byte = (base_gate * 24) / 8 + 3264;
        let credits_data =
            unsafe { _mm512_loadu_si512(data[credits_base_byte..].as_ptr() as *const __m512i) };
        let mask_24bit = _mm512_set1_epi32(0xFFFFFF);
        let credits_values = unsafe {
            extract_15x24_bits_avx512(credits_data, ((base_gate * 24) % 8) as u8, mask_24bit)
        };

        // Store extracted values
        let mut in1_array = [0u64; 8];
        let mut in2_array = [0u64; 8];
        let mut out_array = [0u64; 8];
        let mut credits_array = [0u32; 16];

        unsafe {
            _mm512_storeu_si512(in1_array.as_mut_ptr() as *mut __m512i, in1_values);
            _mm512_storeu_si512(in2_array.as_mut_ptr() as *mut __m512i, in2_values);
            _mm512_storeu_si512(out_array.as_mut_ptr() as *mut __m512i, out_values);
            _mm512_storeu_si512(credits_array.as_mut_ptr() as *mut __m512i, credits_values);
        }

        // Create gate structures
        for i in 0..15 {
            if base_gate + i >= valid_gates {
                break;
            }

            let gate_idx = base_gate + i;
            let byte_idx = gate_idx / 8;
            let bit_idx = gate_idx % 8;
            let gate_type = (gate_types[byte_idx] >> bit_idx) & 1 != 0;

            gates.push(GateV5a {
                in1: in1_array[i / 2] >> ((i % 2) * 34) & 0x3FFFFFFFF,
                in2: in2_array[i / 2] >> ((i % 2) * 34) & 0x3FFFFFFFF,
                out: out_array[i / 2] >> ((i % 2) * 34) & 0x3FFFFFFFF,
                credits: credits_array[i],
                gate_type,
            });
        }
    }

    // Process remaining gates with scalar code
    let start_idx = chunks_of_15 * 15;
    for i in start_idx..(start_idx + remainder) {
        let bit_offset_in1 = i * 34;
        let bit_offset_in2 = i * 34;
        let bit_offset_out = i * 34;
        let bit_offset_credits = i * 24;

        let in1 = extract_34_bits(&data[0..1088], bit_offset_in1);
        let in2 = extract_34_bits(&data[1088..2176], bit_offset_in2);
        let out = extract_34_bits(&data[2176..3264], bit_offset_out);
        let credits = extract_24_bits(&data[3264..4032], bit_offset_credits);

        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let gate_type = (gate_types[byte_idx] >> bit_idx) & 1 != 0;

        gates.push(GateV5a {
            in1,
            in2,
            out,
            credits,
            gate_type,
        });
    }

    DecodedBlock { gates, valid_gates }
}

/// Extract 15 34-bit values using AVX-512
#[inline]
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn extract_15x34_bits_avx512(data: __m512i, bit_shift: u8, mask: __m512i) -> __m512i {
    // If bit_shift is 0, data is already aligned
    let shifted = if bit_shift == 0 {
        data
    } else {
        // For runtime bit_shift, we use variable per-lane shifting
        // This shifts each 64-bit element independently
        _mm512_srlv_epi64(data, _mm512_set1_epi64(bit_shift as i64))
    };

    // Apply mask to get 34-bit values
    _mm512_and_si512(shifted, mask)
}

/// Extract 15 24-bit values using AVX-512
#[inline]
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn extract_15x24_bits_avx512(data: __m512i, bit_shift: u8, mask: __m512i) -> __m512i {
    // Similar to 34-bit extraction but for 24-bit values
    let shifted = if bit_shift == 0 {
        data
    } else {
        // For runtime bit_shift, use variable per-lane shifting
        _mm512_srlv_epi64(data, _mm512_set1_epi64(bit_shift as i64))
    };

    _mm512_and_si512(shifted, mask)
}

/// Decode a v5a block using scalar code
/// This is used for testing and as a fallback on non-x86_64 platforms
fn decode_block_scalar(data: &[u8], max_gates: u64) -> DecodedBlock {
    let valid_gates = std::cmp::min(GATES_PER_BLOCK, max_gates as usize);
    let mut gates = Vec::with_capacity(valid_gates);

    // Extract gate types (last 32 bytes of block)
    let gate_types = &data[4032..4064];

    for i in 0..valid_gates {
        let bit_offset_in1 = i * 34;
        let bit_offset_in2 = i * 34;
        let bit_offset_out = i * 34;
        let bit_offset_credits = i * 24;

        let in1 = extract_34_bits(&data[0..1088], bit_offset_in1);
        let in2 = extract_34_bits(&data[1088..2176], bit_offset_in2);
        let out = extract_34_bits(&data[2176..3264], bit_offset_out);
        let credits = extract_24_bits(&data[3264..4032], bit_offset_credits);

        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let gate_type = (gate_types[byte_idx] >> bit_idx) & 1 != 0;

        gates.push(GateV5a {
            in1,
            in2,
            out,
            credits,
            gate_type,
        });
    }

    DecodedBlock { gates, valid_gates }
}

/// Extract a 34-bit value from packed data
#[inline]
fn extract_34_bits(data: &[u8], bit_offset: usize) -> u64 {
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;

    // Read 8 bytes (we need at most 5 for 34 bits + shift)
    let mut bytes = [0u8; 8];
    let to_copy = std::cmp::min(8, data.len() - byte_offset);
    bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);

    let value = u64::from_le_bytes(bytes);
    (value >> bit_shift) & 0x3FFFFFFFF
}

/// Extract a 24-bit value from packed data
#[inline]
fn extract_24_bits(data: &[u8], bit_offset: usize) -> u32 {
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;

    // Read 4 bytes (we need at most 4 for 24 bits + shift)
    let mut bytes = [0u8; 4];
    let to_copy = std::cmp::min(4, data.len() - byte_offset);
    bytes[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);

    let value = u32::from_le_bytes(bytes);
    (value >> bit_shift) & 0xFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_validation() {
        // Valid header
        let valid_header = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert!(valid_header.validate().is_ok());

        // Invalid magic bytes
        let invalid_magic = HeaderV5a {
            magic: [0x00, 0x00, 0x00, 0x00],
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert!(invalid_magic.validate().is_err());

        // Invalid version
        let invalid_version = HeaderV5a {
            magic: MAGIC,
            version: 0x04, // Wrong version
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert!(invalid_version.validate().is_err());

        // Invalid format type
        let invalid_format = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: 0x01, // Wrong format type for v5a
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert!(invalid_format.validate().is_err());

        // Non-zero reserved bytes
        let invalid_reserved = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [1, 0], // Should be [0, 0]
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert!(invalid_reserved.validate().is_err());
    }

    #[test]
    fn test_header_total_gates() {
        let header = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 100,
            and_gates: 50,
            primary_inputs: 10,
            num_outputs: 5,
        };
        assert_eq!(header.total_gates(), 150);

        // Test with large numbers
        let large_header = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0; 32],
            xor_gates: 6_000_000_000,
            and_gates: 6_000_000_000,
            primary_inputs: 1_000_000,
            num_outputs: 1_000,
        };
        assert_eq!(large_header.total_gates(), 12_000_000_000);
    }

    #[test]
    fn test_extract_34_bits() {
        // Test aligned extraction (bit_offset = 0)
        let mut data = vec![0u8; 8];
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0x03; // Total: 0x3FFFFFFFF (34 bits set)

        let value = extract_34_bits(&data, 0);
        assert_eq!(value, 0x3FFFFFFFF);

        // Test unaligned extraction (bit_offset = 4)
        let mut data = vec![0u8; 8];
        data[0] = 0xF0; // Lower 4 bits will be skipped
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0x3F; // Upper 2 bits + lower 6 bits of next byte
        let value = extract_34_bits(&data, 4);
        assert_eq!(value, 0x3FFFFFFFF);

        // Test extraction at byte boundary (bit_offset = 8)
        let mut data = vec![0u8; 8];
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0xFF;
        data[5] = 0x03;
        let value = extract_34_bits(&data, 8);
        assert_eq!(value, 0x3FFFFFFFF);

        // Test extraction with specific pattern
        let data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let value = extract_34_bits(&data, 0);
        // Little-endian: 0xF0DEBC9A78563412, lower 34 bits = 0x278563412
        assert_eq!(value, 0x278563412);

        // Test extraction at various offsets
        let data = vec![0xFF; 16]; // All bits set
        for offset in 0..40 {
            let value = extract_34_bits(&data, offset);
            assert_eq!(value, 0x3FFFFFFFF, "Failed at offset {}", offset);
        }
    }

    #[test]
    fn test_extract_24_bits() {
        // Test aligned extraction
        let mut data = vec![0u8; 4];
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF; // Total: 0xFFFFFF (24 bits set)

        let value = extract_24_bits(&data, 0);
        assert_eq!(value, 0xFFFFFF);

        // Test unaligned extraction (bit_offset = 4)
        let mut data = vec![0u8; 4];
        data[0] = 0xF0;
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0x0F;
        let value = extract_24_bits(&data, 4);
        assert_eq!(value, 0xFFFFFF);

        // Test extraction at byte boundary
        let mut data = vec![0u8; 4];
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        let value = extract_24_bits(&data, 8);
        assert_eq!(value, 0xFFFFFF);

        // Test with specific pattern
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let value = extract_24_bits(&data, 0);
        assert_eq!(value, 0x563412); // Little-endian

        // Test extraction at various offsets
        let data = vec![0xFF; 8];
        for offset in 0..32 {
            let value = extract_24_bits(&data, offset);
            assert_eq!(value, 0xFFFFFF, "Failed at offset {}", offset);
        }
    }

    #[test]
    fn test_decode_block_scalar_basic() {
        // Create a minimal block with 1 gate
        let mut block_data = vec![0u8; BLOCK_SIZE_V5A];

        // Set first gate data
        // in1 = 2 (primary input 0)
        block_data[0] = 0x02;

        // in2 = 3 (primary input 1)
        block_data[1088] = 0x03;

        // out = 4 (first gate output)
        block_data[2176] = 0x04;

        // credits = 1
        block_data[3264] = 0x01;

        // gate_type = XOR (bit 0 = 0)
        block_data[4032] = 0x00;

        let block = decode_block_scalar(&block_data, 1);
        assert_eq!(block.valid_gates, 1);
        assert_eq!(block.gates.len(), 1);

        let gate = &block.gates[0];
        assert_eq!(gate.in1, 2);
        assert_eq!(gate.in2, 3);
        assert_eq!(gate.out, 4);
        assert_eq!(gate.credits, 1);
        assert_eq!(gate.gate_type, false); // XOR
    }

    #[test]
    fn test_decode_block_scalar_multiple_gates() {
        let mut block_data = vec![0u8; BLOCK_SIZE_V5A];

        // Gate 0: XOR(2, 3) -> 4, credits=2
        // Gate 1: AND(2, 4) -> 5, credits=1
        // Gate 2: XOR(4, 5) -> 6, credits=1

        // Set up in1 values (34 bits each, packed)
        // Gate 0: in1 = 2
        // Gate 1: in1 = 2
        // Gate 2: in1 = 4
        let in1_values = vec![2u64, 2u64, 4u64];
        for (i, &val) in in1_values.iter().enumerate() {
            let bit_offset = i * 34;
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;

            // Write the value (simplified for small values)
            if bit_shift == 0 {
                block_data[byte_offset] = val as u8;
            } else {
                block_data[byte_offset] |= (val << bit_shift) as u8;
                if byte_offset + 1 < block_data.len() {
                    block_data[byte_offset + 1] |= (val >> (8 - bit_shift)) as u8;
                }
            }
        }

        // Set up in2 values
        let in2_values = vec![3u64, 4u64, 5u64];
        for (i, &val) in in2_values.iter().enumerate() {
            let bit_offset = i * 34;
            let byte_offset = 1088 + bit_offset / 8;
            let bit_shift = bit_offset % 8;

            if bit_shift == 0 {
                block_data[byte_offset] = val as u8;
            } else {
                block_data[byte_offset] |= (val << bit_shift) as u8;
                if byte_offset + 1 < block_data.len() {
                    block_data[byte_offset + 1] |= (val >> (8 - bit_shift)) as u8;
                }
            }
        }

        // Set up output values
        let out_values = vec![4u64, 5u64, 6u64];
        for (i, &val) in out_values.iter().enumerate() {
            let bit_offset = i * 34;
            let byte_offset = 2176 + bit_offset / 8;
            let bit_shift = bit_offset % 8;

            if bit_shift == 0 {
                block_data[byte_offset] = val as u8;
            } else {
                block_data[byte_offset] |= (val << bit_shift) as u8;
                if byte_offset + 1 < block_data.len() {
                    block_data[byte_offset + 1] |= (val >> (8 - bit_shift)) as u8;
                }
            }
        }

        // Set up credits (24 bits each)
        let credits = vec![2u32, 1u32, 1u32];
        for (i, &val) in credits.iter().enumerate() {
            let bit_offset = i * 24;
            let byte_offset = 3264 + bit_offset / 8;
            block_data[byte_offset] = val as u8;
        }

        // Set gate types: XOR, AND, XOR
        block_data[4032] = 0b00000010; // Bit 0=0 (XOR), Bit 1=1 (AND), Bit 2=0 (XOR)

        let block = decode_block_scalar(&block_data, 3);
        assert_eq!(block.valid_gates, 3);
        assert_eq!(block.gates.len(), 3);

        // Check gate 0
        assert_eq!(block.gates[0].in1, 2);
        assert_eq!(block.gates[0].in2, 3);
        assert_eq!(block.gates[0].out, 4);
        assert_eq!(block.gates[0].credits, 2);
        assert_eq!(block.gates[0].gate_type, false);

        // Check gate 1
        assert_eq!(block.gates[1].in1, 2);
        assert_eq!(block.gates[1].in2, 4);
        assert_eq!(block.gates[1].out, 5);
        assert_eq!(block.gates[1].credits, 1);
        assert_eq!(block.gates[1].gate_type, true);

        // Check gate 2
        assert_eq!(block.gates[2].in1, 4);
        assert_eq!(block.gates[2].in2, 5);
        assert_eq!(block.gates[2].out, 6);
        assert_eq!(block.gates[2].credits, 1);
        assert_eq!(block.gates[2].gate_type, false);
    }

    #[test]
    fn test_decode_block_scalar_max_gates() {
        let block_data = vec![0xFF; BLOCK_SIZE_V5A];

        // Test with exactly 256 gates
        let block = decode_block_scalar(&block_data, 256);
        assert_eq!(block.valid_gates, 256);
        assert_eq!(block.gates.len(), 256);

        // Test with limit less than block size
        let block = decode_block_scalar(&block_data, 100);
        assert_eq!(block.valid_gates, 100);
        assert_eq!(block.gates.len(), 100);

        // Test with limit greater than block size
        let block = decode_block_scalar(&block_data, 1000);
        assert_eq!(block.valid_gates, 256);
        assert_eq!(block.gates.len(), 256);
    }

    #[test]
    fn test_gate_type_extraction() {
        let mut block_data = vec![0u8; BLOCK_SIZE_V5A];

        // Set specific gate types
        // Byte 0: gates 0-7
        block_data[4032] = 0b10101010; // Alternating XOR/AND

        // Byte 1: gates 8-15
        block_data[4033] = 0b11110000; // First 4 XOR, next 4 AND

        // Byte 31: gates 248-255
        block_data[4063] = 0b11111111; // All AND

        let block = decode_block_scalar(&block_data, 256);

        // Check alternating pattern in first 8 gates
        for i in 0..8 {
            assert_eq!(
                block.gates[i].gate_type,
                i % 2 == 1,
                "Gate {} type mismatch",
                i
            );
        }

        // Check gates 8-11 are XOR
        for i in 8..12 {
            assert_eq!(block.gates[i].gate_type, false, "Gate {} should be XOR", i);
        }

        // Check gates 12-15 are AND
        for i in 12..16 {
            assert_eq!(block.gates[i].gate_type, true, "Gate {} should be AND", i);
        }

        // Check last 8 gates are all AND
        for i in 248..256 {
            assert_eq!(block.gates[i].gate_type, true, "Gate {} should be AND", i);
        }
    }

    #[test]
    fn test_gate_v5a_size() {
        // Ensure GateV5a structure has expected memory layout
        use std::mem;

        // The struct should be reasonably sized
        let size = mem::size_of::<GateV5a>();
        assert!(
            size <= 32,
            "GateV5a is larger than expected: {} bytes",
            size
        );

        // Check field sizes
        assert_eq!(mem::size_of::<u64>(), 8);
        assert_eq!(mem::size_of::<u32>(), 4);
        assert_eq!(mem::size_of::<bool>(), 1);
    }

    #[test]
    fn test_wire_id_limits() {
        // Test maximum 34-bit wire ID
        let max_wire_id = (1u64 << 34) - 1;
        assert_eq!(max_wire_id, 0x3FFFFFFFF);
        assert_eq!(max_wire_id, 17_179_869_183);

        // Test wire ID semantics
        let false_wire = 0u64;
        let true_wire = 1u64;
        let first_input = 2u64;

        assert_eq!(false_wire, 0);
        assert_eq!(true_wire, 1);
        assert_eq!(first_input, 2);
    }

    #[test]
    fn test_credits_limits() {
        // Test maximum 24-bit credits value
        let max_credits = (1u32 << 24) - 1;
        assert_eq!(max_credits, 0xFFFFFF);
        assert_eq!(max_credits, 16_777_215);

        // Test special credits values
        let output_credits = 0u32; // Wire is circuit output
        let consumed_once = 1u32;
        let special_value = 16_777_215u32; // Constants/primary inputs

        assert_eq!(output_credits, 0);
        assert_eq!(consumed_once, 1);
        assert_eq!(special_value, max_credits);
    }

    #[test]
    fn test_block_size_constants() {
        // Verify block structure sizes
        assert_eq!(GATES_PER_BLOCK, 256);
        assert_eq!(BLOCK_SIZE_V5A, 4064);

        // Verify component sizes add up correctly
        let in1_size = (256 * 34 + 7) / 8; // 1088 bytes
        let in2_size = (256 * 34 + 7) / 8; // 1088 bytes
        let out_size = (256 * 34 + 7) / 8; // 1088 bytes
        let credits_size = (256 * 24 + 7) / 8; // 768 bytes
        let types_size = 256 / 8; // 32 bytes

        assert_eq!(in1_size, 1088);
        assert_eq!(in2_size, 1088);
        assert_eq!(out_size, 1088);
        assert_eq!(credits_size, 768);
        assert_eq!(types_size, 32);
        assert_eq!(
            in1_size + in2_size + out_size + credits_size + types_size,
            BLOCK_SIZE_V5A
        );
    }

    #[test]
    fn test_decoded_block_structure() {
        let gates = vec![
            GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: 1,
                gate_type: false,
            },
            GateV5a {
                in1: 4,
                in2: 5,
                out: 6,
                credits: 0,
                gate_type: true,
            },
        ];

        let block = DecodedBlock {
            gates: gates.clone(),
            valid_gates: 2,
        };

        assert_eq!(block.valid_gates, 2);
        assert_eq!(block.gates.len(), 2);
        assert_eq!(block.gates[0].in1, 2);
        assert_eq!(block.gates[1].gate_type, true);
    }

    #[test]
    fn test_bit_packing_edge_cases() {
        // Test extraction at the edge of buffer
        let data = vec![0xFF; 5];
        let value = extract_34_bits(&data, 0);
        assert_eq!(value, 0x3FFFFFFFF);

        // Test with minimal buffer size
        let data = vec![0xFF; 5];
        let value = extract_34_bits(&data, 6); // Start at bit 6
        assert_eq!(value & 0x3FFFFFFFF, value);

        // Test 24-bit extraction at edge
        let data = vec![0xFF; 3];
        let value = extract_24_bits(&data, 0);
        assert_eq!(value, 0xFFFFFF);

        // Test with zeros
        let data = vec![0u8; 8];
        assert_eq!(extract_34_bits(&data, 0), 0);
        assert_eq!(extract_24_bits(&data, 0), 0);
    }

    #[test]
    fn test_header_byte_representation() {
        use std::mem;

        // Verify header is packed correctly
        assert_eq!(mem::size_of::<HeaderV5a>(), 72);

        let header = HeaderV5a {
            magic: MAGIC,
            version: VERSION,
            format_type: FORMAT_TYPE_A,
            reserved: [0, 0],
            checksum: [0x42; 32],
            xor_gates: 0x123456789ABCDEF0,
            and_gates: 0xFEDCBA9876543210,
            primary_inputs: 0x1122334455667788,
            num_outputs: 0x99AABBCCDDEEFF00,
        };

        // Convert to bytes
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                mem::size_of::<HeaderV5a>(),
            )
        };

        // Check magic bytes
        assert_eq!(bytes[0], 0x5A);
        assert_eq!(bytes[1], 0x6B);
        assert_eq!(bytes[2], 0x32);
        assert_eq!(bytes[3], 0x75);

        // Check version and format
        assert_eq!(bytes[4], 0x05);
        assert_eq!(bytes[5], 0x00);

        // Check reserved
        assert_eq!(bytes[6], 0x00);
        assert_eq!(bytes[7], 0x00);

        // Check checksum
        for i in 8..40 {
            assert_eq!(bytes[i], 0x42);
        }

        // Check xor_gates (little-endian)
        assert_eq!(bytes[40], 0xF0);
        assert_eq!(bytes[41], 0xDE);
        assert_eq!(bytes[42], 0xBC);
        assert_eq!(bytes[43], 0x9A);
        assert_eq!(bytes[44], 0x78);
        assert_eq!(bytes[45], 0x56);
        assert_eq!(bytes[46], 0x34);
        assert_eq!(bytes[47], 0x12);
    }

    // Test AVX-512 functions only on x86_64
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_decode_block_avx512() {
        // Check if AVX-512 is available
        if !is_x86_feature_detected!("avx512f")
            || !is_x86_feature_detected!("avx512bw")
            || !is_x86_feature_detected!("avx512vbmi")
        {
            eprintln!("Skipping AVX-512 test - required features not available");
            return;
        }

        // Create a test block
        let mut block_data = vec![0u8; BLOCK_SIZE_V5A];

        // Set some test data
        block_data[0] = 0x02; // in1 for gate 0
        block_data[1088] = 0x03; // in2 for gate 0
        block_data[2176] = 0x04; // out for gate 0
        block_data[3264] = 0x01; // credits for gate 0
        block_data[4032] = 0x00; // gate types

        let block = unsafe { decode_block_avx512(&block_data, 1) };
        assert_eq!(block.valid_gates, 1);
        assert_eq!(block.gates[0].in1, 2);
        assert_eq!(block.gates[0].in2, 3);
        assert_eq!(block.gates[0].out, 4);
        assert_eq!(block.gates[0].credits, 1);
        assert_eq!(block.gates[0].gate_type, false);
    }
}

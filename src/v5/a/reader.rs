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
const MAGIC: [u8; 4] = [0x5A, 0x6B, 0x32, 0x75];

/// Version number for v5
const VERSION: u8 = 0x05;

/// Format type for v5a
const FORMAT_TYPE_A: u8 = 0x00;

/// Gates per block in v5a
const GATES_PER_BLOCK: usize = 256;

/// Size of a v5a block in bytes
const BLOCK_SIZE_V5A: usize = 4064;

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
    mut current_buffer: AlignedBuffer,
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

/// Decode a v5a block using scalar code (non-x86_64 fallback)
#[cfg(not(target_arch = "x86_64"))]
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
    fn test_extract_bits() {
        // Test 34-bit extraction
        let mut data = vec![0u8; 8];
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0x03; // Total: 0x3FFFFFFFF (34 bits set)

        let value = extract_34_bits(&data, 0);
        assert_eq!(value, 0x3FFFFFFFF);

        // Test 24-bit extraction
        let mut data = vec![0u8; 4];
        data[0] = 0xFF;
        data[1] = 0xFF;
        data[2] = 0xFF; // Total: 0xFFFFFF (24 bits set)

        let value = extract_24_bits(&data, 0);
        assert_eq!(value, 0xFFFFFF);
    }
}

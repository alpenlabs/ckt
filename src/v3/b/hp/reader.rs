use cynosure::hints::{likely, prefetch_read_data, unlikely};
use monoio::fs::File;
use std::io::{Error, ErrorKind, Result};

use crate::v3::b::{
    AndGates, CircuitHeader, Gate, Level, WireLocation, XorGates,
    varints::{FlaggedVarInt, StandardVarInt},
};
use crate::v3::{FormatType, VERSION};

/// High performance async reader for CKT v3b format using monoio
pub struct CircuitReader {
    file: File,
    /// Buffer for efficient reading
    buffer: Vec<u8>,
    /// Current position in buffer
    buffer_offset: usize,
    /// Valid data end in buffer
    max_valid_bytes: usize,
    /// Current level being read
    current_level: u32,
    /// Circuit header
    header: CircuitHeader,
    /// Total bytes in the file
    total_bytes: u64,
    /// How many bytes we've read from file
    bytes_read: u64,
    /// Number of levels read so far
    levels_read: usize,
    /// Total gates read so far
    gates_read: u64,
}

impl CircuitReader {
    /// Create a new v3b reader
    pub async fn new(file: File, max_buffer_size: usize) -> Result<Self> {
        let len = file.metadata().await?.len();

        // Read header (58 bytes)
        let (res, header_bytes) = file
            .read_exact_at(Vec::with_capacity(CircuitHeader::SIZE), 0)
            .await;
        res?;

        if unlikely(header_bytes.len() != CircuitHeader::SIZE) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Incomplete header read",
            ));
        }

        // Validate version and type
        if unlikely(header_bytes[0] != VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", header_bytes[0]),
            ));
        }

        if unlikely(header_bytes[1] != FormatType::TypeB.to_byte()) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid format type for v3b: {}", header_bytes[1]),
            ));
        }

        // Extract checksum
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&header_bytes[2..34]);

        // Parse remaining header fields
        let xor_gates = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[42..50].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[50..58].try_into().unwrap());

        let header = CircuitHeader {
            version: header_bytes[0],
            format_type: header_bytes[1],
            checksum,
            xor_gates,
            and_gates,
            primary_inputs,
        };

        Ok(Self {
            file,
            buffer: vec![0; max_buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            current_level: 1, // Start at level 1 (level 0 is implicit)
            header,
            total_bytes: len,
            bytes_read: CircuitHeader::SIZE as u64,
            levels_read: 0,
            gates_read: 0,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeader {
        &self.header
    }

    /// Get current level
    pub fn current_level(&self) -> u32 {
        self.current_level
    }

    /// Get number of levels read so far
    pub fn levels_read(&self) -> usize {
        self.levels_read
    }

    /// Get total gates read so far
    pub fn gates_read(&self) -> u64 {
        self.gates_read
    }

    /// Read the next level in AoS (Array of Structures) format
    pub async fn read_level(&mut self) -> Result<Option<Level>> {
        if unlikely(self.gates_read >= self.header.total_gates()) {
            return Ok(None);
        }

        // Ensure we have data available
        if unlikely(self.buffer_offset >= self.max_valid_bytes) && !self.fill_buffer().await? {
            return Ok(None);
        }

        // Read level header
        let num_xor_flagged = self.read_flagged_varint().await?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        let num_and = if has_and_gates {
            self.read_standard_varint().await?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut level =
            Level::with_capacity(self.current_level, num_xor as usize, num_and as usize);

        // Read XOR gates
        for _ in 0..num_xor {
            let gate = self.read_gate().await?;
            level.xor_gates.push(gate);
            self.gates_read += 1;
        }

        // Read AND gates
        for _ in 0..num_and {
            let gate = self.read_gate().await?;
            level.and_gates.push(gate);
            self.gates_read += 1;
        }

        self.levels_read += 1;
        self.current_level += 1;

        // Prefetch next data if available
        if likely(self.buffer_offset < self.max_valid_bytes) {
            unsafe {
                prefetch_read_data(self.buffer.as_ptr().add(self.buffer_offset), 0);
            }
        }

        Ok(Some(level))
    }

    /// Read the next level in SoA (Structure of Arrays) format for vectorization
    pub async fn read_soa_level<const N: usize>(
        &mut self,
    ) -> Result<Option<(XorGates<N>, AndGates<N>)>> {
        if unlikely(self.gates_read >= self.header.total_gates()) {
            return Ok(None);
        }

        // Ensure we have data available
        if unlikely(self.buffer_offset >= self.max_valid_bytes) && !self.fill_buffer().await? {
            return Ok(None);
        }

        // Read level header
        let num_xor_flagged = self.read_flagged_varint().await?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        let num_and = if has_and_gates {
            self.read_standard_varint().await?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        // Check if level fits in arrays
        if num_xor as usize > N || num_and as usize > N {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Level too large for SoA arrays: {} XOR, {} AND gates (max {})",
                    num_xor, num_and, N
                ),
            ));
        }

        let mut xor_gates = XorGates::<N>::with_capacity(num_xor as usize);
        let mut and_gates = AndGates::<N>::with_capacity(num_and as usize);

        // Read XOR gates into SoA
        for _ in 0..num_xor {
            let gate = self.read_gate().await?;
            xor_gates.input1s.push(gate.in1);
            xor_gates.input2s.push(gate.in2);
            xor_gates.count += 1;
            self.gates_read += 1;
        }

        // Read AND gates into SoA
        for _ in 0..num_and {
            let gate = self.read_gate().await?;
            and_gates.input1s.push(gate.in1);
            and_gates.input2s.push(gate.in2);
            and_gates.count += 1;
            self.gates_read += 1;
        }

        self.levels_read += 1;
        self.current_level += 1;

        Ok(Some((xor_gates, and_gates)))
    }

    /// Read a single gate with implicit output
    async fn read_gate(&mut self) -> Result<Gate> {
        // Decode input1 wire location
        let (level1, index1) = self.read_wire_location().await?;
        let input1 = WireLocation::new(level1, index1);

        // Decode input2 wire location
        let (level2, index2) = self.read_wire_location().await?;
        let input2 = WireLocation::new(level2, index2);

        // Output is implicit (current wire counter)
        Ok(Gate::new(input1, input2))
    }

    /// Read and decode a wire location
    async fn read_wire_location(&mut self) -> Result<(u32, u32)> {
        // Ensure we have enough data for worst case (1 + 8 + 8 = 17 bytes)
        self.ensure_bytes_available(17).await?;

        // Decode directly from buffer
        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (level, index, consumed) =
            FlaggedVarInt::decode_wire_location(buffer_slice, self.current_level)?;

        self.buffer_offset += consumed;

        Ok((level, index))
    }

    /// Read a standard varint
    async fn read_standard_varint(&mut self) -> Result<u64> {
        self.ensure_bytes_available(8).await?; // Max StandardVarInt size

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = StandardVarInt::decode(buffer_slice)?;

        self.buffer_offset += consumed;

        Ok(varint.value())
    }

    /// Read a flagged varint
    async fn read_flagged_varint(&mut self) -> Result<FlaggedVarInt> {
        self.ensure_bytes_available(8).await?; // Max FlaggedVarInt size

        let buffer_slice = &self.buffer[self.buffer_offset..self.max_valid_bytes];
        let (varint, consumed) = FlaggedVarInt::decode(buffer_slice)?;

        self.buffer_offset += consumed;

        Ok(varint)
    }

    /// Ensure at least `needed` bytes are available in buffer
    async fn ensure_bytes_available(&mut self, needed: usize) -> Result<()> {
        let available = self.max_valid_bytes - self.buffer_offset;

        if likely(available >= needed) {
            return Ok(());
        }

        // Compact buffer if needed
        if self.buffer_offset > 0 {
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.max_valid_bytes -= self.buffer_offset;
            self.buffer_offset = 0;
        }

        // Read more data
        self.fill_buffer().await?;

        // Check again
        let available = self.max_valid_bytes - self.buffer_offset;
        if available < needed {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", needed, available),
            ));
        }

        Ok(())
    }

    /// Fill buffer with more data
    async fn fill_buffer(&mut self) -> Result<bool> {
        if unlikely(self.bytes_read >= self.total_bytes) {
            return Ok(false);
        }

        let buffer_space = self.buffer.len() - self.max_valid_bytes;
        let remaining_in_file = self.total_bytes - self.bytes_read;
        let to_read = buffer_space.min(remaining_in_file as usize);

        if to_read == 0 {
            return Ok(self.max_valid_bytes > self.buffer_offset);
        }

        // Read from file
        let read_buffer =
            self.buffer[self.max_valid_bytes..self.max_valid_bytes + to_read].to_vec();
        let (res, returned_buffer) = self.file.read_at(read_buffer, self.bytes_read).await;
        let bytes_read = res?;

        if bytes_read > 0 {
            // Copy read data back to buffer
            self.buffer[self.max_valid_bytes..self.max_valid_bytes + bytes_read]
                .copy_from_slice(&returned_buffer[..bytes_read]);
            self.max_valid_bytes += bytes_read;
            self.bytes_read += bytes_read as u64;
        }

        Ok(bytes_read > 0)
    }
}

/// Async function to verify the BLAKE3 checksum of a v3b file
/// Returns the checksum if verification succeeds
pub async fn verify_checksum_async(file: File) -> Result<[u8; 32]> {
    use blake3::Hasher;

    let len = file.metadata().await?.len();

    // Read header
    let (res, header_bytes) = file
        .read_exact_at(Vec::with_capacity(CircuitHeader::SIZE), 0)
        .await;
    res?;

    // Validate version and type
    if header_bytes[0] != VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid version: {}", header_bytes[0]),
        ));
    }

    if header_bytes[1] != FormatType::TypeB.to_byte() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid format type: {}", header_bytes[1]),
        ));
    }

    // Extract stored checksum
    let mut stored_checksum = [0u8; 32];
    stored_checksum.copy_from_slice(&header_bytes[2..34]);

    // Save header fields after checksum for hashing at the end
    let header_fields_after_checksum = header_bytes[34..].to_vec();

    // Hash all gate data first
    let mut hasher = Hasher::new();
    let mut offset = CircuitHeader::SIZE as u64;
    let buffer = vec![0u8; 1024 * 1024]; // 1MB buffer

    while offset < len {
        let to_read = buffer.len().min((len - offset) as usize);
        let (res, read_buffer) = file.read_at(buffer[..to_read].to_vec(), offset).await;
        let bytes_read = res?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&read_buffer[..bytes_read]);
        offset += bytes_read as u64;
    }

    // Then hash the header fields (after checksum)
    hasher.update(&header_fields_after_checksum);

    // Compare checksums
    let computed_hash = hasher.finalize();
    if computed_hash.as_bytes() == &stored_checksum {
        Ok(stored_checksum)
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "Checksum verification failed",
        ))
    }
}

use cynosure::hints::{likely, prefetch_read_data, unlikely};
use monoio::fs::File;
use std::io::{Error, ErrorKind, Result};

use crate::v2::{AndGates, CircuitHeaderV2, Gate, Level, XorGates, varints::*};

/// High performance file reader for CKT v2 format using monoio
pub struct CircuitReaderV2 {
    file: File,
    /// Buffer used for file reads with monoio
    buffer: Vec<u8>,
    /// Current position in the buffer
    buffer_offset: usize,
    /// How many valid bytes are in the buffer
    max_valid_bytes: usize,
    /// Current wire counter for decoding relative wire IDs
    wire_counter: u64,
    /// Circuit header
    header: CircuitHeaderV2,
    /// Total bytes in the file
    total_bytes: u64,
    /// How many bytes we've read from file
    bytes_read: u64,
    /// Number of levels read so far
    levels_read: usize,
    /// Total gates read so far
    gates_read: u64,
}

impl CircuitReaderV2 {
    /// Create a new v2 reader
    pub async fn new(file: File, max_buffer_size: usize) -> Result<Self> {
        let len = file.metadata().await?.len();

        // Read header (25 bytes: 1 + 8 + 8 + 8)
        let (res, header_bytes) = file.read_exact_at(Vec::with_capacity(25), 0).await;
        res?;

        if unlikely(header_bytes.len() != 25) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Incomplete header read",
            ));
        }

        let version = header_bytes[0];
        if unlikely(version != crate::v2::VERSION) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported version: {}", version),
            ));
        }

        let xor_gates = u64::from_le_bytes(header_bytes[1..9].try_into().unwrap());
        let and_gates = u64::from_le_bytes(header_bytes[9..17].try_into().unwrap());
        let primary_inputs = u64::from_le_bytes(header_bytes[17..25].try_into().unwrap());

        let header = CircuitHeaderV2::with_counts(xor_gates, and_gates, primary_inputs);

        Ok(Self {
            file,
            buffer: vec![0; max_buffer_size],
            buffer_offset: 0,
            max_valid_bytes: 0,
            wire_counter: primary_inputs,
            header,
            total_bytes: len,
            bytes_read: 25, // Already read header
            levels_read: 0,
            gates_read: 0,
        })
    }

    /// Get the circuit header
    pub fn header(&self) -> &CircuitHeaderV2 {
        &self.header
    }

    /// Get current wire counter
    pub fn wire_counter(&self) -> u64 {
        self.wire_counter
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

        // Read level header (num_xor as FlaggedVarInt with AND gate flag)
        let num_xor_flagged = self.read_flagged_varint().await?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        // Only read num_and if flag indicates AND gates are present
        let num_and = if has_and_gates {
            self.read_standard_varint().await?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut level = Level::with_capacity(num_xor as usize, num_and as usize);

        // Read XOR gates
        for _ in 0..num_xor {
            let gate = self.read_gate().await?;
            level.xor_gates.push(gate);
        }

        // Read AND gates
        for _ in 0..num_and {
            let gate = self.read_gate().await?;
            level.and_gates.push(gate);
        }

        self.levels_read += 1;
        self.gates_read += num_xor + num_and;

        Ok(Some(level))
    }

    /// Read the next level in SoA (Structure of Arrays) format for vectorization
    pub async fn read_soa_level<const N: usize>(
        &mut self,
    ) -> Result<Option<(XorGates<N>, AndGates<N>)>> {
        if unlikely(self.gates_read >= self.header.total_gates()) {
            return Ok(None);
        }

        // Read level header (num_xor as FlaggedVarInt with AND gate flag)
        let num_xor_flagged = self.read_flagged_varint().await?;
        let num_xor = num_xor_flagged.value();
        let has_and_gates = num_xor_flagged.flag();

        // Only read num_and if flag indicates AND gates are present
        let num_and = if has_and_gates {
            self.read_standard_varint().await?
        } else {
            0
        };

        if unlikely(num_xor == 0 && num_and == 0) {
            return Ok(None);
        }

        let mut xor_gates = XorGates::<N>::new();
        let mut and_gates = AndGates::<N>::new();

        // Read XOR gates into SoA format
        let xor_count = (num_xor as usize).min(N);
        for i in 0..xor_count {
            let gate = self.read_gate().await?;
            xor_gates.input1s[i] = gate.input1;
            xor_gates.input2s[i] = gate.input2;
            xor_gates.outputs[i] = gate.output;
        }
        xor_gates.count = xor_count;

        // Read AND gates into SoA format
        let and_count = (num_and as usize).min(N);
        for i in 0..and_count {
            let gate = self.read_gate().await?;
            and_gates.input1s[i] = gate.input1;
            and_gates.input2s[i] = gate.input2;
            and_gates.outputs[i] = gate.output;
        }
        and_gates.count = and_count;

        self.levels_read += 1;
        self.gates_read += num_xor + num_and;

        Ok(Some((xor_gates, and_gates)))
    }

    /// Read a single gate and advance wire counter
    async fn read_gate(&mut self) -> Result<Gate> {
        // Read input1 as FlaggedVarInt
        let input1_varint = self.read_flagged_varint().await?;
        let input1 = input1_varint.decode_to_absolute(self.wire_counter);

        // Read input2 as FlaggedVarInt
        let input2_varint = self.read_flagged_varint().await?;
        let input2 = input2_varint.decode_to_absolute(self.wire_counter);

        // Read output as FlaggedVarInt
        let output_varint = self.read_flagged_varint().await?;
        let output = output_varint.decode_to_absolute(self.wire_counter);

        // Advance wire counter (output should equal current counter)
        self.wire_counter += 1;

        Ok(Gate::new(input1, input2, output))
    }

    /// Read a StandardVarInt from the buffer
    async fn read_standard_varint(&mut self) -> Result<u64> {
        // First ensure we have at least 1 byte to read the length
        self.ensure_bytes_available(1).await?;

        // Determine the length from the first byte
        let first_byte = self.buffer[self.buffer_offset];
        let length = match first_byte >> 6 {
            0b00 => 1, // Most common case for small values
            0b01 => 2,
            0b10 => 4,
            0b11 => 8, // Least common case
            _ => unreachable!(),
        };

        // Now ensure we have that many bytes
        self.ensure_bytes_available(length).await?;

        let buffer_slice = &self.buffer[self.buffer_offset..];
        let (varint, bytes_consumed) = StandardVarInt::decode(buffer_slice)?;
        self.buffer_offset += bytes_consumed;

        Ok(varint.value())
    }

    /// Read a FlaggedVarInt from the buffer
    async fn read_flagged_varint(&mut self) -> Result<FlaggedVarInt> {
        // First ensure we have at least 1 byte to read the length
        self.ensure_bytes_available(1).await?;

        // Determine the length from the first byte
        let first_byte = self.buffer[self.buffer_offset];
        let length = match first_byte >> 6 {
            0b00 => 1, // Most common case for relative wire IDs
            0b01 => 2,
            0b10 => 4,
            0b11 => 8, // Least common case
            _ => unreachable!(),
        };

        // Now ensure we have that many bytes
        self.ensure_bytes_available(length).await?;

        let buffer_slice = &self.buffer[self.buffer_offset..];
        let (varint, bytes_consumed) = FlaggedVarInt::decode(buffer_slice)?;
        self.buffer_offset += bytes_consumed;

        Ok(varint)
    }

    /// Ensure at least `needed` bytes are available in the buffer
    async fn ensure_bytes_available(&mut self, needed: usize) -> Result<()> {
        // Fast path: already have enough bytes
        if likely(self.buffer_offset + needed <= self.max_valid_bytes) {
            return Ok(());
        }

        // Check if we need to refill buffer
        if unlikely(self.buffer_offset == self.max_valid_bytes) {
            if unlikely(!self.fill_buffer().await?) {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Unexpected end of data",
                ));
            }
        }

        // Check if we now have enough after refill
        if likely(self.buffer_offset + needed <= self.max_valid_bytes) {
            return Ok(());
        }

        // Compact buffer if needed
        if likely(self.buffer_offset > 0) {
            let remaining = self.max_valid_bytes - self.buffer_offset;
            self.buffer
                .copy_within(self.buffer_offset..self.max_valid_bytes, 0);
            self.buffer_offset = 0;
            self.max_valid_bytes = remaining;

            // Try filling again after compact
            self.fill_buffer().await?;
        }

        if unlikely(self.buffer_offset + needed > self.max_valid_bytes) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "Need {} bytes but only {} available",
                    needed,
                    self.max_valid_bytes - self.buffer_offset
                ),
            ));
        }

        Ok(())
    }

    /// Fill buffer with more data from file
    async fn fill_buffer(&mut self) -> Result<bool> {
        if unlikely(self.bytes_read >= self.total_bytes) {
            return Ok(false);
        }

        let buf = std::mem::take(&mut self.buffer);
        let (res, returned_buf) = self.file.read_at(buf, self.bytes_read).await;
        let bytes_read = res?;

        if unlikely(bytes_read == 0) {
            return Ok(false);
        }

        self.buffer = returned_buf;
        self.max_valid_bytes = bytes_read;
        self.bytes_read += bytes_read as u64;
        self.buffer_offset = 0;

        // Prefetch next data if buffer isn't full
        if likely(bytes_read == self.buffer.len() && self.bytes_read < self.total_bytes) {
            unsafe { prefetch_read_data(self.buffer.as_ptr(), 0) };
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::hp::writer::CircuitWriterV2;
    use monoio::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_reader_basic() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        // Write a test circuit
        {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file_path)
                .await?;

            let mut writer = CircuitWriterV2::new(file, 4).await?; // 4 primary inputs

            let mut level = Level::new();
            level.xor_gates.push(Gate::new(0, 1, 4)); // XOR(0,1) -> 4
            level.xor_gates.push(Gate::new(2, 3, 5)); // XOR(2,3) -> 5
            level.and_gates.push(Gate::new(4, 5, 6)); // AND(4,5) -> 6

            writer.write_level(&level).await?;
            writer.finish().await?;
        }

        // Read it back
        {
            let file = OpenOptions::new().read(true).open(file_path).await?;
            let mut reader = CircuitReaderV2::new(file, 64 * 1024).await?;

            assert_eq!(reader.header().xor_gates, 2);
            assert_eq!(reader.header().and_gates, 1);
            assert_eq!(reader.header().primary_inputs, 4);

            let level = reader.read_level().await?.unwrap();
            assert_eq!(level.xor_gates.len(), 2);
            assert_eq!(level.and_gates.len(), 1);

            assert_eq!(level.xor_gates[0], Gate::new(0, 1, 4));
            assert_eq!(level.xor_gates[1], Gate::new(2, 3, 5));
            assert_eq!(level.and_gates[0], Gate::new(4, 5, 6));

            // Should be at end
            assert!(reader.read_level().await?.is_none());
        }

        Ok(())
    }

    #[monoio::test]
    async fn test_reader_soa() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        // Write a test circuit
        {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file_path)
                .await?;

            let mut writer = CircuitWriterV2::new(file, 2).await?; // 2 primary inputs

            let mut level = Level::new();
            level.xor_gates.push(Gate::new(0, 1, 2)); // XOR(0,1) -> 2
            level.and_gates.push(Gate::new(0, 2, 3)); // AND(0,2) -> 3

            writer.write_level(&level).await?;
            writer.finish().await?;
        }

        // Read it back in SoA format
        {
            let file = OpenOptions::new().read(true).open(file_path).await?;
            let mut reader = CircuitReaderV2::new(file, 64 * 1024).await?;

            let (xor_gates, and_gates) = reader.read_soa_level::<8>().await?.unwrap();

            assert_eq!(xor_gates.count, 1);
            assert_eq!(xor_gates.input1s[0], 0);
            assert_eq!(xor_gates.input2s[0], 1);
            assert_eq!(xor_gates.outputs[0], 2);

            assert_eq!(and_gates.count, 1);
            assert_eq!(and_gates.input1s[0], 0);
            assert_eq!(and_gates.input2s[0], 2);
            assert_eq!(and_gates.outputs[0], 3);
        }

        Ok(())
    }
}

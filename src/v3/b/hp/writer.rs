use blake3::Hasher;
use cynosure::hints::{likely, unlikely};
use monoio::fs::File;
use std::io::Result;

use crate::v3::{CircuitStats, FormatType, VERSION};
use crate::{
    GateType,
    v3::b::{
        CircuitHeader, Gate, Level,
        varints::{FlaggedVarInt, StandardVarInt},
    },
};

/// High-performance async writer for CKT v3b format using monoio
pub struct CircuitWriter {
    file: File,
    buffer: Vec<u8>,
    wire_counter: u64,
    current_level: u32,
    primary_inputs: u64,
    xor_gates_written: u64,
    and_gates_written: u64,
    bytes_written: u64,
    level_sizes: Vec<usize>,
    hasher: Hasher,
}

impl CircuitWriter {
    /// Create a new v3b writer with the given primary inputs count
    pub async fn new(file: File, primary_inputs: u64) -> Result<Self> {
        // Write placeholder header (58 bytes)
        let mut placeholder = vec![0u8; CircuitHeader::SIZE];
        placeholder[0] = VERSION;
        placeholder[1] = FormatType::TypeB.to_byte();
        // Rest are zeros (checksum, counts)

        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        Ok(Self {
            file,
            buffer: Vec::with_capacity(1024 * 1024), // 1MB buffer
            wire_counter: primary_inputs,
            current_level: 1, // Start at level 1 (level 0 is implicit)
            primary_inputs,
            xor_gates_written: 0,
            and_gates_written: 0,
            bytes_written: CircuitHeader::SIZE as u64,
            level_sizes: vec![primary_inputs as usize], // Level 0 size
            hasher: Hasher::new(),
        })
    }

    /// Write a complete level (XOR gates followed by AND gates)
    pub async fn write_level(&mut self, level: &Level) -> Result<()> {
        if unlikely(level.is_empty()) {
            return Ok(());
        }

        // Write level header: num_xor with AND gate flag, optionally num_and
        let has_and_gates = !level.and_gates.is_empty();
        let num_xor_flagged =
            FlaggedVarInt::with_flag(level.xor_gates.len() as u64, has_and_gates)?;
        let mut temp_buf = [0u8; 8]; // Max FlaggedVarInt size
        let bytes_used = num_xor_flagged.encode(&mut temp_buf)?;
        self.buffer.extend_from_slice(&temp_buf[..bytes_used]);
        self.hasher.update(&temp_buf[..bytes_used]);

        // Only write num_and if there are AND gates (flag optimization)
        if has_and_gates {
            let num_and_varint = StandardVarInt::new(level.and_gates.len() as u64)?;
            let bytes_used = num_and_varint.encode(&mut temp_buf)?;
            self.buffer.extend_from_slice(&temp_buf[..bytes_used]);
            self.hasher.update(&temp_buf[..bytes_used]);
        }

        // Write all XOR gates
        for gate in &level.xor_gates {
            self.write_gate(gate, GateType::XOR).await?;
        }

        // Write all AND gates
        for gate in &level.and_gates {
            self.write_gate(gate, GateType::AND).await?;
        }

        // Track level size
        let level_size = level.xor_gates.len() + level.and_gates.len();
        self.level_sizes.push(level_size);
        self.current_level += 1;

        // Flush buffer if it's getting large
        if unlikely(self.buffer.len() > 512 * 1024) {
            self.flush_buffer().await?;
        }

        Ok(())
    }

    /// Write a single gate with implicit output
    async fn write_gate(&mut self, gate: &Gate, gate_type: GateType) -> Result<()> {
        let mut temp_buf = [0u8; 32]; // Max size for wire encoding

        // Encode input1 wire location
        let bytes1 = FlaggedVarInt::encode_wire_location(
            gate.in1.level,
            gate.in1.index,
            self.current_level,
            &mut temp_buf,
        )?;
        self.buffer.extend_from_slice(&temp_buf[..bytes1]);
        self.hasher.update(&temp_buf[..bytes1]);

        // Encode input2 wire location
        let bytes2 = FlaggedVarInt::encode_wire_location(
            gate.in2.level,
            gate.in2.index,
            self.current_level,
            &mut temp_buf,
        )?;
        self.buffer.extend_from_slice(&temp_buf[..bytes2]);
        self.hasher.update(&temp_buf[..bytes2]);

        // Output is implicit - just increment wire counter
        self.wire_counter += 1;

        // Track gate type counts
        match gate_type {
            GateType::XOR => self.xor_gates_written += 1,
            GateType::AND => self.and_gates_written += 1,
        }

        Ok(())
    }

    /// Write multiple levels in sequence
    pub async fn write_levels(&mut self, levels: &[Level]) -> Result<()> {
        for level in levels {
            self.write_level(level).await?;
        }
        Ok(())
    }

    /// Get the current wire counter (next available wire ID)
    pub fn wire_counter(&self) -> u64 {
        self.wire_counter
    }

    /// Get current level
    pub fn current_level(&self) -> u32 {
        self.current_level
    }

    /// Get total gates written so far
    pub fn gates_written(&self) -> u64 {
        self.xor_gates_written + self.and_gates_written
    }

    /// Get XOR gates written so far
    pub fn xor_gates_written(&self) -> u64 {
        self.xor_gates_written
    }

    /// Get AND gates written so far
    pub fn and_gates_written(&self) -> u64 {
        self.and_gates_written
    }

    /// Flush the write buffer to file
    async fn flush_buffer(&mut self) -> Result<()> {
        if likely(!self.buffer.is_empty()) {
            let buf = std::mem::take(&mut self.buffer);
            let (result, returned_buf) = self.file.write_all_at(buf, self.bytes_written).await;
            result?;

            let bytes_written = returned_buf.len() as u64;
            self.bytes_written += bytes_written;

            // Reuse the buffer
            self.buffer = returned_buf;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Finish writing and update header with actual gate counts and checksum
    pub async fn finish(mut self) -> Result<(File, CircuitStats)> {
        // Flush any remaining gate data
        self.flush_buffer().await?;

        // Hash is computed as: hash(gate_data || header_fields_after_checksum)
        // Add the actual header fields (after checksum position) to the hash
        self.hasher.update(&self.xor_gates_written.to_le_bytes());
        self.hasher.update(&self.and_gates_written.to_le_bytes());
        self.hasher.update(&self.primary_inputs.to_le_bytes());

        // Compute the final checksum
        let hash = self.hasher.finalize();
        let checksum_bytes = hash.as_bytes();

        // Store checksum for return
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(checksum_bytes);

        // Build complete header with checksum
        let mut header_bytes = Vec::with_capacity(CircuitHeader::SIZE);
        header_bytes.push(VERSION);
        header_bytes.push(FormatType::TypeB.to_byte());
        header_bytes.extend_from_slice(checksum_bytes);
        header_bytes.extend_from_slice(&self.xor_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.and_gates_written.to_le_bytes());
        header_bytes.extend_from_slice(&self.primary_inputs.to_le_bytes());

        // Update header at the beginning of the file
        let (res, _) = self.file.write_all_at(header_bytes, 0).await;
        res?;

        // Sync file to ensure all data is written
        self.file.sync_all().await?;

        let stats = CircuitStats {
            total_gates: self.xor_gates_written + self.and_gates_written,
            xor_gates: self.xor_gates_written,
            and_gates: self.and_gates_written,
            primary_inputs: self.primary_inputs,
            total_levels: (self.current_level - 1) as u32, // Subtract 1 since we start at level 1
            bytes_written: self.bytes_written,
            checksum,
        };

        Ok((self.file, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::b::WireLocation;
    use monoio::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[monoio::test]
    async fn test_writer_basic() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 4).await?; // 4 primary inputs

        // Level 1: 2 XOR gates using primary inputs
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // input from primary input 0
            WireLocation::new(0, 1), // input from primary input 1
        ));
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 2), // input from primary input 2
            WireLocation::new(0, 3), // input from primary input 3
        ));

        // Level 2: 1 AND gate using outputs from level 1
        let mut level2 = Level::new(2);
        level2.and_gates.push(Gate::new(
            WireLocation::new(1, 0), // input from level 1, gate 0 (wire 4)
            WireLocation::new(1, 1), // input from level 1, gate 1 (wire 5)
        ));

        writer.write_level(&level1).await?;
        writer.write_level(&level2).await?;

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);
        assert_eq!(stats.primary_inputs, 4);

        Ok(())
    }

    #[monoio::test]
    async fn test_writer_multiple_levels() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 2).await?; // 2 primary inputs

        // Level 1: Gates that only use primary inputs
        let mut level1 = Level::new(1);
        level1.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // primary input 0
            WireLocation::new(0, 1), // primary input 1
        )); // This produces wire 2

        // Level 2: XOR gate that uses Level 1 output
        let mut level2 = Level::new(2);
        level2.xor_gates.push(Gate::new(
            WireLocation::new(0, 0), // primary input 0
            WireLocation::new(1, 0), // level 1, gate 0 (wire 2)
        )); // This produces wire 3

        // Level 3: AND gate that uses Level 2 output
        let mut level3 = Level::new(3);
        level3.and_gates.push(Gate::new(
            WireLocation::new(0, 1), // primary input 1
            WireLocation::new(2, 0), // level 2, gate 0 (wire 3)
        )); // This produces wire 4

        writer.write_level(&level1).await?;
        writer.write_level(&level2).await?;
        writer.write_level(&level3).await?;

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.total_levels, 3);

        Ok(())
    }

    #[monoio::test]
    async fn test_empty_level() -> Result<()> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;

        let mut writer = CircuitWriter::new(file, 2).await?;

        let empty_level = Level::new(1);
        writer.write_level(&empty_level).await?; // Should succeed and do nothing

        let (_, stats) = writer.finish().await?;
        assert_eq!(stats.total_gates, 0);

        Ok(())
    }
}

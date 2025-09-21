//! High-performance v5b writer using monoio io_uring
//!
//! This implementation provides a clean API for writing v5b format circuits:
//! - Level-based writing with Level struct
//! - Efficient bit packing with Structure-of-Arrays layout
//! - Direct async I/O with monoio
//! - BLAKE3 checksum calculation following spec order

use blake3::Hasher;
use monoio::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::path::Path;

use super::{
    BLOCK_SIZE, BlockV5b, GATES_PER_BLOCK, GateV5b, HEADER_SIZE, HeaderV5b, LEVEL_HEADER_SIZE,
    LevelHeader, MAX_MEMORY_ADDRESS, OUTPUT_ENTRY_SIZE,
};

/// A complete level of gates to be written
pub struct Level {
    pub xor_gates: Vec<GateV5b>,
    pub and_gates: Vec<GateV5b>,
}

impl Level {
    /// Create a new empty level
    pub fn new() -> Self {
        Self {
            xor_gates: Vec::new(),
            and_gates: Vec::new(),
        }
    }

    /// Create a level with preallocated capacity
    pub fn with_capacity(xor_capacity: usize, and_capacity: usize) -> Self {
        Self {
            xor_gates: Vec::with_capacity(xor_capacity),
            and_gates: Vec::with_capacity(and_capacity),
        }
    }

    /// Add an XOR gate to the level
    pub fn add_xor(&mut self, gate: GateV5b) -> Result<()> {
        gate.validate()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid gate: {}", e)))?;
        self.xor_gates.push(gate);
        Ok(())
    }

    /// Add an AND gate to the level
    pub fn add_and(&mut self, gate: GateV5b) -> Result<()> {
        gate.validate()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("Invalid gate: {}", e)))?;
        self.and_gates.push(gate);
        Ok(())
    }

    /// Get total number of gates in this level
    pub fn total_gates(&self) -> usize {
        self.xor_gates.len() + self.and_gates.len()
    }

    /// Check if level is empty
    pub fn is_empty(&self) -> bool {
        self.xor_gates.is_empty() && self.and_gates.is_empty()
    }

    /// Validate the level
    pub fn validate(&self) -> Result<()> {
        if self.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "Level cannot be empty"));
        }

        // Validate all gates
        for gate in &self.xor_gates {
            gate.validate().map_err(|e| {
                Error::new(ErrorKind::InvalidInput, format!("Invalid XOR gate: {}", e))
            })?;
        }
        for gate in &self.and_gates {
            gate.validate().map_err(|e| {
                Error::new(ErrorKind::InvalidInput, format!("Invalid AND gate: {}", e))
            })?;
        }

        Ok(())
    }

    /// Pack level into blocks
    fn pack_into_blocks(&self) -> Vec<BlockV5b> {
        let total = self.total_gates();
        let num_blocks = (total + GATES_PER_BLOCK - 1) / GATES_PER_BLOCK;
        let mut blocks = Vec::with_capacity(num_blocks);

        // Create an iterator over all gates (XOR first, then AND)
        let all_gates = self.xor_gates.iter().chain(self.and_gates.iter());

        let mut current_block = BlockV5b::new();
        let mut gates_in_block = 0;

        for gate in all_gates {
            BlockV5b::pack_24bit(&mut current_block.in1_stream, gates_in_block, gate.in1);
            BlockV5b::pack_24bit(&mut current_block.in2_stream, gates_in_block, gate.in2);
            BlockV5b::pack_24bit(&mut current_block.out_stream, gates_in_block, gate.out);

            gates_in_block += 1;

            if gates_in_block == GATES_PER_BLOCK {
                blocks.push(current_block);
                current_block = BlockV5b::new();
                gates_in_block = 0;
            }
        }

        // Add final partial block if needed
        if gates_in_block > 0 {
            blocks.push(current_block);
        }

        blocks
    }
}

/// Production circuit writer for v5b format
pub struct CircuitWriterV5b {
    /// File handle
    file: File,

    /// Current file offset for writing
    current_offset: u64,

    /// Circuit metadata
    primary_inputs: u64,
    outputs: Vec<u32>,
    num_levels: u32,

    /// Tracking state
    levels_written: u32,
    total_xor_gates: u64,
    total_and_gates: u64,

    /// Checksum hasher
    hasher: Hasher,

    /// Path for finalization
    path: std::path::PathBuf,
}

impl CircuitWriterV5b {
    /// Create a new v5b writer with outputs specified upfront
    pub async fn new(
        path: impl AsRef<Path>,
        primary_inputs: u64,
        outputs: Vec<u32>, // Outputs provided here
        num_levels: u32,
    ) -> Result<Self> {
        let path = path.as_ref().to_owned();

        // Validate outputs
        for &output in &outputs {
            if output >= MAX_MEMORY_ADDRESS {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Output address {} exceeds 24-bit maximum", output),
                ));
            }
        }

        // Open file with O_DIRECT for optimal performance
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
        }

        let file = opts.open(&path).await?;

        // Calculate initial offset (header + outputs)
        let num_outputs = outputs.len();
        let outputs_size = num_outputs * OUTPUT_ENTRY_SIZE;
        let initial_offset = (HEADER_SIZE + outputs_size) as u64;

        // Write placeholder header and space for outputs
        let placeholder = vec![0u8; HEADER_SIZE + outputs_size];
        let (res, _) = file.write_all_at(placeholder, 0).await;
        res?;

        // Create hasher and hash outputs (spec step 1)
        let mut hasher = Hasher::new();
        for &output in &outputs {
            let bytes = [
                (output & 0xFF) as u8,
                ((output >> 8) & 0xFF) as u8,
                ((output >> 16) & 0xFF) as u8,
            ];
            hasher.update(&bytes);
        }

        Ok(Self {
            file,
            current_offset: initial_offset,
            primary_inputs,
            outputs,
            num_levels,
            levels_written: 0,
            total_xor_gates: 0,
            total_and_gates: 0,
            hasher,
            path,
        })
    }

    /// Write a complete level
    pub async fn write_level(&mut self, level: Level) -> Result<()> {
        if self.levels_written >= self.num_levels {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Cannot exceed {} levels", self.num_levels),
            ));
        }

        // Validate level
        level.validate()?;

        // Write level header
        let level_header =
            LevelHeader::new(level.xor_gates.len() as u32, level.and_gates.len() as u32);
        let header_bytes = level_header.to_bytes();

        // Convert to Vec for monoio
        let header_vec = header_bytes.to_vec();
        let (res, _) = self
            .file
            .write_all_at(header_vec, self.current_offset)
            .await;
        res?;

        self.hasher.update(&header_bytes);
        self.current_offset += LEVEL_HEADER_SIZE as u64;

        // Pack and write blocks
        let blocks = level.pack_into_blocks();
        for block in blocks {
            // Convert block to bytes
            let mut block_bytes = Vec::with_capacity(BLOCK_SIZE);
            block_bytes.extend_from_slice(&block.in1_stream);
            block_bytes.extend_from_slice(&block.in2_stream);
            block_bytes.extend_from_slice(&block.out_stream);

            // Hash the block data (spec step 2)
            self.hasher.update(&block_bytes);

            // Write block
            let (res, _) = self
                .file
                .write_all_at(block_bytes, self.current_offset)
                .await;
            res?;
            self.current_offset += BLOCK_SIZE as u64;
        }

        // Update statistics
        self.total_xor_gates += level.xor_gates.len() as u64;
        self.total_and_gates += level.and_gates.len() as u64;
        self.levels_written += 1;

        Ok(())
    }

    /// Write multiple levels
    pub async fn write_levels(&mut self, levels: Vec<Level>) -> Result<()> {
        for level in levels {
            self.write_level(level).await?;
        }
        Ok(())
    }

    /// Finalize the writer and update the header with checksum
    /// The scratch_space parameter specifies the maximum memory address used
    pub async fn finalize(mut self, scratch_space: u64) -> Result<crate::v5::CircuitStats> {
        // Validate we wrote the expected number of levels
        if self.levels_written != self.num_levels {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Level count mismatch: wrote {}, expected {}",
                    self.levels_written, self.num_levels
                ),
            ));
        }

        // Validate scratch space
        if scratch_space >= (MAX_MEMORY_ADDRESS as u64) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Scratch space {} exceeds maximum", scratch_space),
            ));
        }

        // Sync the file to ensure all blocks are written
        self.file.sync_all().await?;

        // Create final header
        let mut header = HeaderV5b::new();
        header.primary_inputs = self.primary_inputs;
        header.num_outputs = self.outputs.len() as u64;
        header.num_levels = self.num_levels;
        header.scratch_space = scratch_space;
        header.xor_gates = self.total_xor_gates;
        header.and_gates = self.total_and_gates;

        // Hash header fields after checksum (spec step 3)
        let header_bytes = header.to_bytes();
        self.hasher.update(&header_bytes[40..]); // Skip magic, version, type, reserved, and checksum

        // Compute final checksum
        let hash = self.hasher.finalize();
        header.checksum.copy_from_slice(hash.as_bytes());

        // Write the final header and outputs at the beginning of the file
        self.write_header_and_outputs(&header).await?;

        Ok(crate::v5::CircuitStats {
            total_gates: self.total_xor_gates + self.total_and_gates,
            xor_gates: self.total_xor_gates,
            and_gates: self.total_and_gates,
            primary_inputs: self.primary_inputs,
            num_outputs: self.outputs.len() as u64,
            bytes_written: self.current_offset,
            checksum: header.checksum,
        })
    }

    /// Write header and outputs to the file
    async fn write_header_and_outputs(&self, header: &HeaderV5b) -> Result<()> {
        // Reopen file for updating header
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
        }

        let file = opts.open(&self.path).await?;

        // Write header
        let header_vec = header.to_bytes().to_vec();
        let (res, _) = file.write_all_at(header_vec, 0).await;
        res?;

        // Write outputs
        let outputs_offset = HEADER_SIZE as u64;
        let mut outputs_buffer = Vec::with_capacity(self.outputs.len() * OUTPUT_ENTRY_SIZE);

        for &output in &self.outputs {
            outputs_buffer.push((output & 0xFF) as u8);
            outputs_buffer.push(((output >> 8) & 0xFF) as u8);
            outputs_buffer.push(((output >> 16) & 0xFF) as u8);
        }

        let (res, _) = file.write_all_at(outputs_buffer, outputs_offset).await;
        res?;

        // Sync file
        file.sync_all().await?;

        Ok(())
    }
}

/// Verify the checksum of a v5b file
pub async fn verify_checksum(path: impl AsRef<Path>) -> Result<bool> {
    // Open file with O_DIRECT for optimal performance
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECT | libc::O_NOATIME);
    }

    let file = opts.open(path.as_ref()).await?;

    // Read header
    let mut header_bytes = vec![0u8; HEADER_SIZE];
    let (res, buf) = file.read_exact_at(header_bytes, 0).await;
    res?;
    let header_array: [u8; 88] = buf
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid header size"))?;
    let header = HeaderV5b::from_bytes(&header_array);

    // Validate header format
    header
        .validate()
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    // Create hasher
    let mut hasher = Hasher::new();

    // Step 1: Hash outputs
    let outputs_offset = HEADER_SIZE as u64;
    let outputs_size = header.num_outputs as usize * OUTPUT_ENTRY_SIZE;

    if outputs_size > 0 {
        let mut outputs_buf = vec![0u8; outputs_size];
        let (res, buf) = file.read_exact_at(outputs_buf, outputs_offset).await;
        res?;
        hasher.update(&buf);
    }

    // Step 2: Hash all level headers and gate blocks
    let mut current_offset = outputs_offset + outputs_size as u64;

    for _level_idx in 0..header.num_levels {
        // Read and hash level header
        let mut level_header_buf = vec![0u8; LEVEL_HEADER_SIZE];
        let (res, buf) = file.read_exact_at(level_header_buf, current_offset).await;
        res?;
        hasher.update(&buf);
        current_offset += LEVEL_HEADER_SIZE as u64;

        // Parse level header to get gate count
        let level_header_array: [u8; 8] = buf
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid level header size"))?;
        let level_header = LevelHeader::from_bytes(&level_header_array);
        let level_gates = level_header.num_gates as usize;

        // Calculate number of blocks for this level
        let blocks_in_level = (level_gates + GATES_PER_BLOCK - 1) / GATES_PER_BLOCK;

        // Read and hash all blocks in this level
        for _ in 0..blocks_in_level {
            let mut block_buf = vec![0u8; BLOCK_SIZE];
            let (res, buf) = file.read_exact_at(block_buf, current_offset).await;
            res?;
            hasher.update(&buf);
            current_offset += BLOCK_SIZE as u64;
        }
    }

    // Step 3: Hash header fields after checksum
    let header_bytes = header.to_bytes();
    hasher.update(&header_bytes[40..]); // Skip magic, version, type, reserved, and checksum

    // Compare checksums
    let computed = hasher.finalize();
    Ok(computed.as_bytes() == &header.checksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_level_basic() {
        let mut level = Level::new();
        assert!(level.is_empty());

        level.add_xor(GateV5b::new(2, 3, 4).unwrap()).unwrap();
        level.add_and(GateV5b::new(4, 5, 6).unwrap()).unwrap();

        assert_eq!(level.total_gates(), 2);
        assert_eq!(level.xor_gates.len(), 1);
        assert_eq!(level.and_gates.len(), 1);
    }

    #[test]
    fn test_level_validation() {
        let level = Level::new();
        assert!(level.validate().is_err()); // Empty level should fail

        let mut level = Level::new();
        level.add_xor(GateV5b::new(2, 3, 4).unwrap()).unwrap();
        assert!(level.validate().is_ok());

        // Invalid gate
        let bad_gate = GateV5b {
            in1: 10,
            in2: 20,
            out: MAX_MEMORY_ADDRESS,
        };
        assert!(level.add_xor(bad_gate).is_err());
    }

    #[monoio::test]
    async fn test_basic_writer() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        let mut writer = CircuitWriterV5b::new(
            path,
            2,        // 2 primary inputs
            vec![10], // 1 output at address 10
            2,        // 2 levels
        )
        .await?;

        // Level 1: 2 XOR gates
        let mut level1 = Level::new();
        level1.add_xor(GateV5b::new(2, 3, 4).unwrap())?;
        level1.add_xor(GateV5b::new(4, 5, 6).unwrap())?;
        writer.write_level(level1).await?;

        // Level 2: 1 AND gate
        let mut level2 = Level::new();
        level2.add_and(GateV5b::new(6, 7, 8).unwrap())?;
        writer.write_level(level2).await?;

        let stats = writer.finalize(100).await?; // Scratch space of 100
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);

        Ok(())
    }

    #[monoio::test]
    async fn test_large_level() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        // Create a level with more than one block (504 gates per block)
        let num_gates = 1000u32;
        let mut writer = CircuitWriterV5b::new(
            path,
            10,        // 10 primary inputs
            vec![999], // 1 output at address 999
            1,         // 1 level
        )
        .await?;

        let mut level = Level::with_capacity(num_gates as usize, 0);
        for i in 0..num_gates {
            level.add_xor(GateV5b::new(i + 10, i + 11, i + 1000).unwrap())?;
        }
        writer.write_level(level).await?;

        let stats = writer.finalize(2000).await?; // Scratch space of 2000
        assert_eq!(stats.total_gates, num_gates as u64);
        assert_eq!(stats.xor_gates, num_gates as u64);
        assert_eq!(stats.and_gates, 0);

        Ok(())
    }

    #[monoio::test]
    async fn test_multiple_levels() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        let mut writer = CircuitWriterV5b::new(
            path,
            4,              // 4 primary inputs
            vec![100, 101], // 2 outputs
            3,              // 3 levels
        )
        .await?;

        // Level 1: 100 XOR, 50 AND
        let mut level1 = Level::with_capacity(100, 50);
        for i in 0..100 {
            level1.add_xor(GateV5b::new(i + 4, i + 5, i + 200).unwrap())?;
        }
        for i in 0..50 {
            level1.add_and(GateV5b::new(i + 300, i + 301, i + 400).unwrap())?;
        }
        writer.write_level(level1).await?;

        // Level 2: 50 XOR, 100 AND
        let mut level2 = Level::with_capacity(50, 100);
        for i in 0..50 {
            level2.add_xor(GateV5b::new(i + 500, i + 501, i + 600).unwrap())?;
        }
        for i in 0..100 {
            level2.add_and(GateV5b::new(i + 700, i + 701, i + 800).unwrap())?;
        }
        writer.write_level(level2).await?;

        // Level 3: 0 XOR, 25 AND
        let mut level3 = Level::with_capacity(0, 25);
        for i in 0..25 {
            level3.add_and(GateV5b::new(i + 900, i + 901, i + 950).unwrap())?;
        }
        writer.write_level(level3).await?;

        let stats = writer.finalize(1000).await?; // Scratch space of 1000
        assert_eq!(stats.total_gates, 325);
        assert_eq!(stats.xor_gates, 150);
        assert_eq!(stats.and_gates, 175);

        Ok(())
    }

    #[monoio::test]
    async fn test_round_trip_with_reader() -> Result<()> {
        use super::super::CircuitReaderV5b;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        // Write a small test circuit
        {
            let mut writer = CircuitWriterV5b::new(
                path,
                2,        // 2 primary inputs
                vec![10], // 1 output at address 10
                2,        // 2 levels
            )
            .await?;

            // Level 1: 3 XOR gates
            let mut level1 = Level::new();
            level1.add_xor(GateV5b::new(2, 3, 4).unwrap())?;
            level1.add_xor(GateV5b::new(4, 5, 6).unwrap())?;
            level1.add_xor(GateV5b::new(6, 7, 8).unwrap())?;

            // Level 2: 2 AND gates
            let mut level2 = Level::new();
            level2.add_and(GateV5b::new(8, 9, 10).unwrap())?;
            level2.add_and(GateV5b::new(10, 11, 12).unwrap())?;

            writer.write_levels(vec![level1, level2]).await?;
            writer.finalize(100).await?; // Scratch space of 100
        }

        // Read the circuit back
        let mut reader = CircuitReaderV5b::open(path)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?;

        // Verify header using copy to avoid packed field reference issues
        let header = reader.header();
        let primary_inputs = header.primary_inputs;
        let num_outputs = header.num_outputs;
        let num_levels = header.num_levels;
        let xor_gates = header.xor_gates;
        let and_gates = header.and_gates;
        let scratch_space = header.scratch_space;

        assert_eq!(primary_inputs, 2);
        assert_eq!(num_outputs, 1);
        assert_eq!(num_levels, 2);
        assert_eq!(xor_gates, 3);
        assert_eq!(and_gates, 2);
        assert_eq!(scratch_space, 100);
        assert_eq!(header.total_gates(), 5);

        // Verify outputs
        assert_eq!(reader.outputs(), &[10]);

        // Read level 1
        let level1 = reader
            .next_level()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?
            .ok_or_else(|| Error::new(ErrorKind::Other, "No level 1"))?;
        let level1_num_gates = level1.num_gates;
        let level1_num_xor_gates = level1.num_xor_gates;
        assert_eq!(level1_num_gates, 3);
        assert_eq!(level1_num_xor_gates, 3);

        let mut gates = Vec::new();
        let count = reader
            .next_gates(&mut gates)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?;
        assert_eq!(count, 3);
        assert_eq!(gates[0].in1, 2);
        assert_eq!(gates[0].in2, 3);
        assert_eq!(gates[0].out, 4);

        // Read level 2
        let level2 = reader
            .next_level()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?
            .ok_or_else(|| Error::new(ErrorKind::Other, "No level 2"))?;
        let level2_num_gates = level2.num_gates;
        let level2_num_xor_gates = level2.num_xor_gates;
        assert_eq!(level2_num_gates, 2);
        assert_eq!(level2_num_xor_gates, 0);

        let count = reader
            .next_gates(&mut gates)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?;
        assert_eq!(count, 2);
        assert_eq!(gates[0].in1, 8);
        assert_eq!(gates[0].in2, 9);
        assert_eq!(gates[0].out, 10);

        Ok(())
    }

    #[monoio::test]
    async fn test_verify_checksum() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();

        // Write a circuit
        {
            let mut writer = CircuitWriterV5b::new(path, 2, vec![10, 11], 2).await?;

            // Level 1: 2 XOR gates
            let mut level1 = Level::new();
            level1.add_xor(GateV5b::new(2, 3, 4).unwrap())?;
            level1.add_xor(GateV5b::new(4, 5, 6).unwrap())?;
            writer.write_level(level1).await?;

            // Level 2: 1 AND gate
            let mut level2 = Level::new();
            level2.add_and(GateV5b::new(6, 7, 8).unwrap())?;
            writer.write_level(level2).await?;

            writer.finalize(100).await?;
        }

        // Verify checksum
        assert!(verify_checksum(&path).await?);

        // Corrupt the file and verify checksum fails
        {
            use std::fs::OpenOptions as StdOpenOptions;
            use std::io::{Seek, SeekFrom, Write};

            let mut file = StdOpenOptions::new().write(true).open(&path)?;

            // Corrupt a byte in the middle of the file
            file.seek(SeekFrom::Start(150))?;
            file.write_all(&[0xFF])?;
        }

        // Checksum should now fail
        assert!(!verify_checksum(&path).await?);

        Ok(())
    }
}

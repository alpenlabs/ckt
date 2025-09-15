//! CKT Format v2 - High-performance Boolean circuit format
//!
//! This module implements the v2 format with:
//! - Scalable wire IDs (up to 2^61 using varints)
//! - Explicit topological levels for parallel processing
//! - Locality-aware compression with relative/absolute wire ID encoding
//! - SoA-friendly reader API for vectorization

pub mod reader;
pub mod varints;
pub mod writer;

#[cfg(feature = "high-performance")]
pub mod hp;

/// CKT v2 format version identifier
pub const VERSION: u8 = 2;

/// A gate with wire IDs encoded as varints
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    pub input1: u64,
    pub input2: u64,
    pub output: u64,
}

impl Gate {
    pub fn new(input1: u64, input2: u64, output: u64) -> Self {
        Self {
            input1,
            input2,
            output,
        }
    }
}

/// Circuit header for v2 format - uses fixed-size u64s for seekable updates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitHeaderV2 {
    pub version: u8,
    pub xor_gates: u64,      // 8 bytes, little-endian
    pub and_gates: u64,      // 8 bytes, little-endian
    pub primary_inputs: u64, // 8 bytes, little-endian
}

impl CircuitHeaderV2 {
    /// Create header with known primary inputs, gate counts will be updated later
    pub fn new(primary_inputs: u64) -> Self {
        Self {
            version: VERSION,
            xor_gates: 0, // Will be updated when writing is complete
            and_gates: 0, // Will be updated when writing is complete
            primary_inputs,
        }
    }

    /// Create header with all values (for reading or when counts are known)
    pub fn with_counts(xor_gates: u64, and_gates: u64, primary_inputs: u64) -> Self {
        Self {
            version: VERSION,
            xor_gates,
            and_gates,
            primary_inputs,
        }
    }

    pub fn total_gates(&self) -> u64 {
        self.xor_gates + self.and_gates
    }

    /// Header size in bytes: 1 (version) + 8 + 8 + 8 = 25 bytes
    pub const SIZE: usize = 25;
}

/// A level containing XOR and AND gates that can be processed in parallel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Level {
    pub xor_gates: Vec<Gate>,
    pub and_gates: Vec<Gate>,
}

impl Level {
    pub fn new() -> Self {
        Self {
            xor_gates: Vec::new(),
            and_gates: Vec::new(),
        }
    }

    pub fn with_capacity(xor_capacity: usize, and_capacity: usize) -> Self {
        Self {
            xor_gates: Vec::with_capacity(xor_capacity),
            and_gates: Vec::with_capacity(and_capacity),
        }
    }

    pub fn total_gates(&self) -> usize {
        self.xor_gates.len() + self.and_gates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.xor_gates.is_empty() && self.and_gates.is_empty()
    }
}

impl Default for Level {
    fn default() -> Self {
        Self::new()
    }
}

/// Structure of Arrays representation for XOR gates - optimized for vectorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorGates<const N: usize> {
    pub input1s: [u64; N],
    pub input2s: [u64; N],
    pub outputs: [u64; N],
    pub count: usize,
}

impl<const N: usize> XorGates<N> {
    pub fn new() -> Self {
        Self {
            input1s: [0; N],
            input2s: [0; N],
            outputs: [0; N],
            count: 0,
        }
    }
}

impl<const N: usize> Default for XorGates<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Structure of Arrays representation for AND gates - optimized for vectorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndGates<const N: usize> {
    pub input1s: [u64; N],
    pub input2s: [u64; N],
    pub outputs: [u64; N],
    pub count: usize,
}

impl<const N: usize> AndGates<N> {
    pub fn new() -> Self {
        Self {
            input1s: [0; N],
            input2s: [0; N],
            outputs: [0; N],
            count: 0,
        }
    }
}

impl<const N: usize> Default for AndGates<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Gate type enumeration for v2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

#[cfg(all(test, feature = "high-performance"))]
mod compatibility_tests {
    use super::*;
    use monoio::fs::OpenOptions;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    /// Test compatibility between standard and monoio implementations
    #[monoio::test]
    async fn test_std_monoio_compatibility() -> std::io::Result<()> {
        // Create test circuit with standard writer
        let std_buffer = Cursor::new(Vec::new());
        let mut std_writer = writer::CircuitWriterV2::new(std_buffer, 4)?; // 4 primary inputs

        let mut level0 = Level::new();
        level0.xor_gates.push(Gate::new(0, 1, 4)); // XOR(0,1) -> 4
        level0.xor_gates.push(Gate::new(2, 3, 5)); // XOR(2,3) -> 5

        let mut level1 = Level::new();
        level1.and_gates.push(Gate::new(4, 5, 6)); // AND(4,5) -> 6

        std_writer.write_level(&level0)?;
        std_writer.write_level(&level1)?;

        let (std_cursor, std_stats) = std_writer.finish()?;
        let std_data = std_cursor.into_inner();

        // Create same circuit with monoio writer

        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path();

        let monoio_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
            .await?;

        let mut monoio_writer = hp::writer::CircuitWriterV2::new(monoio_file, 4).await?;
        monoio_writer.write_level(&level0).await?;
        monoio_writer.write_level(&level1).await?;
        let (_, monoio_stats) = monoio_writer.finish().await?;

        // Read monoio data
        let monoio_file = OpenOptions::new().read(true).open(file_path).await?;
        let file_len = monoio_file.metadata().await?.len() as usize;
        let monoio_data = {
            let (res, buf) = monoio_file
                .read_exact_at(Vec::with_capacity(file_len), 0)
                .await;
            res?;
            buf
        };

        // Verify stats match
        assert_eq!(std_stats.total_gates, monoio_stats.total_gates);
        assert_eq!(std_stats.xor_gates, monoio_stats.xor_gates);
        assert_eq!(std_stats.and_gates, monoio_stats.and_gates);
        assert_eq!(std_stats.primary_inputs, monoio_stats.primary_inputs);

        // Verify binary data is identical
        assert_eq!(std_data.len(), monoio_data.len());
        assert_eq!(std_data, monoio_data);

        // Test reading with both readers
        let std_cursor = Cursor::new(std_data.clone());
        let mut std_reader = reader::CircuitReaderV2::new(std_cursor)?;

        let monoio_file = OpenOptions::new().read(true).open(file_path).await?;
        let mut monoio_reader = hp::reader::CircuitReaderV2::new(monoio_file, 64 * 1024).await?;

        // Compare headers
        assert_eq!(std_reader.header(), monoio_reader.header());

        // Compare level 0
        let std_level0 = std_reader.read_level()?.unwrap();
        let monoio_level0 = monoio_reader.read_level().await?.unwrap();
        assert_eq!(std_level0, monoio_level0);

        // Compare level 1
        let std_level1 = std_reader.read_level()?.unwrap();
        let monoio_level1 = monoio_reader.read_level().await?.unwrap();
        assert_eq!(std_level1, monoio_level1);

        // Both should be at end
        assert!(std_reader.read_level()?.is_none());
        assert!(monoio_reader.read_level().await?.is_none());

        Ok(())
    }

    /// Test SoA compatibility between implementations
    #[monoio::test]
    async fn test_soa_compatibility() -> std::io::Result<()> {
        // Create test data with standard writer
        let buffer = Cursor::new(Vec::new());
        let mut writer = writer::CircuitWriterV2::new(buffer, 2)?;

        let mut level = Level::new();
        level.xor_gates.push(Gate::new(0, 1, 2)); // XOR(0,1) -> 2
        level.and_gates.push(Gate::new(0, 2, 3)); // AND(0,2) -> 3

        writer.write_level(&level)?;
        let (cursor, _) = writer.finish()?;
        let data = cursor.into_inner();

        // Read with standard reader SoA
        let cursor = Cursor::new(data.clone());
        let mut std_reader = reader::CircuitReaderV2::new(cursor)?;
        let (std_xor, std_and) = std_reader.read_soa_level::<8>()?.unwrap();

        // Read with monoio reader SoA
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &data)?;

        let monoio_file = OpenOptions::new().read(true).open(temp_file.path()).await?;
        let mut monoio_reader = hp::reader::CircuitReaderV2::new(monoio_file, 64 * 1024).await?;
        let (monoio_xor, monoio_and) = monoio_reader.read_soa_level::<8>().await?.unwrap();

        // Compare SoA results
        assert_eq!(std_xor.count, monoio_xor.count);
        assert_eq!(std_and.count, monoio_and.count);

        for i in 0..std_xor.count {
            assert_eq!(std_xor.input1s[i], monoio_xor.input1s[i]);
            assert_eq!(std_xor.input2s[i], monoio_xor.input2s[i]);
            assert_eq!(std_xor.outputs[i], monoio_xor.outputs[i]);
        }

        for i in 0..std_and.count {
            assert_eq!(std_and.input1s[i], monoio_and.input1s[i]);
            assert_eq!(std_and.input2s[i], monoio_and.input2s[i]);
            assert_eq!(std_and.outputs[i], monoio_and.outputs[i]);
        }

        Ok(())
    }
}

// src/v5/b/integration.rs
//
// Integration tests for v5b format reader and writer (32-bit AoS layout)

#[cfg(test)]
mod tests {
    use crate::GateType;
    use crate::v5::b::{
        GATE_SIZE, HEADER_SIZE, OUTPUT_ENTRY_SIZE,
        reader::{CircuitReaderV5b, GateV5b as ReaderGate, verify_v5b_checksum},
        writer::{CircuitWriterV5b, GateV5b as WriterGate},
    };
    use tempfile::tempdir;

    #[monoio::test]
    async fn test_empty_circuit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.v5b");

        // Write empty circuit
        let writer = CircuitWriterV5b::new(&path, 0, 0).await.unwrap();
        let stats = writer.finalize(2, vec![]).await.unwrap();
        assert_eq!(stats.total_gates, 0);
        assert_eq!(stats.num_levels, 0);
        assert_eq!(stats.num_outputs, 0);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.header().total_gates(), 0);
        let num_levels = reader.header().num_levels;
        assert_eq!(num_levels, 0);
        assert_eq!(reader.outputs().len(), 0);

        // Should have no levels
        let level = reader.next_level().await.unwrap();
        assert!(level.is_none());
    }

    #[monoio::test]
    async fn test_single_gate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("single.v5b");

        // Write single XOR gate
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 4).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();
        let stats = writer.finalize(5, vec![4]).await.unwrap();

        assert_eq!(stats.total_gates, 1);
        assert_eq!(stats.xor_gates, 1);
        assert_eq!(stats.and_gates, 0);
        assert_eq!(stats.num_levels, 1);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.header().total_gates(), 1);
        let xor_gates = reader.header().xor_gates;
        let and_gates = reader.header().and_gates;
        assert_eq!(xor_gates, 1);
        assert_eq!(and_gates, 0);
        assert_eq!(reader.outputs(), &[4]);

        let level = reader.next_level().await.unwrap().unwrap();
        assert_eq!(level.level_index, 0);
        assert_eq!(level.xor_gates.len(), 1);
        assert_eq!(level.and_gates.len(), 0);
        assert_eq!(level.xor_gates[0].in1, 2);
        assert_eq!(level.xor_gates[0].in2, 3);
        assert_eq!(level.xor_gates[0].out, 4);

        // No more levels
        assert!(reader.next_level().await.unwrap().is_none());
    }

    #[monoio::test]
    async fn test_multiple_levels() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multilevel.v5b");

        // Create a circuit with 3 levels
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();

        // Level 1: 2 gates
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 4).unwrap())
            .unwrap();
        writer
            .add_gate(GateType::AND, WriterGate::new(2, 3, 5).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        // Level 2: 1 gate
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(4, 5, 6).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        // Level 3: 1 gate
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::AND, WriterGate::new(6, 2, 7).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        let stats = writer.finalize(8, vec![7]).await.unwrap();
        assert_eq!(stats.total_gates, 4);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 2);
        assert_eq!(stats.num_levels, 3);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back and verify structure
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.header().total_gates(), 4);
        let num_levels = reader.header().num_levels;
        assert_eq!(num_levels, 3);

        // Level 1
        let level1 = reader.next_level().await.unwrap().unwrap();
        assert_eq!(level1.level_index, 0);
        assert_eq!(level1.xor_gates.len(), 1);
        assert_eq!(level1.and_gates.len(), 1);
        // First should be XOR
        assert_eq!(
            level1.xor_gates[0],
            ReaderGate {
                in1: 2,
                in2: 3,
                out: 4
            }
        );
        // Then AND
        assert_eq!(
            level1.and_gates[0],
            ReaderGate {
                in1: 2,
                in2: 3,
                out: 5
            }
        );

        // Level 2
        let level2 = reader.next_level().await.unwrap().unwrap();
        assert_eq!(level2.level_index, 1);
        assert_eq!(level2.xor_gates.len(), 1);
        assert_eq!(level2.and_gates.len(), 0);
        assert_eq!(
            level2.xor_gates[0],
            ReaderGate {
                in1: 4,
                in2: 5,
                out: 6
            }
        );

        // Level 3
        let level3 = reader.next_level().await.unwrap().unwrap();
        assert_eq!(level3.level_index, 2);
        assert_eq!(level3.xor_gates.len(), 0);
        assert_eq!(level3.and_gates.len(), 1);
        assert_eq!(
            level3.and_gates[0],
            ReaderGate {
                in1: 6,
                in2: 2,
                out: 7
            }
        );

        // No more levels
        assert!(reader.next_level().await.unwrap().is_none());
    }

    #[monoio::test]
    async fn test_mixed_gate_types_in_level() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mixed.v5b");

        // Write level with interleaved XOR and AND gates
        let mut writer = CircuitWriterV5b::new(&path, 2, 2).await.unwrap();
        writer.start_level().unwrap();

        // Add gates in mixed order
        for i in 0..50u32 {
            writer
                .add_gate(GateType::XOR, WriterGate::new(2, 3, 100 + i).unwrap())
                .unwrap();
            writer
                .add_gate(GateType::AND, WriterGate::new(2, 3, 200 + i).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        let stats = writer.finalize(300, vec![103, 203]).await.unwrap();
        assert_eq!(stats.total_gates, 100);
        assert_eq!(stats.xor_gates, 50);
        assert_eq!(stats.and_gates, 50);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back and verify XOR gates come first
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let level = reader.next_level().await.unwrap().unwrap();

        // First 50 should be XOR gates (outputs 100-149)
        assert_eq!(level.xor_gates.len(), 50);
        for i in 0..50 {
            assert_eq!(level.xor_gates[i].out, 100 + i as u32);
        }

        // Next 50 should be AND gates (outputs 200-249)
        assert_eq!(level.and_gates.len(), 50);
        for i in 0..50 {
            assert_eq!(level.and_gates[i].out, 200 + i as u32);
        }
    }

    #[monoio::test]
    async fn test_large_level() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.v5b");

        // Write a large number of gates in one level
        let num_gates = 10_000;
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();

        for i in 0..num_gates {
            let gate_type = if i % 2 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            };
            writer
                .add_gate(gate_type, WriterGate::new(2, 3, 1000 + i).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        let stats = writer.finalize(20_000, vec![1000]).await.unwrap();
        assert_eq!(stats.total_gates, num_gates as u64);
        assert_eq!(stats.xor_gates, num_gates as u64 / 2);
        assert_eq!(stats.and_gates, num_gates as u64 / 2);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let level = reader.next_level().await.unwrap().unwrap();

        assert_eq!(level.xor_gates.len(), (num_gates / 2) as usize);
        assert_eq!(level.and_gates.len(), (num_gates / 2) as usize);

        // Verify gates are in correct order
        for (i, gate) in level.xor_gates.iter().enumerate() {
            assert_eq!(gate.out, 1000 + (i * 2) as u32);
        }
        for (i, gate) in level.and_gates.iter().enumerate() {
            assert_eq!(gate.out, 1000 + (i * 2 + 1) as u32);
        }
    }

    #[monoio::test]
    async fn test_multiple_outputs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multiout.v5b");

        let mut writer = CircuitWriterV5b::new(&path, 2, 5).await.unwrap();
        writer.start_level().unwrap();

        // Create 5 gates with different outputs
        for i in 0..5u32 {
            writer
                .add_gate(GateType::XOR, WriterGate::new(2, 3, 10 + i).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        let outputs = vec![10, 11, 12, 13, 14];
        let stats = writer.finalize(20, outputs.clone()).await.unwrap();
        assert_eq!(stats.num_outputs, 5);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.outputs(), &outputs[..]);
    }

    #[monoio::test]
    async fn test_scratch_space_validation() {
        let dir = tempdir().unwrap();

        // Test 1: Gate address >= scratch_space should fail
        let path1 = dir.path().join("invalid1.v5b");
        let mut w1 = CircuitWriterV5b::new(&path1, 0, 1).await.unwrap();
        w1.start_level().unwrap();
        w1.add_gate(GateType::XOR, WriterGate::new(0, 1, 100).unwrap())
            .unwrap();
        w1.finish_level().await.unwrap();
        // scratch_space=50 but gate uses address 100
        let res = w1.finalize(50, vec![10]).await;
        assert!(res.is_err());

        // Test 2: Output address >= scratch_space should fail
        let path2 = dir.path().join("invalid2.v5b");
        let mut w2 = CircuitWriterV5b::new(&path2, 0, 1).await.unwrap();
        w2.start_level().unwrap();
        w2.add_gate(GateType::XOR, WriterGate::new(0, 1, 10).unwrap())
            .unwrap();
        w2.finish_level().await.unwrap();
        // scratch_space=50 but output is 60
        let res = w2.finalize(50, vec![60]).await;
        assert!(res.is_err());
    }

    #[monoio::test]
    async fn test_32bit_addresses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("32bit.v5b");

        // Test with large addresses that would overflow 24-bit
        let large_addr = 20_000_000u32; // > 16_777_216 (2^24)

        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, large_addr).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();
        let stats = writer
            .finalize(large_addr as u64 + 1, vec![large_addr])
            .await
            .unwrap();

        assert_eq!(stats.total_gates, 1);
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let level = reader.next_level().await.unwrap().unwrap();
        assert_eq!(level.xor_gates[0].out, large_addr);
        assert_eq!(reader.outputs()[0], large_addr);
    }

    #[monoio::test]
    async fn test_gate_memory_layout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("layout.v5b");

        // Verify that gates are laid out as expected (3 consecutive u32s)
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(
                GateType::XOR,
                WriterGate::new(0x11111111, 0x22222222, 0x33333333).unwrap(),
            )
            .unwrap();
        writer
            .add_gate(
                GateType::AND,
                WriterGate::new(0x44444444, 0x55555555, 0x66666666).unwrap(),
            )
            .unwrap();
        writer.finish_level().await.unwrap();
        writer.finalize(0x70000000, vec![0x33333333]).await.unwrap();

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read the file manually to verify byte layout
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mut f = File::open(&path).unwrap();

        // Skip header (88 bytes) + outputs (1 × 4 bytes) + level header (8 bytes)
        f.seek(SeekFrom::Start(
            (HEADER_SIZE + OUTPUT_ENTRY_SIZE + 8) as u64,
        ))
        .unwrap();

        // Read first gate (12 bytes)
        let mut gate1_bytes = [0u8; GATE_SIZE];
        f.read_exact(&mut gate1_bytes).unwrap();

        // Verify little-endian layout
        assert_eq!(
            u32::from_le_bytes([
                gate1_bytes[0],
                gate1_bytes[1],
                gate1_bytes[2],
                gate1_bytes[3]
            ]),
            0x11111111
        );
        assert_eq!(
            u32::from_le_bytes([
                gate1_bytes[4],
                gate1_bytes[5],
                gate1_bytes[6],
                gate1_bytes[7]
            ]),
            0x22222222
        );
        assert_eq!(
            u32::from_le_bytes([
                gate1_bytes[8],
                gate1_bytes[9],
                gate1_bytes[10],
                gate1_bytes[11]
            ]),
            0x33333333
        );

        // Read second gate (12 bytes)
        let mut gate2_bytes = [0u8; GATE_SIZE];
        f.read_exact(&mut gate2_bytes).unwrap();

        assert_eq!(
            u32::from_le_bytes([
                gate2_bytes[0],
                gate2_bytes[1],
                gate2_bytes[2],
                gate2_bytes[3]
            ]),
            0x44444444
        );
        assert_eq!(
            u32::from_le_bytes([
                gate2_bytes[4],
                gate2_bytes[5],
                gate2_bytes[6],
                gate2_bytes[7]
            ]),
            0x55555555
        );
        assert_eq!(
            u32::from_le_bytes([
                gate2_bytes[8],
                gate2_bytes[9],
                gate2_bytes[10],
                gate2_bytes[11]
            ]),
            0x66666666
        );
    }

    #[monoio::test]
    async fn test_corrupted_checksum() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupted.v5b");

        // Write valid file
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 4).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();
        writer.finalize(5, vec![4]).await.unwrap();

        // Corrupt the checksum
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        let mut f = OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(8)).unwrap(); // Seek to checksum start
        f.write_all(&[0xFF; 32]).unwrap(); // Corrupt it

        // Verify should fail
        assert!(!verify_v5b_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn test_zero_copy_reinterpret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zerocopy.v5b");

        // Write gates
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();

        for i in 0..1000u32 {
            writer
                .add_gate(GateType::XOR, WriterGate::new(i, i + 1, i + 2).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        writer.finalize(5000, vec![100]).await.unwrap();

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let level = reader.next_level().await.unwrap().unwrap();

        // Verify that we got all gates correctly
        assert_eq!(level.xor_gates.len(), 1000);
        for (i, gate) in level.xor_gates.iter().enumerate() {
            assert_eq!(gate.in1, i as u32);
            assert_eq!(gate.in2, i as u32 + 1);
            assert_eq!(gate.out, i as u32 + 2);
        }
    }
}

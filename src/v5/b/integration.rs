// src/v5/b/integration.rs
//
// Integration tests for v5b format reader and writer

#[cfg(test)]
mod tests {
    use crate::GateType;
    use crate::v5::b::{
        GATES_PER_BLOCK, HEADER_SIZE, OUTPUT_ENTRY_SIZE,
        reader::{CircuitReaderV5b, GateV5b as ReaderGate, verify_v5b_checksum},
        writer::{CircuitWriterV5b, GateV5b as WriterGate},
    };
    use std::collections::HashSet;
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

        let mut level = reader.next_level().await.unwrap().unwrap();

        // Should have exactly one block with one gate
        {
            let block_soa = level
                .next_block_soa()
                .await
                .unwrap()
                .expect("Expected a block");
            assert_eq!(block_soa.gates_in_block, 1);
            assert_eq!(block_soa.in1[0], 2);
            assert_eq!(block_soa.in2[0], 3);
            assert_eq!(block_soa.out[0], 4);
        }

        // No more blocks
        assert!(
            level.next_block_soa().await.unwrap().is_none(),
            "Expected no more blocks"
        );
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
        let mut level1 = reader.next_level().await.unwrap().unwrap();
        let block1 = level1.next_block().await.unwrap().unwrap();
        assert_eq!(block1.len(), 2);
        // First should be XOR (XOR gates come before AND)
        assert_eq!(
            block1[0],
            ReaderGate {
                in1: 2,
                in2: 3,
                out: 4
            }
        );
        assert_eq!(
            block1[1],
            ReaderGate {
                in1: 2,
                in2: 3,
                out: 5
            }
        );

        // Level 2
        let mut level2 = reader.next_level().await.unwrap().unwrap();
        let block2 = level2.next_block().await.unwrap().unwrap();
        assert_eq!(block2.len(), 1);
        assert_eq!(
            block2[0],
            ReaderGate {
                in1: 4,
                in2: 5,
                out: 6
            }
        );

        // Level 3
        let mut level3 = reader.next_level().await.unwrap().unwrap();
        let block3 = level3.next_block().await.unwrap().unwrap();
        assert_eq!(block3.len(), 1);
        assert_eq!(
            block3[0],
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
        let mut level = reader.next_level().await.unwrap().unwrap();
        let block_soa = level.next_block_soa().await.unwrap().unwrap();

        // First 50 should be XOR gates (outputs 100-149)
        for i in 0..50 {
            assert_eq!(block_soa.out[i], 100 + i as u32);
        }

        // Next 50 should be AND gates (outputs 200-249)
        for i in 50..100 {
            assert_eq!(block_soa.out[i], 200 + (i - 50) as u32);
        }

        assert_eq!(block_soa.xor_gates, 50);
        assert_eq!(block_soa.gates_in_block, 100);
        drop(block_soa);
    }

    #[monoio::test]
    async fn test_full_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fullblock.v5b");

        // Write exactly GATES_PER_BLOCK gates
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();

        for i in 0..GATES_PER_BLOCK as u32 {
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
        let stats = writer.finalize(2000, vec![1000]).await.unwrap();
        assert_eq!(stats.total_gates, GATES_PER_BLOCK as u64);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let mut level = reader.next_level().await.unwrap().unwrap();

        // Should have exactly one full block
        {
            let block_soa = level
                .next_block_soa()
                .await
                .unwrap()
                .expect("Expected a full block");
            assert_eq!(block_soa.gates_in_block, GATES_PER_BLOCK);
            drop(block_soa);
        }

        // No more blocks
        assert!(
            level.next_block_soa().await.unwrap().is_none(),
            "Expected no more blocks"
        );
    }

    #[monoio::test]
    async fn test_multiple_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multiblock.v5b");

        // Write 1.5 blocks worth of gates
        let num_gates = GATES_PER_BLOCK + GATES_PER_BLOCK / 2;
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();

        for i in 0..num_gates as u32 {
            writer
                .add_gate(GateType::XOR, WriterGate::new(2, 3, 1000 + i).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        let stats = writer.finalize(6000, vec![5000]).await.unwrap();
        assert_eq!(stats.total_gates, num_gates as u64);
        assert_eq!(stats.xor_gates, num_gates as u64);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let mut level = reader.next_level().await.unwrap().unwrap();

        // First block (full)
        let block1_soa = level
            .next_block_soa()
            .await
            .unwrap()
            .expect("Expected first block");
        assert_eq!(block1_soa.gates_in_block, GATES_PER_BLOCK);
        drop(block1_soa);

        // Second block (partial)
        let block2_soa = level
            .next_block_soa()
            .await
            .unwrap()
            .expect("Expected second block");
        assert_eq!(block2_soa.gates_in_block, GATES_PER_BLOCK / 2);
        drop(block2_soa);

        // No more blocks
        assert!(
            level.next_block_soa().await.unwrap().is_none(),
            "Expected no more blocks"
        );
    }

    #[monoio::test]
    async fn test_block_boundary_xor_and_split() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("boundary.v5b");

        // Create scenario where XOR/AND boundary falls within a block
        let xor_count = 300;
        let and_count = 300; // Total 600, which spans 2 blocks (504 + 96)

        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();

        // Add interleaved, but they'll be reordered as XOR-first
        for i in 0..xor_count {
            writer
                .add_gate(GateType::XOR, WriterGate::new(2, 3, 1000 + i).unwrap())
                .unwrap();
        }
        for i in 0..and_count {
            writer
                .add_gate(GateType::AND, WriterGate::new(2, 3, 2000 + i).unwrap())
                .unwrap();
        }

        writer.finish_level().await.unwrap();
        let stats = writer.finalize(3000, vec![2000]).await.unwrap();
        assert_eq!(stats.total_gates, 600);
        assert_eq!(stats.xor_gates, 300);
        assert_eq!(stats.and_gates, 300);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read and verify gate order
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        let mut level = reader.next_level().await.unwrap().unwrap();

        // First block has 504 gates (300 XOR + 204 AND)
        let block1_soa = level
            .next_block_soa()
            .await
            .unwrap()
            .expect("Expected first block");
        assert_eq!(block1_soa.gates_in_block, 504);
        assert_eq!(block1_soa.xor_gates, 300);

        // Check first 300 are XOR gates (outputs 1000-1299)
        for i in 0..300 {
            assert_eq!(block1_soa.out[i], 1000 + i as u32);
        }
        // Check next 204 are AND gates (outputs 2000-2203)
        for i in 300..504 {
            assert_eq!(block1_soa.out[i], 2000 + (i - 300) as u32);
        }
        drop(block1_soa);

        // Second block has remaining 96 AND gates
        let block2_soa = level
            .next_block_soa()
            .await
            .unwrap()
            .expect("Expected second block");
        assert_eq!(block2_soa.gates_in_block, 96);
        assert_eq!(block2_soa.xor_gates, 0); // No XOR gates in second block
        // Check these are AND gates (outputs 2204-2299)
        for i in 0..96 {
            assert_eq!(block2_soa.out[i], 2204 + i as u32);
        }
        drop(block2_soa);

        // No more blocks
        assert!(
            level.next_block_soa().await.unwrap().is_none(),
            "Expected no more blocks"
        );
    }

    #[monoio::test]
    async fn test_large_circuit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.v5b");

        // Create a multi-level circuit with many gates
        let gates_per_level = 1000;
        let num_levels = 10;
        let mut writer = CircuitWriterV5b::new(&path, 100, 1).await.unwrap();

        for level in 0..num_levels {
            writer.start_level().unwrap();
            for i in 0..gates_per_level {
                let out = 10000 * (level + 1) + i;
                let gate_type = if i % 3 == 0 {
                    GateType::XOR
                } else {
                    GateType::AND
                };
                writer
                    .add_gate(gate_type, WriterGate::new(2, 3, out).unwrap())
                    .unwrap();
            }
            writer.finish_level().await.unwrap();
        }

        let stats = writer.finalize(110000, vec![50000]).await.unwrap();
        assert_eq!(stats.total_gates, (gates_per_level * num_levels) as u64);
        assert_eq!(stats.num_levels, num_levels);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back and verify counts
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(
            reader.header().total_gates(),
            (gates_per_level * num_levels) as u64
        );
        let header_num_levels = reader.header().num_levels;
        assert_eq!(header_num_levels, num_levels);

        // Verify each level
        for level_idx in 0..num_levels {
            let mut level = reader.next_level().await.unwrap().unwrap();
            let mut gates_read = 0;
            let mut expected_outs = HashSet::new();

            for i in 0..gates_per_level {
                expected_outs.insert(10000 * (level_idx + 1) + i);
            }

            // Each level has 1000 gates, which requires 2 blocks (1000 / 504 = 2)
            // First block: 504 gates
            let block1_soa = level
                .next_block_soa()
                .await
                .unwrap()
                .expect("Expected first block");
            let block1_gates = block1_soa.gates_in_block;
            let mut block1_outs = Vec::new();
            for i in 0..block1_gates {
                block1_outs.push(block1_soa.out[i]);
            }
            drop(block1_soa);
            gates_read += block1_gates;
            for out in block1_outs {
                assert!(expected_outs.remove(&out));
            }

            // Second block: 496 gates (1000 - 504)
            let block2_soa = level
                .next_block_soa()
                .await
                .unwrap()
                .expect("Expected second block");
            let block2_gates = block2_soa.gates_in_block;
            let mut block2_outs = Vec::new();
            for i in 0..block2_gates {
                block2_outs.push(block2_soa.out[i]);
            }
            drop(block2_soa);
            gates_read += block2_gates;
            for out in block2_outs {
                assert!(expected_outs.remove(&out));
            }

            // No more blocks expected
            assert!(
                level.next_block_soa().await.unwrap().is_none(),
                "Unexpected third block in level {}",
                level_idx
            );

            assert_eq!(gates_read, gates_per_level as usize);
            assert!(expected_outs.is_empty());
        }
    }

    #[monoio::test]
    async fn test_max_memory_address() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("maxaddr.v5b");

        // Test with maximum valid 24-bit address
        let max_addr = 0xFFFFFF;
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, max_addr).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        // Should succeed with scratch space > max address
        let stats = writer
            .finalize(max_addr as u64 + 1, vec![max_addr])
            .await
            .unwrap();
        assert_eq!(stats.total_gates, 1);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.outputs(), &[max_addr]);
        let mut level = reader.next_level().await.unwrap().unwrap();
        let block = level.next_block().await.unwrap().unwrap();
        assert_eq!(block[0].out, max_addr);
    }

    #[monoio::test]
    async fn test_empty_level() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty_level.v5b");

        // Create circuit with empty level in between
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();

        // Level 1: has gates
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 4).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        // Level 2: empty (allowed by auto-finish in finalize)
        writer.start_level().unwrap();
        writer.finish_level().await.unwrap();

        // Level 3: has gates
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::AND, WriterGate::new(4, 2, 5).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        let stats = writer.finalize(10, vec![5]).await.unwrap();
        assert_eq!(stats.total_gates, 2);
        assert_eq!(stats.num_levels, 3);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let mut reader = CircuitReaderV5b::open(&path).unwrap();

        // Level 1
        let mut level1 = reader.next_level().await.unwrap().unwrap();
        let block1 = level1.next_block().await.unwrap().unwrap();
        assert_eq!(block1.len(), 1);

        // Level 2 (empty)
        let mut level2 = reader.next_level().await.unwrap().unwrap();
        assert!(level2.next_block().await.unwrap().is_none());

        // Level 3
        let mut level3 = reader.next_level().await.unwrap().unwrap();
        let block3 = level3.next_block().await.unwrap().unwrap();
        assert_eq!(block3.len(), 1);
    }

    #[monoio::test]
    async fn test_corrupted_checksum() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.v5b");

        // Write valid circuit
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 4).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();
        writer.finalize(5, vec![4]).await.unwrap();

        // Verify original is valid
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Corrupt the file by modifying a byte in the gate data
        {
            use std::fs::OpenOptions;
            use std::io::{Seek, SeekFrom, Write};

            let mut file = OpenOptions::new()
                .write(true)
                .read(true)
                .open(&path)
                .unwrap();

            // Seek past header and outputs to gate data
            file.seek(SeekFrom::Start(
                (HEADER_SIZE + OUTPUT_ENTRY_SIZE + 8 + 100) as u64,
            ))
            .unwrap();
            file.write_all(&[0xFF]).unwrap();
        }

        // Checksum should now fail
        assert!(!verify_v5b_checksum(&path).await.unwrap());
    }

    #[monoio::test]
    async fn test_multiple_outputs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi_out.v5b");

        // Create circuit with multiple outputs
        let outputs = vec![100, 200, 300, 400, 500];
        let mut writer = CircuitWriterV5b::new(&path, 2, outputs.len() as u64)
            .await
            .unwrap();

        writer.start_level().unwrap();
        for &out in &outputs {
            writer
                .add_gate(GateType::XOR, WriterGate::new(2, 3, out).unwrap())
                .unwrap();
        }
        writer.finish_level().await.unwrap();

        let stats = writer.finalize(1000, outputs.clone()).await.unwrap();
        assert_eq!(stats.num_outputs, outputs.len() as u64);

        // Verify checksum
        assert!(verify_v5b_checksum(&path).await.unwrap());

        // Read back
        let reader = CircuitReaderV5b::open(&path).unwrap();
        assert_eq!(reader.outputs(), outputs.as_slice());
    }

    #[monoio::test]
    async fn test_scratch_space_validation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("scratch.v5b");

        // Create circuit with gates using high addresses
        let mut writer = CircuitWriterV5b::new(&path, 2, 1).await.unwrap();
        writer.start_level().unwrap();
        writer
            .add_gate(GateType::XOR, WriterGate::new(2, 3, 1000).unwrap())
            .unwrap();
        writer.finish_level().await.unwrap();

        // Should fail if scratch_space is too small
        let result = writer.finalize(500, vec![1000]).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("addresses are >= scratch_space")
        );
    }
}

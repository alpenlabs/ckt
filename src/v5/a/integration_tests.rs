//! Integration tests for v5a format reader/writer round-trip verification

#[cfg(test)]
mod tests {
    use crate::v5::a::{
        GATES_PER_BLOCK, GateV5a, HeaderV5a, MAX_CREDITS, MAX_WIRE_ID, reader::CircuitReaderV5a,
        writer::CircuitWriterV5a,
    };
    use blake3::Hasher;
    use tempfile::tempdir;

    /// Helper function to create a test gate
    fn make_gate(i: u64) -> GateV5a {
        GateV5a {
            in1: 2 + (i % 10),
            in2: 3 + (i % 8),
            out: 100 + i,
            credits: 1 + (i % 100) as u32,
            gate_type: i % 3 == 0, // Every third gate is AND
        }
    }

    #[monoio::test]
    async fn test_round_trip_empty_circuit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.v5a");

        // Write empty circuit
        {
            let writer = CircuitWriterV5a::new(&path, 5, vec![]).await.unwrap();
            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, 0);
            assert_eq!(stats.primary_inputs, 5);
            assert_eq!(stats.num_outputs, 0);
        }

        // Read it back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();
            let header = reader.header();
            assert_eq!(header.total_gates(), 0);
            let primary_inputs = header.primary_inputs;
            assert_eq!(primary_inputs, 5);
            let num_outputs = header.num_outputs;
            assert_eq!(num_outputs, 0);
            assert_eq!(reader.outputs().len(), 0);

            // Should have no blocks
            assert!(reader.next_block().unwrap().is_none());

            // Checksum should still verify
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_single_gate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("single.v5a");

        let test_gate = GateV5a {
            in1: 2,
            in2: 3,
            out: 4,
            credits: 1,
            gate_type: false, // XOR
        };

        // Write single gate
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![4]).await.unwrap();
            writer.write_gate(test_gate).await.unwrap();
            let stats = writer.finalize().await.unwrap();

            assert_eq!(stats.total_gates, 1);
            assert_eq!(stats.xor_gates, 1);
            assert_eq!(stats.and_gates, 0);
            assert_eq!(stats.primary_inputs, 2);
            assert_eq!(stats.num_outputs, 1);
        }

        // Read it back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            // Check header
            let header = reader.header();
            let xor_gates = header.xor_gates;
            assert_eq!(xor_gates, 1);
            let and_gates = header.and_gates;
            assert_eq!(and_gates, 0);
            let primary_inputs = header.primary_inputs;
            assert_eq!(primary_inputs, 2);
            let num_outputs = header.num_outputs;
            assert_eq!(num_outputs, 1);

            // Check outputs
            let outputs = reader.outputs();
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0], 4);

            // Read the gate
            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, 1);
            assert_eq!(block.gates.len(), 1);

            let gate = &block.gates[0];
            assert_eq!(gate.in1, test_gate.in1);
            assert_eq!(gate.in2, test_gate.in2);
            assert_eq!(gate.out, test_gate.out);
            assert_eq!(gate.credits, test_gate.credits);
            assert_eq!(gate.gate_type, test_gate.gate_type);

            // No more blocks
            assert!(reader.next_block().unwrap().is_none());

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_two_gates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("two_gates.v5a");

        let gate1 = GateV5a {
            in1: 2,
            in2: 3,
            out: 4,
            credits: 1,
            gate_type: false, // XOR
        };

        let gate2 = GateV5a {
            in1: 3,
            in2: 4,
            out: 5,
            credits: 2,
            gate_type: true, // AND
        };

        // Write two gates
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![5]).await.unwrap();
            writer.write_gate(gate1).await.unwrap();
            writer.write_gate(gate2).await.unwrap();
            let stats = writer.finalize().await.unwrap();

            assert_eq!(stats.total_gates, 2);
            assert_eq!(stats.xor_gates, 1);
            assert_eq!(stats.and_gates, 1);
        }

        // Read them back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, 2);

            // Check first gate
            let read_gate1 = &block.gates[0];
            assert_eq!(read_gate1.in1, gate1.in1, "Gate 0 in1 mismatch");
            assert_eq!(read_gate1.in2, gate1.in2, "Gate 0 in2 mismatch");
            assert_eq!(read_gate1.out, gate1.out, "Gate 0 out mismatch");
            assert_eq!(read_gate1.credits, gate1.credits, "Gate 0 credits mismatch");
            assert_eq!(
                read_gate1.gate_type, gate1.gate_type,
                "Gate 0 type mismatch"
            );

            // Check second gate
            let read_gate2 = &block.gates[1];
            assert_eq!(read_gate2.in1, gate2.in1, "Gate 1 in1 mismatch");
            assert_eq!(read_gate2.in2, gate2.in2, "Gate 1 in2 mismatch");
            assert_eq!(read_gate2.out, gate2.out, "Gate 1 out mismatch");
            assert_eq!(read_gate2.credits, gate2.credits, "Gate 1 credits mismatch");
            assert_eq!(
                read_gate2.gate_type, gate2.gate_type,
                "Gate 1 type mismatch"
            );

            // No more blocks
            assert!(reader.next_block().unwrap().is_none());

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_three_gates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("three_gates.v5a");

        let gates = vec![
            GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: 1,
                gate_type: false, // XOR
            },
            GateV5a {
                in1: 3,
                in2: 4,
                out: 5,
                credits: 2,
                gate_type: true, // AND
            },
            GateV5a {
                in1: 4,
                in2: 5,
                out: 6,
                credits: 3,
                gate_type: false, // XOR
            },
        ];

        // Write three gates
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![6]).await.unwrap();
            for gate in &gates {
                writer.write_gate(*gate).await.unwrap();
            }
            let stats = writer.finalize().await.unwrap();

            assert_eq!(stats.total_gates, 3);
            assert_eq!(stats.xor_gates, 2);
            assert_eq!(stats.and_gates, 1);
        }

        // Read them back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, 3);

            // Check all gates
            for (i, expected) in gates.iter().enumerate() {
                let actual = &block.gates[i];
                assert_eq!(actual.in1, expected.in1, "Gate {} in1 mismatch", i);
                assert_eq!(actual.in2, expected.in2, "Gate {} in2 mismatch", i);
                assert_eq!(actual.out, expected.out, "Gate {} out mismatch", i);
                assert_eq!(
                    actual.credits, expected.credits,
                    "Gate {} credits mismatch",
                    i
                );
                assert_eq!(
                    actual.gate_type, expected.gate_type,
                    "Gate {} type mismatch",
                    i
                );
            }

            // No more blocks
            assert!(reader.next_block().unwrap().is_none());

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_full_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("full_block.v5a");

        // Write exactly one full block (256 gates)
        {
            let mut writer = CircuitWriterV5a::new(&path, 10, vec![355]).await.unwrap();

            for i in 0..GATES_PER_BLOCK as u64 {
                writer.write_gate(make_gate(i)).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, GATES_PER_BLOCK as u64);
        }

        // Read it back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let header = reader.header();
            assert_eq!(header.total_gates(), GATES_PER_BLOCK as u64);

            // Should get exactly one full block
            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, GATES_PER_BLOCK);

            // Verify all gates
            for i in 0..GATES_PER_BLOCK {
                let expected = make_gate(i as u64);
                let actual = &block.gates[i];
                assert_eq!(actual.in1, expected.in1, "Gate {} in1 mismatch", i);
                assert_eq!(actual.in2, expected.in2, "Gate {} in2 mismatch", i);
                assert_eq!(actual.out, expected.out, "Gate {} out mismatch", i);
                assert_eq!(
                    actual.credits, expected.credits,
                    "Gate {} credits mismatch",
                    i
                );
                assert_eq!(
                    actual.gate_type, expected.gate_type,
                    "Gate {} type mismatch",
                    i
                );
            }

            // No more blocks
            assert!(reader.next_block().unwrap().is_none());

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_partial_block() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("partial_block.v5a");

        const NUM_GATES: u64 = 100; // Less than a full block

        // Write partial block
        {
            let mut writer = CircuitWriterV5a::new(&path, 10, vec![199]).await.unwrap();

            for i in 0..NUM_GATES {
                writer.write_gate(make_gate(i)).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, NUM_GATES);
        }

        // Read it back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let header = reader.header();
            assert_eq!(header.total_gates(), NUM_GATES);

            // Should get one partial block
            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, NUM_GATES as usize);

            // Verify all gates
            for i in 0..NUM_GATES as usize {
                let expected = make_gate(i as u64);
                let actual = &block.gates[i];
                assert_eq!(actual.in1, expected.in1);
                assert_eq!(actual.in2, expected.in2);
                assert_eq!(actual.out, expected.out);
                assert_eq!(actual.credits, expected.credits);
                assert_eq!(actual.gate_type, expected.gate_type);
            }

            // No more blocks
            assert!(reader.next_block().unwrap().is_none());

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_multiple_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("multiple_blocks.v5a");

        const NUM_GATES: u64 = 600; // More than 2 blocks

        // Write multiple blocks
        {
            let mut writer = CircuitWriterV5a::new(&path, 20, vec![699]).await.unwrap();

            for i in 0..NUM_GATES {
                writer.write_gate(make_gate(i)).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, NUM_GATES);

            // Check gate type counts
            let expected_and = NUM_GATES / 3;
            let expected_xor = NUM_GATES - expected_and;
            assert_eq!(stats.and_gates, expected_and);
            assert_eq!(stats.xor_gates, expected_xor);
        }

        // Read it back
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let header = reader.header();
            assert_eq!(header.total_gates(), NUM_GATES);

            let mut gates_read = 0u64;
            let mut block_count = 0;

            while let Some(block) = reader.next_block().unwrap() {
                block_count += 1;

                for (idx, gate) in block.gates.iter().enumerate() {
                    let i = gates_read + idx as u64;
                    let expected = make_gate(i);
                    assert_eq!(gate.in1, expected.in1, "Gate {} in1 mismatch", i);
                    assert_eq!(gate.in2, expected.in2, "Gate {} in2 mismatch", i);
                    assert_eq!(gate.out, expected.out, "Gate {} out mismatch", i);
                    assert_eq!(
                        gate.credits, expected.credits,
                        "Gate {} credits mismatch",
                        i
                    );
                    assert_eq!(
                        gate.gate_type, expected.gate_type,
                        "Gate {} type mismatch",
                        i
                    );
                }

                gates_read += block.valid_gates as u64;
            }

            assert_eq!(gates_read, NUM_GATES);
            assert_eq!(block_count, 3); // 256 + 256 + 88

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_round_trip_max_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("max_values.v5a");

        // Test with maximum valid values
        let gates = vec![
            GateV5a {
                in1: MAX_WIRE_ID,
                in2: MAX_WIRE_ID - 1,
                out: MAX_WIRE_ID - 2,
                credits: MAX_CREDITS,
                gate_type: true,
            },
            GateV5a {
                in1: 0,
                in2: 1,
                out: 2,
                credits: 0,
                gate_type: false,
            },
            GateV5a {
                in1: 1000000,
                in2: 2000000,
                out: 3000000,
                credits: 1000,
                gate_type: true,
            },
        ];

        // Write gates
        {
            let mut writer =
                CircuitWriterV5a::new(&path, MAX_WIRE_ID, vec![MAX_WIRE_ID, 0, 3000000])
                    .await
                    .unwrap();

            for gate in &gates {
                writer.write_gate(*gate).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, 3);
            assert_eq!(stats.xor_gates, 1);
            assert_eq!(stats.and_gates, 2);
        }

        // Read and verify
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            // Check outputs
            let outputs = reader.outputs();
            assert_eq!(outputs.len(), 3);
            assert_eq!(outputs[0], MAX_WIRE_ID);
            assert_eq!(outputs[1], 0);
            assert_eq!(outputs[2], 3000000);

            // Read gates
            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, 3);

            for i in 0..3 {
                let expected = &gates[i];
                let actual = &block.gates[i];
                assert_eq!(actual.in1, expected.in1);
                assert_eq!(actual.in2, expected.in2);
                assert_eq!(actual.out, expected.out);
                assert_eq!(actual.credits, expected.credits);
                assert_eq!(actual.gate_type, expected.gate_type);
            }

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_checksum_verification() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("checksum.v5a");

        // Write some gates
        {
            let mut writer = CircuitWriterV5a::new(&path, 3, vec![10, 11]).await.unwrap();

            for i in 0..50 {
                writer.write_gate(make_gate(i)).await.unwrap();
            }

            writer.finalize().await.unwrap();
        }

        // Manually verify checksum follows spec
        {
            let file_content = std::fs::read(&path).unwrap();
            let header_size = std::mem::size_of::<HeaderV5a>();
            let outputs_size = 2 * 5; // 2 outputs * 5 bytes each

            let mut manual_hasher = Hasher::new();

            // 1. Hash OUTPUTS section
            manual_hasher.update(&file_content[header_size..header_size + outputs_size]);

            // 2. Hash GATE BLOCKS section
            manual_hasher.update(&file_content[header_size + outputs_size..]);

            // 3. Hash header fields after checksum
            manual_hasher.update(&file_content[40..72]);

            let computed = manual_hasher.finalize();

            // Extract checksum from header
            let header_checksum = &file_content[8..40];
            assert_eq!(computed.as_bytes(), header_checksum);
        }

        // Verify reader agrees
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            // Read all blocks
            while let Some(_) = reader.next_block().unwrap() {}

            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_large_circuit_simulation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.v5a");

        const NUM_GATES: u64 = 10_000;
        const NUM_INPUTS: u64 = 1000;
        const NUM_OUTPUTS: usize = 100;

        // Generate output wire IDs
        let outputs: Vec<u64> = (0..NUM_OUTPUTS as u64)
            .map(|i| NUM_INPUTS + NUM_GATES - NUM_OUTPUTS as u64 + i)
            .collect();

        // Write large circuit
        {
            let mut writer = CircuitWriterV5a::new(&path, NUM_INPUTS, outputs.clone())
                .await
                .unwrap();

            for i in 0..NUM_GATES {
                let gate = GateV5a {
                    in1: if i < 100 { i + 2 } else { NUM_INPUTS + i - 100 },
                    in2: if i < 50 { i + 3 } else { NUM_INPUTS + i - 50 },
                    out: NUM_INPUTS + i,
                    credits: if i >= NUM_GATES - NUM_OUTPUTS as u64 {
                        0 // Output gates
                    } else {
                        1 + (i % 10) as u32
                    },
                    gate_type: i % 7 < 3, // Mix of gate types
                };
                writer.write_gate(gate).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, NUM_GATES);
            assert_eq!(stats.primary_inputs, NUM_INPUTS);
            assert_eq!(stats.num_outputs, NUM_OUTPUTS as u64);
        }

        // Read and verify
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let header = reader.header();
            assert_eq!(header.total_gates(), NUM_GATES);
            let primary_inputs = header.primary_inputs;
            assert_eq!(primary_inputs, NUM_INPUTS);
            let num_outputs = header.num_outputs;
            assert_eq!(num_outputs, NUM_OUTPUTS as u64);

            // Verify outputs match
            assert_eq!(reader.outputs(), outputs.as_slice());

            let mut total_gates_read = 0;
            let mut blocks_read = 0;

            while let Some(block) = reader.next_block().unwrap() {
                blocks_read += 1;
                total_gates_read += block.valid_gates;

                // Spot check some gates
                if blocks_read == 1 {
                    // Check first gate in first block
                    assert_eq!(block.gates[0].in1, 2);
                    assert_eq!(block.gates[0].in2, 3);
                    assert_eq!(block.gates[0].out, NUM_INPUTS);
                }
            }

            assert_eq!(total_gates_read, NUM_GATES as usize);

            let expected_blocks = (NUM_GATES as usize + GATES_PER_BLOCK - 1) / GATES_PER_BLOCK;
            assert_eq!(blocks_read, expected_blocks);

            // Verify checksum
            assert!(reader.verify_checksum().unwrap());
        }
    }

    #[monoio::test]
    async fn test_error_handling() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("errors.v5a");

        // Test wire ID validation
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![]).await.unwrap();

            let invalid_gate = GateV5a {
                in1: MAX_WIRE_ID + 1, // Over limit
                in2: 3,
                out: 4,
                credits: 1,
                gate_type: false,
            };

            assert!(writer.write_gate(invalid_gate).await.is_err());
        }

        // Test credits validation
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![]).await.unwrap();

            let invalid_gate = GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: MAX_CREDITS + 1, // Over limit
                gate_type: false,
            };

            assert!(writer.write_gate(invalid_gate).await.is_err());
        }
    }

    #[monoio::test]
    async fn test_spec_compliance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("spec.v5a");

        // Create the example circuit from the spec
        // Primary inputs: 2 (wires 2, 3)
        // Gate 0: XOR(2, 3) -> 4, credits=2
        // Gate 1: AND(2, 4) -> 5, credits=1
        // Gate 2: XOR(4, 5) -> 6, credits=1
        // Gate 3: AND(5, 6) -> 7, credits=0 (output)
        // Output: wire 7

        let gates = vec![
            GateV5a {
                in1: 2,
                in2: 3,
                out: 4,
                credits: 2,
                gate_type: false, // XOR
            },
            GateV5a {
                in1: 2,
                in2: 4,
                out: 5,
                credits: 1,
                gate_type: true, // AND
            },
            GateV5a {
                in1: 4,
                in2: 5,
                out: 6,
                credits: 1,
                gate_type: false, // XOR
            },
            GateV5a {
                in1: 5,
                in2: 6,
                out: 7,
                credits: 0,      // Output
                gate_type: true, // AND
            },
        ];

        // Write circuit
        {
            let mut writer = CircuitWriterV5a::new(&path, 2, vec![7]).await.unwrap();

            for gate in &gates {
                writer.write_gate(*gate).await.unwrap();
            }

            let stats = writer.finalize().await.unwrap();
            assert_eq!(stats.total_gates, 4);
            assert_eq!(stats.xor_gates, 2);
            assert_eq!(stats.and_gates, 2);
            assert_eq!(stats.primary_inputs, 2);
            assert_eq!(stats.num_outputs, 1);
        }

        // Verify file structure
        {
            let file_content = std::fs::read(&path).unwrap();

            // Check file starts with magic bytes "Zk2u"
            assert_eq!(&file_content[0..4], &[0x5A, 0x6B, 0x32, 0x75]);

            // Check version and format type
            assert_eq!(file_content[4], 0x05); // Version 5
            assert_eq!(file_content[5], 0x00); // Format type A

            // Check reserved bytes
            assert_eq!(file_content[6], 0x00);
            assert_eq!(file_content[7], 0x00);

            // File should be exactly: 72 (header) + 5 (output) + 4064 (one block)
            assert_eq!(file_content.len(), 72 + 5 + 4064);
        }

        // Read and verify
        {
            let mut reader = CircuitReaderV5a::new(&path).await.unwrap();

            let header = reader.header();
            let xor_gates = header.xor_gates;
            assert_eq!(xor_gates, 2);
            let and_gates = header.and_gates;
            assert_eq!(and_gates, 2);
            let primary_inputs = header.primary_inputs;
            assert_eq!(primary_inputs, 2);
            let num_outputs = header.num_outputs;
            assert_eq!(num_outputs, 1);

            assert_eq!(reader.outputs(), &[7]);

            let block = reader.next_block().unwrap().unwrap();
            assert_eq!(block.valid_gates, 4);

            for i in 0..4 {
                assert_eq!(block.gates[i].in1, gates[i].in1);
                assert_eq!(block.gates[i].in2, gates[i].in2);
                assert_eq!(block.gates[i].out, gates[i].out);
                assert_eq!(block.gates[i].credits, gates[i].credits);
                assert_eq!(block.gates[i].gate_type, gates[i].gate_type);
            }

            assert!(reader.verify_checksum().unwrap());
        }
    }
}

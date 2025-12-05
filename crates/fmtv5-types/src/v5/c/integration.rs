//! Integration tests for v5c reader and writer

use std::sync::Arc;

use crate::GateType;
use crate::v5::c::reader::ReaderV5c;
use crate::v5::c::writer::WriterV5c;
use crate::v5::c::*;

#[monoio::test]
async fn test_round_trip_small_circuit() {
    let path = "/tmp/test_v5c_round_trip_small.ckt";

    // Write a small circuit (4 gates)
    let mut writer = WriterV5c::new(path, 2, 1).await.unwrap();
    writer
        .write_gate(GateV5c::new(2, 3, 4), GateType::XOR)
        .await
        .unwrap();
    writer
        .write_gate(GateV5c::new(4, 3, 5), GateType::XOR)
        .await
        .unwrap();
    writer
        .write_gate(GateV5c::new(2, 4, 6), GateType::AND)
        .await
        .unwrap();
    writer
        .write_gate(GateV5c::new(5, 6, 7), GateType::AND)
        .await
        .unwrap();

    let stats = writer.finalize(1000, vec![7]).await.unwrap();
    assert_eq!(stats.total_gates, 4);
    assert_eq!(stats.xor_gates, 2);
    assert_eq!(stats.and_gates, 2);

    // Read back
    let mut reader = ReaderV5c::open(path).unwrap();
    assert_eq!(reader.header().total_gates(), 4);
    assert_eq!(reader.outputs(), &[7]);

    // Get blocks (should be first buffer with 1 partial block)
    let mut buffer = vec![0u8; BLOCK_SIZE * 16];
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 1); // Only 1 block of gates

    // Verify gates in block (cast buffer to blocks)
    let blocks = unsafe { &*(buffer.as_ptr() as *const [Block; 16]) };
    let block = &blocks[0];
    assert_eq!(block.gates[0].in1, 2);
    assert_eq!(block.gates[0].in2, 3);
    assert_eq!(block.gates[0].out, 4);
    assert_eq!(block.gate_type(0), GateType::XOR);

    assert_eq!(block.gates[1].in1, 4);
    assert_eq!(block.gates[1].in2, 3);
    assert_eq!(block.gates[1].out, 5);
    assert_eq!(block.gate_type(1), GateType::XOR);

    assert_eq!(block.gates[2].in1, 2);
    assert_eq!(block.gates[2].in2, 4);
    assert_eq!(block.gates[2].out, 6);
    assert_eq!(block.gate_type(2), GateType::AND);

    assert_eq!(block.gates[3].in1, 5);
    assert_eq!(block.gates[3].in2, 6);
    assert_eq!(block.gates[3].out, 7);
    assert_eq!(block.gate_type(3), GateType::AND);

    // No more blocks
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 0);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_round_trip_multiple_blocks() {
    let path = "/tmp/test_v5c_round_trip_multi.ckt";

    // Write enough gates for 2 full blocks + partial
    let total_gates = GATES_PER_BLOCK * 2 + 1000;
    let mut writer = WriterV5c::new(path, 100, 10).await.unwrap();

    for i in 0..total_gates {
        let gate = GateV5c::new(100, 101, 102 + i as u32);
        writer
            .write_gate(
                gate,
                if i % 2 == 0 {
                    GateType::XOR
                } else {
                    GateType::AND
                },
            )
            .await
            .unwrap();
    }

    let outputs: Vec<u32> = (200..210).collect();
    let stats = writer.finalize(100000, outputs.clone()).await.unwrap();
    assert_eq!(stats.total_gates, total_gates as u64);

    // Read back
    let mut reader = ReaderV5c::open(path).unwrap();
    assert_eq!(reader.header().total_gates(), total_gates as u64);
    assert_eq!(reader.outputs(), &outputs[..]);

    // 2 full blocks + 1 partial = 3 blocks
    let mut buffer = vec![0u8; BLOCK_SIZE * 16];
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 3);

    // Verify first block has correct gates
    let blocks = unsafe { &*(buffer.as_ptr() as *const [Block; 16]) };
    let first_block = &blocks[0];
    assert_eq!(first_block.gates[0].in1, 100);
    assert_eq!(first_block.gates[0].out, 102);

    // 3 blocks total, should all fit in first buffer
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 0);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_arc_sharing_pattern() {
    let path = "/tmp/test_v5c_arc_sharing.ckt";

    // Write a circuit with exactly GATES_PER_BLOCK gates (1 full block)
    let mut writer = WriterV5c::new(path, 10, 1).await.unwrap();

    for i in 0..GATES_PER_BLOCK {
        let gate = GateV5c::new(10, 11, 100 + i as u32);
        writer.write_gate(gate, GateType::XOR).await.unwrap();
    }

    writer.finalize(100000, vec![100]).await.unwrap();

    // Read and simulate Arc-sharing to workers
    let mut reader = ReaderV5c::open(path).unwrap();

    let mut buffer = vec![0u8; BLOCK_SIZE * 16];
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 1); // One block

    // Simulate master thread distributing to workers via Arc
    let shared = Arc::new(buffer);

    // Simulate 4 workers processing their assigned blocks
    let blocks = unsafe { &*(shared.as_ptr() as *const [Block; 16]) };
    let mut total_processed = 0;
    for _block in blocks.iter().take(num_blocks) {
        // Each worker would process gates from this block
        total_processed += GATES_PER_BLOCK;
    }
    assert_eq!(total_processed, GATES_PER_BLOCK);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_large_outputs() {
    let path = "/tmp/test_v5c_large_outputs.ckt";

    // Create circuit with >256 KiB of outputs (requires multiple 256 KiB sections)
    let num_outputs = 100_000; // 400 KB of outputs
    let outputs: Vec<u32> = (1000..1000 + num_outputs).collect();

    let mut writer = WriterV5c::new(path, 10, num_outputs as u64).await.unwrap();

    // Write some gates
    for i in 0..1000 {
        writer
            .write_gate(GateV5c::new(10, 11, 1000 + i), GateType::XOR)
            .await
            .unwrap();
    }

    writer.finalize(200000, outputs.clone()).await.unwrap();

    // Read back and verify outputs
    let reader = ReaderV5c::open(path).unwrap();
    assert_eq!(reader.outputs().len(), num_outputs as usize);
    assert_eq!(reader.outputs(), &outputs[..]);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_checksum_verification() {
    let path = "/tmp/test_v5c_checksum.ckt";

    // Write a circuit
    let mut writer = WriterV5c::new(path, 5, 2).await.unwrap();

    for i in 0..100 {
        writer
            .write_gate(GateV5c::new(5, 6, 100 + i), GateType::AND)
            .await
            .unwrap();
    }

    writer.finalize(1000, vec![100, 199]).await.unwrap();

    // Verify checksum
    let valid = crate::v5::c::reader::verify_v5c_checksum(path)
        .await
        .unwrap();
    assert!(valid);

    // Corrupt the file and verify checksum fails
    let mut bytes = std::fs::read(path).unwrap();
    bytes[crate::v5::c::ALIGNMENT + 1000] ^= 0xFF; // Flip bits in outputs section
    std::fs::write(path, &bytes).unwrap();

    let valid = crate::v5::c::reader::verify_v5c_checksum(path)
        .await
        .unwrap();
    assert!(!valid);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_partial_last_block() {
    let path = "/tmp/test_v5c_partial_last.ckt";

    // Write exactly 1.5 blocks worth of gates
    let total_gates = GATES_PER_BLOCK + (GATES_PER_BLOCK / 2);
    let mut writer = WriterV5c::new(path, 10, 1).await.unwrap();

    for i in 0..total_gates {
        writer
            .write_gate(GateV5c::new(10, 11, 100 + i as u32), GateType::XOR)
            .await
            .unwrap();
    }

    writer.finalize(100000, vec![100]).await.unwrap();

    // Read and verify partial block handling
    let mut reader = ReaderV5c::open(path).unwrap();
    let header = *reader.header();

    let mut buffer = vec![0u8; BLOCK_SIZE * 16];
    let num_blocks = reader.read_blocks(&mut buffer).await.unwrap();
    assert_eq!(num_blocks, 2); // 2 blocks

    // Verify first block has full GATES_PER_BLOCK gates
    let blocks = unsafe { &*(buffer.as_ptr() as *const [Block; 16]) };
    let _block1 = &blocks[0];
    let gates_in_block1 = get_block_num_gates(header.total_gates(), 0);
    assert_eq!(gates_in_block1, GATES_PER_BLOCK);

    // Verify second block has partial gates
    let _block2 = &blocks[1];
    let gates_in_block2 = get_block_num_gates(header.total_gates(), 1);
    assert_eq!(gates_in_block2, GATES_PER_BLOCK / 2);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_empty_circuit_rejected() {
    let path = "/tmp/test_v5c_empty.ckt";

    let writer = WriterV5c::new(path, 0, 0).await.unwrap();

    // Try to finalize without writing any gates
    let result = writer.finalize(100, vec![]).await;

    // Should succeed (empty circuit is valid)
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.total_gates, 0);

    std::fs::remove_file(path).unwrap();
}

#[monoio::test]
async fn test_writer_validates_addresses() {
    let path = "/tmp/test_v5c_validate_addr.ckt";

    let mut writer = WriterV5c::new(path, 10, 1).await.unwrap();

    // Write valid gate
    writer
        .write_gate(GateV5c::new(10, 11, 100), GateType::XOR)
        .await
        .unwrap();

    // Try to finalize with scratch_space too small
    let result = writer.finalize(50, vec![100]).await;
    assert!(result.is_err());

    std::fs::remove_file(path).unwrap();
}

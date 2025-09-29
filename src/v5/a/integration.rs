use crate::v5::a::reader::{CircuitReaderV5a, verify_v5a_checksum};
use crate::v5::a::writer::CircuitWriterV5a;
use tempfile::tempdir;

use crate::{
    GateType,
    v5::a::{BLOCK_SIZE_BYTES, GATES_PER_BLOCK, GateV5a, MAX_CREDITS, MAX_WIRE_ID},
};

fn mk_gate(i: u64) -> GateV5a {
    GateV5a {
        in1: (i * 7 + 1) & MAX_WIRE_ID,
        in2: (i * 11 + 2) & MAX_WIRE_ID,
        out: (i * 13 + 3) & MAX_WIRE_ID,
        credits: (((i as u32) * 5 + 1) & MAX_CREDITS),
        gate_type: if i % 3 == 0 {
            GateType::AND
        } else {
            GateType::XOR
        },
    }
}

async fn write_file(
    path: &std::path::Path,
    primary_inputs: u64,
    outputs: Vec<u64>,
    gates: &[GateV5a],
) {
    let mut w = CircuitWriterV5a::new(path, primary_inputs, outputs)
        .await
        .unwrap();
    w.write_gates(gates).await.unwrap();
    w.finalize().await.unwrap();
}

#[monoio::test]
async fn round_trip_small() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rt_small.v5a");

    let outputs = vec![2, 3, 4, 5, 6];
    let gates: Vec<_> = (0..123u64).map(mk_gate).collect();
    write_file(&path, 42, outputs.clone(), &gates).await;

    let mut r = CircuitReaderV5a::open(&path).unwrap();
    assert_eq!(r.header().primary_inputs, 42);
    assert_eq!(r.outputs(), &outputs[..]);

    // Accumulate all gates back
    let mut acc: Vec<GateV5a> = Vec::new();
    while let Some(v) = r.next_block().await.unwrap() {
        acc.extend(v.into_iter());
    }

    assert_eq!(acc.len(), gates.len());
    for (i, (g0, g1)) in gates.iter().zip(&acc).enumerate() {
        assert_eq!(g0.in1, g1.in1, "in1 mismatch at {}", i);
        assert_eq!(g0.in2, g1.in2, "in2 mismatch at {}", i);
        assert_eq!(g0.out, g1.out, "out mismatch at {}", i);
        assert_eq!(g0.credits, g1.credits, "credits mismatch at {}", i);
        assert_eq!(g0.gate_type, g1.gate_type, "type mismatch at {}", i);
    }

    assert!(verify_v5a_checksum(path).await.unwrap());
}

#[monoio::test]
async fn round_trip_cross_triplebuffer_chunk_boundary() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("rt_big.v5a");

    // Enough blocks to exceed one 4 MiB triple-buffer chunk.
    // blocks_needed = floor(4MiB / 4064) + 5 safety
    const BUFFER_SIZE: usize = 4 * 1024 * 1024;
    let blocks_needed = BUFFER_SIZE / BLOCK_SIZE_BYTES + 5;
    let total_gates = (blocks_needed * GATES_PER_BLOCK) as u64;

    let outputs = vec![9, 10, 11];
    let gates: Vec<_> = (0..total_gates).map(mk_gate).collect();

    write_file(&path, 7, outputs.clone(), &gates).await;

    let mut r = CircuitReaderV5a::open(&path).unwrap();
    assert_eq!(r.outputs(), &outputs[..]);

    // Stream all blocks via SoA, count and validate a few positions
    let mut seen = 0usize;
    let mut probe_positions = [
        0usize,
        GATES_PER_BLOCK - 1,
        GATES_PER_BLOCK + 13,
        gates.len() - 1,
    ];
    probe_positions.sort_unstable();
    let mut next_probe = 0usize;

    while let Some(blk) = r.next_block_soa().await.unwrap() {
        for i in 0..blk.gates_in_block {
            let idx = seen + i;
            if next_probe < probe_positions.len() && idx == probe_positions[next_probe] {
                // Compare with original
                let g = mk_gate(idx as u64);
                assert_eq!(blk.in1[i], g.in1);
                assert_eq!(blk.in2[i], g.in2);
                assert_eq!(blk.out[i], g.out);
                assert_eq!(blk.credits[i], g.credits);
                assert_eq!(blk.gate_types[i], g.gate_type);
                next_probe += 1;
            }
        }
        seen += blk.gates_in_block;
    }
    assert_eq!(seen, gates.len());
    assert!(verify_v5a_checksum(path).await.unwrap());
}

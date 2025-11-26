use std::collections::hash_map::Entry;

use ahash::{HashMap, HashMapExt};
use ckt_fmtv5_types::v5::{a::reader::CircuitReaderV5a, c::*};
use indicatif::ProgressBar;

use crate::slab::FakeSlabAllocator;

pub async fn prealloc(input: &str, output: &str) {
    let mut slab = FakeSlabAllocator::new();

    let mut reader = CircuitReaderV5a::open(input).unwrap();
    let header = reader.header();
    let mut writer = WriterV5c::new(output, header.primary_inputs, header.num_outputs)
        .await
        .unwrap();
    let mut wire_map = WireMap::new();

    for _ in 0..header.primary_inputs + 2 {
        slab.allocate();
    }

    dbg!(reader.outputs());

    let pb = ProgressBar::new(header.total_gates());

    let mut temp_count = 0;

    while let Some(block) = reader.next_block_soa().await.unwrap() {
        for i in 0..block.gates_in_block {
            let in1 = lookup_wire::<false>(
                &mut wire_map,
                &mut slab,
                block.in1[i],
                header.primary_inputs,
            )
            .unwrap();
            let in2 = lookup_wire::<false>(
                &mut wire_map,
                &mut slab,
                block.in2[i],
                header.primary_inputs,
            )
            .unwrap();

            let out_wire_id = slab.allocate();
            wire_map.insert(
                block.out[i],
                WireEntry {
                    slab_idx: out_wire_id,
                    // safe because max creds is like 45k
                    credits_remaining: block.credits[i] as u16,
                },
            );
            writer
                .write_gate(
                    GateV5c {
                        in1: in1 as u32,
                        in2: in2 as u32,
                        out: out_wire_id as u32,
                    },
                    block.gate_types[i],
                )
                .await
                .unwrap();
        }
        temp_count += block.gates_in_block;
        if temp_count > 1_000_000 {
            pb.inc(temp_count as u64);
            temp_count = 0;
        }
    }
    pb.finish();

    let outputs = reader
        .outputs()
        .iter()
        .map(|o| {
            lookup_wire::<true>(&mut wire_map, &mut slab, *o, header.primary_inputs)
                .expect("output wire to be produced by a gate or passed from inputs")
                as u32
        })
        .collect();

    writer
        .finalize(slab.max_allocated_concurrently() as u64, outputs)
        .await
        .unwrap();
}

type AbsoluteWireId = u64;

#[derive(Debug)]
struct WireEntry {
    slab_idx: usize,
    credits_remaining: u16,
}

type WireMap = HashMap<AbsoluteWireId, WireEntry>;

fn lookup_wire<const IGNORE_CREDS: bool>(
    map: &mut WireMap,
    slab: &mut FakeSlabAllocator,
    wire: AbsoluteWireId,
    primary_inputs: u64,
) -> Option<usize> {
    if wire <= primary_inputs + 2 {
        return Some(wire as usize);
    }
    let Entry::Occupied(mut entry) = map.entry(wire) else {
        dbg!(wire);
        return None;
    };

    let idx = entry.get().slab_idx;
    if !IGNORE_CREDS {
        match entry.get().credits_remaining {
            1 => {
                entry.remove();
                slab.deallocate(idx);
            }
            _ => entry.get_mut().credits_remaining -= 1,
        }
    }
    Some(idx)
}

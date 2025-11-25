//! Circuit level size histogram analyzer

use std::collections::hash_map::Entry;

use ahash::{HashMap, HashMapExt};
use ckt_fmtv5_types::v5::a::reader::CircuitReaderV5a;
use indicatif::ProgressBar;
use ckt_lvl::slab::FakeSlabAllocator;

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/Users/user/g16.ckt").unwrap();
    let pb = ProgressBar::new(reader.header().total_gates());

    let perma_wires = reader.header().primary_inputs + 2;

    let mut slab = FakeSlabAllocator::new();
    let mut creds: HashMap<u64, (usize, u32)> = HashMap::new();
    for _ in 0..perma_wires {
        slab.allocate();
    }

    while let Some(block) = reader.next_block_soa().await.unwrap() {
        for i in 0..block.gates_in_block {
            lookup_wire(perma_wires, &mut creds, &mut slab, block.in1[i]);
            lookup_wire(perma_wires, &mut creds, &mut slab, block.in2[i]);
            let out_slab_idx = slab.allocate();
            creds.insert(block.out[i], (out_slab_idx, block.credits[i]));
        }

        pb.inc(block.gates_in_block as u64);
        pb.println(format!("{}", slab.max_allocated_concurrently()));
    }
    pb.finish();
    dbg!(slab.max_allocated_concurrently());
}

fn lookup_wire(
    perma_wires: u64,
    creds: &mut HashMap<u64, (usize, u32)>,
    slab: &mut FakeSlabAllocator,
    wire_id: u64,
) {
    if wire_id <= perma_wires {
        return;
    }
    let Entry::Occupied(mut entry) = creds.entry(wire_id) else {
        panic!("unavailable wire");
    };

    let (slab_idx, creds_remaining) = entry.get_mut();
    match creds_remaining {
        1 => {
            slab.deallocate(*slab_idx);
            entry.remove();
        }
        _ => {
            *creds_remaining -= 1;
        }
    }
}

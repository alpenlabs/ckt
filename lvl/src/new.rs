use std::mem::{swap, take};

use ckt::{
    v5::{
        a::{writer::BlockBuilder, GateV5a, BLOCK_SIZE_BYTES, GATES_PER_BLOCK},
        avx512::{decode_block_v5a_avx512, BlockV5a},
    },
    GateType,
};
use cynosure::hints::unlikely;
use roaring::RoaringBitmap;

use crate::types::{CompactWireId, Credits};

#[derive(Debug, Clone, Copy)]
pub struct IntermediateGate {
    pub in1: u64,
    pub in2: u64,
    pub out: u64,
    pub credits: u32,
}

struct WireTracker {
    map: [RoaringBitmap; 4],
}

impl WireTracker {
    fn bitmap_pos(wire_id: u64) -> (usize, u32) {
        // Use upper 2 bits (bits 32-33) for the index (0-3)
        let idx = (wire_id >> 32) as usize & 0x3;
        // Use lower 32 bits (bits 0-31) as the RoaringBitmap key
        let key = wire_id as u32;
        (idx, key)
    }

    fn get_wire_available(&self, wire_id: u64) -> bool {
        let (idx, key) = Self::bitmap_pos(wire_id);
        self.map[idx].contains(key)
    }

    fn set_wire_available(&mut self, wire_id: u64, available: bool) {
        let (idx, key) = Self::bitmap_pos(wire_id);
        if available {
            self.map[idx].insert(key);
        } else {
            self.map[idx].remove(key);
        }
    }
}

struct Leveller {
    available_wires: WireTracker,
    vec1: Vec<BlockV5a>,
    vec1_gates: usize,

    vec2: Vec<BlockV5a>,
    vec2_gates: usize,
    block_builder: BlockBuilder,
}

impl Leveller {
    fn new(primary_inputs: u64, gates: Vec<BlockV5a>, num_gates: usize) -> Self {
        let mut available_wires = WireTracker {
            map: std::array::from_fn(|_| RoaringBitmap::new()),
        };
        for i in 0..primary_inputs + 2 {
            available_wires.set_wire_available(i, true);
        }
        Self {
            available_wires,
            vec1: gates,
            vec2: Vec::new(),
            vec1_gates: num_gates,
            vec2_gates: 0,
            block_builder: BlockBuilder::new(),
        }
    }

    fn take_level(&mut self) -> Option<Level> {
        let mut gates_left = self.vec1_gates;
        if gates_left == 0 {
            return None;
        }
        let mut level = Level::default();
        let vec1 = take(&mut self.vec1);
        for block in vec1.iter() {
            let gates_in_block = gates_left.min(GATES_PER_BLOCK);
            let mut in1 = [0u64; GATES_PER_BLOCK];
            let mut in2 = [0u64; GATES_PER_BLOCK];
            let mut out = [0u64; GATES_PER_BLOCK];
            let mut credits_out = [0u32; GATES_PER_BLOCK];
            let mut and_gates = [false; GATES_PER_BLOCK];
            unsafe {
                decode_block_v5a_avx512(
                    &block,
                    gates_in_block,
                    &mut in1,
                    &mut in2,
                    &mut out,
                    &mut credits_out,
                    &mut and_gates,
                );
            }

            for i in 0..gates_in_block {
                let in1 = in1[i];
                let in2 = in2[i];
                let out = out[i];
                let credits = credits_out[i];
                let and_gate = and_gates[i];
                let gate_type = if and_gate {
                    GateType::AND
                } else {
                    GateType::XOR
                };
                if unlikely(
                    self.available_wires.get_wire_available(in1)
                        && self.available_wires.get_wire_available(in2),
                ) {
                    let gate = IntermediateGate {
                        in1: in1,
                        in2: in2,
                        out: out,
                        credits,
                    };
                    if and_gate {
                        level.and_gates.push(gate);
                    } else {
                        level.xor_gates.push(gate);
                    }
                } else {
                    self.defer_gate(in1, in2, out, credits, gate_type);
                }
            }
        }

        if !self.block_builder.is_empty() {
            let block = self.block_builder.encode();
            self.vec2.push(block);
            self.vec2_gates += self.block_builder.len();
            self.block_builder.clear();
        }

        self.vec1 = vec1;

        self.vec1.clear();
        swap(&mut self.vec1, &mut self.vec2);
        self.vec1_gates = self.vec2_gates;
        self.vec2_gates = 0;
        self.block_builder.clear();

        for gate in level.xor_gates.iter() {
            self.available_wires.set_wire_available(gate.out, true);
        }
        for gate in level.and_gates.iter() {
            self.available_wires.set_wire_available(gate.out, true);
        }

        Some(level)
    }

    fn defer_gate(&mut self, in1: u64, in2: u64, out: u64, credits: u32, gate_type: GateType) {
        if unlikely(self.block_builder.is_full()) {
            let block = self.block_builder.encode();
            self.vec2.push(block);
            self.vec2_gates += self.block_builder.len();
            self.block_builder.clear();
        }
        self.block_builder
            .push(GateV5a {
                in1,
                in2,
                out,
                credits,
                gate_type,
            })
            .unwrap();
    }
}

#[derive(Debug, Default)]
pub struct Level {
    pub xor_gates: Vec<IntermediateGate>,
    pub and_gates: Vec<IntermediateGate>,
}

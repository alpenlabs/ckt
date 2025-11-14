use blake3::Hasher;
use ckt::{
    GateType,
    v5::c::{Block, reader::ReaderV5c},
};
use gobble::{
    Engine,
    traits::{GarblingInstance, GarblingInstanceConfig, GobbleEngine},
};

#[monoio::main]
async fn main() {
    let filename = std::env::args().nth(1).expect("filename");

    let mut reader = ReaderV5c::open(filename).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let labels: Vec<_> = (0..header.primary_inputs).map(|_| [0u8; 16]).collect();

    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta: [0u8; 16],
        primary_input_false_labels: &labels,
    };

    let mut garb_instance = engine.new_garbling_instance(config);

    let mut hasher = Hasher::new();

    let mut block_idx = 0;
    while let Some((block, num_blocks)) = reader.next_blocks_ref().await.unwrap() {
        let blocks = unsafe { &*(block.as_ptr() as *const [Block; 16]) };
        for block in blocks.iter().take(num_blocks) {
            let gates_in_block = block.num_gates(total_gates, block_idx);
            block_idx += 1;
            for i in 0..gates_in_block {
                let gate = block.gates[i];
                let gate_type = block.gate_type(i);
                match gate_type {
                    GateType::AND => {
                        let ct = garb_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );

                        let bytes: [u8; 16] = unsafe { std::mem::transmute(ct.0) };

                        hasher.update(&bytes);
                    }
                    GateType::XOR => garb_instance.feed_xor_gate(
                        gate.in1 as usize,
                        gate.in2 as usize,
                        gate.out as usize,
                    ),
                }
            }
        }
    }

    let hash = hasher.finalize();
    println!("Hash: {:?}", hash);
}

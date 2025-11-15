use blake3::Hasher;
use ckt::{
    GateType,
    v5::c::{Block, reader::ReaderV5c},
};
use gobble::{
    Engine,
    traits::{GarblingInstance, GarblingInstanceConfig, GobbleEngine},
};
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::time::Instant;

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
    let mut total_gates_processed = 0u64;
    let pb = ProgressBar::new(total_gates);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("🦃 [{bar:50.cyan/blue}] {percent:>3}% | {msg} | {elapsed_precise}")
            .unwrap()
            .progress_chars("█░")
    );
    let start = Instant::now();
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
            
            total_gates_processed += gates_in_block as u64;
            pb.inc(gates_in_block as u64);
        }
        
        let elapsed = start.elapsed();
        if elapsed.as_secs_f64() > 0.0 {
            let rate_m = (total_gates_processed as f64 / elapsed.as_secs_f64()) / 1_000_000.0;
            let processed_b = total_gates_processed as f64 / 1_000_000_000.0;
            let total_b = total_gates as f64 / 1_000_000_000.0;
            pb.set_message(format!("{:.2}B / {:.2}B gates @ {:.0} M/s", processed_b, total_b, rate_m));
        }
    }
    
    pb.finish();
    
    let hash = hasher.finalize();
    println!("\n🔐 Hash: {}", hash.to_hex());
}

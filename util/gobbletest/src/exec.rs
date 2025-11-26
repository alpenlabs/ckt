use ckt_fmtv5_types::{GateType, v5::c::*};
use ckt_gobble::{
    Engine,
    traits::{ExecutionInstance, ExecutionInstanceConfig, GobbleEngine},
};
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::time::Instant;

use crate::common::read_inputs;

pub async fn exec(circuit_file: &str, input_file: &str) -> Vec<bool> {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let input_values_bits = read_inputs(input_file, header.primary_inputs as usize);

    let config = ExecutionInstanceConfig {
        scratch_space: header.scratch_space as u32,
        input_values: &input_values_bits,
    };

    let mut exec_instance = engine.new_execution_instance(config);

    let mut block_idx = 0;
    let mut total_gates_processed = 0u64;
    let pb = ProgressBar::new(total_gates);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("🦃 [{bar:50.cyan/blue}] {percent:>3}% | {msg} | {elapsed_precise}")
            .unwrap()
            .progress_chars("█░"),
    );
    let start = Instant::now();
    while let Some(chunk) = reader.next_blocks_chunk().await.unwrap() {
        for block in chunk.blocks_iter() {
            let gates_in_block = get_block_num_gates(total_gates, block_idx);
            block_idx += 1;
            for i in 0..gates_in_block {
                let gate = block.gates[i];
                let gate_type = block.gate_type(i);
                match gate_type {
                    GateType::AND => {
                        exec_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );
                    }
                    GateType::XOR => exec_instance.feed_xor_gate(
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
            pb.set_message(format!(
                "{:.2}B / {:.2}B gates @ {:.0} M/s",
                processed_b, total_b, rate_m
            ));
        }
    }

    pb.finish();

    let output_wires = reader
        .outputs()
        .iter()
        .map(|w| *w as u64)
        .collect::<Vec<_>>();
    let mut output_values = vec![false; output_wires.len()];
    exec_instance.get_values(&output_wires, &mut output_values);

    println!("Output values: {:?}", output_values);

    output_values
}

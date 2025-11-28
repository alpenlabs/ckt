use bitvec::vec::BitVec;
use ckt_fmtv5_types::{
    GateType,
    v5::c::{Block, reader::ReaderV5c},
};
#[cfg(target_arch = "aarch64")]
use ckt_gobble::aarch64::Ciphertext;
#[cfg(target_arch = "x86_64")]
use ckt_gobble::x86_64::Ciphertext;
use ckt_gobble::{
    Engine,
    traits::{EvaluationInstance, EvaluationInstanceConfig, GobbleEngine},
};
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::fs::File;
use std::io::{BufReader, Read};
use std::time::Instant;

pub async fn eval(
    circuit_file: &str,
    ciphertext_file: &str,
    input_values_bits: &BitVec,
    input_labels: &[[u8; 16]],
) -> (Vec<[u8; 16]>, Vec<bool>) {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: input_labels,
        selected_primary_input_values: input_values_bits,
    };

    let mut eval_instance = engine.new_evaluation_instance(config);

    let garbled_file = File::open(ciphertext_file).unwrap();
    let mut ct_reader = BufReader::new(garbled_file);

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
                        let mut ct_bytes = [0u8; 16];
                        ct_reader.read_exact(&mut ct_bytes).unwrap();
                        let ct = Ciphertext::from(ct_bytes);

                        eval_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                            ct,
                        );
                    }
                    GateType::XOR => eval_instance.feed_xor_gate(
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
    let mut output_labels = vec![[0u8; 16]; output_wires.len()];
    let mut output_values = vec![false; output_wires.len()];
    eval_instance.get_labels(&output_wires, &mut output_labels);
    eval_instance.get_values(&output_wires, &mut output_values);

    println!("Output labels: {:?}", output_labels);
    println!("Output values: {:?}", output_values);

    (output_labels, output_values)
}

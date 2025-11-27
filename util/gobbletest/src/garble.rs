use bitvec::vec::BitVec;
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
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;

use crate::common::read_inputs;

pub async fn garble(
    circuit_file: &str,
    input_file: &str,
    output_file: &str,
    rng: &mut ChaCha20Rng,
) -> ([u8; 16], BitVec, Vec<[u8; 16]>, Vec<[u8; 16]>) {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let labels: Vec<_> = (0..header.primary_inputs)
        .map(|_| {
            let mut label = [0u8; 16];
            rng.fill_bytes(&mut label);
            label
        })
        .collect();

    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta,
        primary_input_false_labels: &labels,
    };

    let mut garb_instance = engine.new_garbling_instance(config);

    let file = File::create(output_file).unwrap();
    let mut writer = BufWriter::new(file);

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
                        let ct = garb_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );

                        let bytes: [u8; 16] = unsafe { std::mem::transmute(ct.0) };

                        writer.write_all(&bytes).unwrap();
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
            pb.set_message(format!(
                "{:.2}B / {:.2}B gates @ {:.0} M/s",
                processed_b, total_b, rate_m
            ));
        }
    }

    pb.finish();

    writer.flush().unwrap();

    let output_wires = reader
        .outputs()
        .iter()
        .map(|w| *w as u64)
        .collect::<Vec<_>>();
    let mut garbler_output_labels = vec![[0u8; 16]; output_wires.len()];
    let output_values = BitVec::repeat(false, output_wires.len());
    garb_instance.get_selected_labels(&output_wires, &output_values, &mut garbler_output_labels);

    println!("\n✓ Garbled circuit written to {}", output_file);

    // Read inputs and encode them
    let input_values_bits = read_inputs(input_file, header.primary_inputs as usize);
    let input_wires: Vec<u64> = (2..=header.primary_inputs + 1).collect();
    let mut input_labels = vec![[0u8; 16]; input_wires.len()];

    garb_instance.get_selected_labels(&input_wires, &input_values_bits, &mut input_labels);

    (
        delta,
        input_values_bits,
        input_labels,
        garbler_output_labels,
    )
}

pub async fn garble_discard(circuit_file: &str, rng: &mut ChaCha20Rng) -> Vec<[u8; 16]> {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let labels: Vec<_> = (0..header.primary_inputs)
        .map(|_| {
            let mut label = [0u8; 16];
            rng.fill_bytes(&mut label);
            label
        })
        .collect();

    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta,
        primary_input_false_labels: &labels,
    };

    let mut garb_instance = engine.new_garbling_instance(config);

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
                        garb_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );
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
    let mut garbler_output_labels = vec![[0u8; 16]; output_wires.len()];
    let output_values = BitVec::repeat(false, output_wires.len());
    garb_instance.get_selected_labels(&output_wires, &output_values, &mut garbler_output_labels);

    garbler_output_labels
}

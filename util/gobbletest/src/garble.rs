use std::fs::File;
use std::io::{BufWriter, sink};

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::*;
use ckt_gobble::traits::{GarblingInstance, GarblingInstanceConfig};
use ckt_runner_exec::{GarbleTask, HashWriter, process_task};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;

use crate::common::{ProgressBarTask, read_inputs};

pub async fn garble(
    circuit_file: &str,
    input_file: &str,
    output_file: &str,
    rng: &mut ChaCha20Rng,
) -> ([u8; 16], BitVec, Vec<[u8; 16]>, Vec<[u8; 16]>) {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();

    // TODO move this setup into `initialize`
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

    let task_info = GarbleTask::new(config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Open the output writer.
    let file = File::create(output_file).unwrap();
    let writer = BufWriter::new(file);

    // Execute the garbling loop.
    //
    // The output from this is the garbler output labels.
    let output = process_task(&task_with_progress, writer, &mut reader)
        .await
        .expect("garble: process task");

    println!("\n✓ Garbled circuit written to {}", output_file);

    // Read inputs and encode them
    let input_values_bits = read_inputs(input_file, header.primary_inputs as usize);
    let input_wires: Vec<u64> = (2..=header.primary_inputs + 1).collect();
    let mut input_labels = vec![[0u8; 16]; input_wires.len()];
    output
        .instance
        .get_selected_labels(&input_wires, &input_values_bits, &mut input_labels);

    (
        delta,
        input_values_bits,
        input_labels,
        output.garbler_output_labels,
    )
}

pub async fn garble_discard(circuit_file: &str, rng: &mut ChaCha20Rng) -> Vec<[u8; 16]> {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();

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

    let task_info = GarbleTask::new(config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Use HashWriter with sink() to discard output while still hashing.
    let writer = HashWriter::new(sink());

    let output = process_task(&task_with_progress, writer, &mut reader)
        .await
        .expect("garble_discard: process task");

    output.garbler_output_labels
}

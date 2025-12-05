use std::fs::File;
use std::io::BufReader;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::traits::EvaluationInstanceConfig;
use ckt_runner_exec::{CircuitReader, EvalTask, ReaderV5cWrapper, process_task};

use crate::common::ProgressBarTask;

pub async fn eval(
    circuit_file: &str,
    ciphertext_file: &str,
    input_values_bits: &BitVec,
    input_labels: &[[u8; 16]],
) -> (Vec<[u8; 16]>, Vec<bool>) {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(circuit_file).unwrap());

    let header = *reader.header();

    let config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: input_labels,
        selected_primary_input_values: input_values_bits,
    };

    let task_info = EvalTask::new(config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Open the ciphertext reader.
    let garbled_file = File::open(ciphertext_file).unwrap();
    let ct_reader = BufReader::new(garbled_file);

    // Execute the evaluation loop.
    let output = process_task(&task_with_progress, ct_reader, &mut reader)
        .await
        .expect("eval: process task");

    println!("Output labels: {:?}", output.output_labels);
    println!("Output values: {:?}", output.output_values);

    (output.output_labels, output.output_values)
}

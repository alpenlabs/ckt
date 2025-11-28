use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::traits::ExecutionInstanceConfig;
use ckt_runner_exec::{ExecTask, process_task};

use crate::common::{ProgressBarTask, read_inputs};

pub async fn exec(circuit_file: &str, input_file: &str) -> Vec<bool> {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();

    let input_values_bits = read_inputs(input_file, header.primary_inputs as usize);

    let config = ExecutionInstanceConfig {
        scratch_space: header.scratch_space as u32,
        input_values: &input_values_bits,
    };

    let task_info = ExecTask::new(config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Execute the circuit.
    let output = process_task(&task_with_progress, (), &mut reader)
        .await
        .expect("exec: process task");

    println!("Output values: {:?}", output.output_values);

    output.output_values
}

use std::fs::File;
use std::io::BufReader;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{
    traits::EvaluationInstanceConfig,
    Label, translate,
};
use ckt_runner_exec::{CircuitReader, EvalTask, ReaderV5cWrapper, process_task};

use crate::common::{
    ProgressBarTask, read_inputs, bits_to_bytes, read_translation_material,
};

/// Evaluation with translation support.
/// 
/// Translates byte labels to bit labels using translation material, then runs standard evaluation.
pub async fn eval_with_translation(
    circuit_file: &str,
    ciphertext_file: &str,
    translation_file: &str,
    input_file: &str,
    byte_labels: &[[u8; 16]],
) -> (Vec<[u8; 16]>, Vec<bool>) {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(circuit_file).unwrap());
    let header = *reader.header();

    // Read inputs as bits and convert to bytes (need to know byte values for translation)
    let num_bits = header.primary_inputs as usize;
    let num_bytes = (num_bits + 7) / 8; // Round up division
    let input_bits = read_inputs(input_file, num_bits);
    let input_bytes = bits_to_bytes(&input_bits, num_bytes);

    assert_eq!(
        byte_labels.len(),
        num_bytes,
        "Expected {} byte labels, got {}",
        num_bytes,
        byte_labels.len()
    );

    // Read translation material from file
    let translation_material = read_translation_material(translation_file, num_bytes);

    // Translate byte labels to bit labels
    // Only translate exactly primary_inputs bits (may be less than num_bytes * 8)
    let mut bit_labels = Vec::new();
    let mut input_values_bits = BitVec::new();
    let mut bit_count = 0;

    for byte_position in 0..num_bytes {
        let byte_label = Label::from(byte_labels[byte_position]);
        let byte_value = input_bytes[byte_position];

        // Translate: byte_label to 8 bit labels
        let translated_bit_labels = unsafe {
            translate(
                byte_position as u64,
                byte_label,
                byte_value,
                translation_material[byte_position],
            )
        };

        // Extract bit values and labels
        for bit_position in 0..8 {
            if bit_count >= header.primary_inputs as usize {
                break;
            }
            let bit_value = ((byte_value >> bit_position) & 1) == 1;
            input_values_bits.push(bit_value);

            let label_bytes: [u8; 16] = translated_bit_labels[bit_position].into();
            bit_labels.push(label_bytes);
            bit_count += 1;
        }
        if bit_count >= header.primary_inputs as usize {
            break;
        }
    }
    
    assert_eq!(
        bit_labels.len(),
        header.primary_inputs as usize,
        "Expected {} bit labels, got {}",
        header.primary_inputs,
        bit_labels.len()
    );

    // Run standard evaluation
    let config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: &bit_labels,
        selected_primary_input_values: &input_values_bits,
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

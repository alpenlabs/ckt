use std::fs::File;
use std::io::BufReader;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{Label, traits::EvaluationInstanceConfig, translate, translate_outputs};
use ckt_runner_exec::{CircuitReader, EvalTask, ReaderV5cWrapper, process_task};

use crate::common::{
    ProgressBarTask, bits_to_bytes, read_inputs, read_output_translation_material,
    read_translation_material,
};

/// Output from evaluation with translation support.
#[derive(Debug)]
pub struct EvalTranslationOutput {
    /// Output labels from evaluation.
    pub output_labels: Vec<[u8; 16]>,
    /// Output boolean values corresponding to the labels.
    pub output_values: Vec<bool>,
    /// Recovered secrets for false outputs (None for true outputs).
    pub recovered_secrets: Vec<Option<[u8; 32]>>,
}

/// Evaluation with translation support.
///
/// Translates byte labels to bit labels using translation material, then runs standard evaluation.
/// Also translates output labels to recover secrets for false outputs.
pub async fn eval_with_translation(
    circuit_file: &str,
    ciphertext_file: &str,
    translation_file: &str,
    output_translation_file: &str,
    input_file: &str,
    byte_labels: &[[u8; 16]],
    aes128_key: [u8; 16],
    public_s: [u8; 16],
) -> EvalTranslationOutput {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(circuit_file).unwrap());
    let header = *reader.header();

    // Read inputs as bits and convert to bytes (need to know byte values for translation)
    let num_bits = header.primary_inputs as usize;
    let num_bytes = num_bits.div_ceil(8);
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
        let translated_bit_labels = translate(
            byte_position as u64,
            byte_label,
            byte_value,
            translation_material[byte_position],
        );

        // Extract bit values and labels
        for (bit_position, translated_label) in translated_bit_labels.iter().enumerate() {
            if bit_count >= header.primary_inputs as usize {
                break;
            }
            let bit_value = ((byte_value >> bit_position) & 1) == 1;
            input_values_bits.push(bit_value);

            let label_bytes: [u8; 16] = (*translated_label).into();
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
        aes128_key,
        public_s,
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

    // Read output translation material and translate outputs
    let output_translation_material = read_output_translation_material(output_translation_file);

    // Convert output labels to Label type
    let output_labels_typed: Vec<Label> = output
        .output_labels
        .iter()
        .map(|bytes| Label::from(*bytes))
        .collect();

    // Translate outputs to recover secrets for false outputs
    let recovered_secrets = translate_outputs(
        &output_labels_typed,
        &output.output_values,
        &output_translation_material,
    );

    EvalTranslationOutput {
        output_labels: output.output_labels,
        output_values: output.output_values,
        recovered_secrets,
    }
}

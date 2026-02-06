use std::fs::File;
use std::io::BufReader;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::ReaderV5c;
use ckt_gobble::{Label, traits::EvaluationInstanceConfig, translate_input, translate_output};
use ckt_runner_exec::{CircuitReader, EvalTask, ReaderV5cWrapper, process_task};

use crate::common::{
    ProgressBarTask, bits_to_bytes, read_input_translation_material, read_inputs,
    read_output_translation_material,
};
use crate::garble::GarblingParams;

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

/// Input configuration for evaluation with translation.
pub struct EvalTranslationConfig<'a> {
    pub circuit_file: &'a str,
    pub ciphertext_file: &'a str,
    pub translation_file: &'a str,
    pub output_translation_file: &'a str,
    pub input_file: &'a str,
    pub byte_labels: &'a [[u8; 16]],
    pub garbling_params: &'a GarblingParams,
}

/// Evaluation with translation support.
///
/// Translates byte labels to bit labels using translation material, then runs standard evaluation.
/// Also translates output labels to recover secrets for false outputs.
pub async fn eval_with_translation(config: EvalTranslationConfig<'_>) -> EvalTranslationOutput {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(config.circuit_file).unwrap());
    let header = *reader.header();

    // Read inputs as bits and convert to bytes (need to know byte values for translation)
    let num_bits = header.primary_inputs as usize;
    let num_bytes = num_bits.div_ceil(8);
    let input_bits = read_inputs(config.input_file, num_bits);
    let input_bytes = bits_to_bytes(&input_bits, num_bytes);

    assert_eq!(
        config.byte_labels.len(),
        num_bytes,
        "Expected {} byte labels, got {}",
        num_bytes,
        config.byte_labels.len()
    );

    // Read translation material from file
    let translation_material = read_input_translation_material(config.translation_file, num_bytes);

    // Translate byte labels to bit labels
    // Only translate exactly primary_inputs bits (may be less than num_bytes * 8)
    let mut bit_labels = Vec::new();
    let mut input_values_bits = BitVec::new();
    let mut bit_count = 0;

    for byte_position in 0..num_bytes {
        let byte_label = Label::from(config.byte_labels[byte_position]);
        let byte_value = input_bytes[byte_position];

        // Translate: byte_label to 8 bit labels
        let translated_bit_labels = translate_input(
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
    let eval_config = EvaluationInstanceConfig {
        scratch_space: header.scratch_space as u32,
        selected_primary_input_labels: &bit_labels,
        selected_primary_input_values: &input_values_bits,
        aes128_key: config.garbling_params.aes128_key,
        public_s: config.garbling_params.public_s,
    };

    let task_info = EvalTask::new(eval_config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Open the ciphertext reader.
    let garbled_file = File::open(config.ciphertext_file).unwrap();
    let ct_reader = BufReader::new(garbled_file);

    // Execute the evaluation loop.
    let output = process_task(&task_with_progress, ct_reader, &mut reader)
        .await
        .expect("eval: process task");

    println!("Output labels: {:?}", output.output_labels);
    println!("Output values: {:?}", output.output_values);

    // Read output translation material and translate outputs
    let output_translation_material =
        read_output_translation_material(config.output_translation_file);

    // Convert output labels to Label type
    let output_labels_typed: Vec<Label> = output
        .output_labels
        .iter()
        .map(|bytes| Label::from(*bytes))
        .collect();

    // Translate outputs to recover secrets for false outputs
    let recovered_secrets = translate_output(
        &output_labels_typed,
        &output.output_values,
        &output_translation_material,
    )
    .expect("output translation inputs must have matching lengths");

    EvalTranslationOutput {
        output_labels: output.output_labels,
        output_values: output.output_values,
        recovered_secrets,
    }
}

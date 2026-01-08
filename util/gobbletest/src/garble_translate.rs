use std::fs::File;
use std::io::BufWriter;

use ckt_fmtv5_types::v5::c::*;
use ckt_gobble::{
    traits::GarblingInstanceConfig,
    BitLabel, ByteLabel, Label, generate_translation_material,
};
use ckt_runner_exec::{CircuitReader, GarbleTask, ReaderV5cWrapper, process_task};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;

use crate::common::{
    ProgressBarTask, read_inputs, bits_to_bytes, generate_byte_labels, write_translation_material,
};

/// Garbling with translation support.
/// 
/// Returns: (delta, byte_labels, translation_file_path, garbler_output_labels)
pub async fn garble_with_translation(
    circuit_file: &str,
    input_file: &str,
    output_file: &str,
    rng: &mut ChaCha20Rng,
    byte_labels: Option<Vec<ByteLabel>>,
) -> ([u8; 16], Vec<[u8; 16]>, String, Vec<[u8; 16]>) {
    let mut reader = ReaderV5cWrapper::new(ReaderV5c::open(circuit_file).unwrap());
    let header = *reader.header();

    // Read inputs as bits and convert to bytes
    let num_bits = header.primary_inputs as usize;
    let num_bytes = (num_bits + 7) / 8; // Round up division
    let input_bits = read_inputs(input_file, num_bits);
    let input_bytes = bits_to_bytes(&input_bits, num_bytes);

    // Generate or use provided byte labels
    let byte_labels_vec = byte_labels.unwrap_or_else(|| {
        generate_byte_labels(num_bytes, rng)
    });

    assert_eq!(
        byte_labels_vec.len(),
        num_bytes,
        "Expected {} byte labels, got {}",
        num_bytes,
        byte_labels_vec.len()
    );

    // Generate global delta (same as used in standard garbling)
    // This delta ensures FreeXOR optimization: true_label = false_label XOR delta
    let mut delta_bytes = [0u8; 16];
    rng.fill_bytes(&mut delta_bytes);
    let delta = Label::from(delta_bytes);

    // Import xor128 function
    #[cfg(target_arch = "aarch64")]
    use ckt_gobble::aarch64::xor128;
    #[cfg(target_arch = "x86_64")]
    use ckt_gobble::x86_64::xor128;

    // Generate bit labels for each byte position
    let mut bit_labels_vec = Vec::new(); // Vec<[BitLabel; 8]>

    for _byte_position in 0..num_bytes {
        // Generate 8 false labels (one per bit position)
        // True labels will be computed as false_label XOR delta (FreeXOR optimization)
        let default_label = Label::from([0u8; 16]);
        let mut bit_labels_array = [BitLabel::new([default_label, default_label]); 8];

        for bit_position in 0..8 {
            // Generate false label (for bit value 0)
            let mut false_label_bytes = [0u8; 16];
            rng.fill_bytes(&mut false_label_bytes);
            let false_label = Label::from(false_label_bytes);

            // Compute true label (for bit value 1) = false_label XOR delta
            // This ensures global delta correlation for FreeXOR optimization
            let true_label = Label(unsafe { xor128(false_label.0, delta.0) });

            bit_labels_array[bit_position] = BitLabel::new([false_label, true_label]);
        }
        bit_labels_vec.push(bit_labels_array);
    }

    // Generate translation material
    let mut translation_material = Vec::new();
    for byte_position in 0..num_bytes {
        let material = unsafe {
            generate_translation_material(
                byte_position as u64,
                byte_labels_vec[byte_position],
                bit_labels_vec[byte_position],
            )
        };
        translation_material.push(material);
    }

    // Write translation material to file
    let translation_file = format!("{}.translation", output_file);
    write_translation_material(&translation_file, &translation_material);
    println!("✓ Translation material written to {}", translation_file);

    // Flatten bit labels for garbling
    // Convert [byte_position][bit_position] -> flat Vec<[u8; 16]>
    // This becomes primary_input_false_labels for standard garbling
    // These labels already have delta correlation (true = false XOR delta)
    // This ensures FreeXOR optimization works correctly
    // Note: Only generate exactly primary_inputs bits (may be less than num_bytes * 8)
    let mut primary_input_false_labels = Vec::new();
    let mut bit_count = 0;
    for byte_position in 0..num_bytes {
        for bit_position in 0..8 {
            if bit_count >= header.primary_inputs as usize {
                break;
            }
            // Get false label (index 0) from BitLabel
            let false_label = bit_labels_vec[byte_position][bit_position].get_label(false);
            let label_bytes: [u8; 16] = false_label.into();
            primary_input_false_labels.push(label_bytes);
            bit_count += 1;
        }
        if bit_count >= header.primary_inputs as usize {
            break;
        }
    }
    
    assert_eq!(
        primary_input_false_labels.len(),
        header.primary_inputs as usize,
        "Expected {} primary input labels, got {}",
        header.primary_inputs,
        primary_input_false_labels.len()
    );

    // Run standard garbling
    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta: delta_bytes, // Same delta used for bit label generation
        primary_input_false_labels: &primary_input_false_labels,
    };

    let task_info = GarbleTask::new(config);
    let task_with_progress = ProgressBarTask::new(task_info);

    // Open the output writer.
    let file = File::create(output_file).unwrap();
    let writer = BufWriter::new(file);

    // Execute the garbling loop.
    let output = process_task(&task_with_progress, writer, &mut reader)
        .await
        .expect("garble: process task");

    println!("\n✓ Garbled circuit written to {}", output_file);

    // Select byte labels based on input bytes
    let mut selected_byte_labels = Vec::new();
    for byte_position in 0..num_bytes {
        let byte_value = input_bytes[byte_position];
        let label = byte_labels_vec[byte_position].get_label(byte_value);
        selected_byte_labels.push(label.into());
    }

    (
        delta_bytes,
        selected_byte_labels,
        translation_file,
        output.garbler_output_labels,
    )
}


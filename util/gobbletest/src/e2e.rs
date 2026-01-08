use crate::{eval, eval_translate, exec, garble, garble_translate};
use rand_chacha::ChaCha20Rng;

pub async fn test_end_to_end(
    circuit_file: &str,
    input_file: &str,
    rng: &mut ChaCha20Rng,
    garbled_file: Option<&str>,
) {
    let garbled_file = garbled_file.unwrap_or("gc.bin");

    println!("🦃 Running end-to-end test: exec → garble → eval\n");

    // Step 1: Execute in cleartext to get expected outputs
    println!("📊 Step 1: Executing circuit in cleartext...");
    let cleartext_outputs = exec::exec(circuit_file, input_file).await;

    // Step 2: Garble the circuit
    println!("\n🔒 Step 2: Garbling circuit...");
    let (delta, input_values_bits, input_labels, garbler_output_labels) =
        garble::garble(circuit_file, input_file, garbled_file, rng).await;

    // Step 3: Evaluate the garbled circuit
    println!("\n🔓 Step 3: Evaluating garbled circuit...");
    let (eval_output_labels, eval_output_values) = eval::eval(
        circuit_file,
        garbled_file,
        &input_values_bits,
        &input_labels,
    )
    .await;

    // Step 4: Verify correctness
    println!("\n✅ Step 4: Verifying correctness...\n");

    let mut all_passed = true;

    // Check that evaluator outputs match cleartext execution
    if eval_output_values != cleartext_outputs {
        println!("❌ FAILED: Evaluator outputs don't match cleartext execution!");
        println!("   Expected: {:?}", cleartext_outputs);
        println!("   Got:      {:?}", eval_output_values);
        all_passed = false;
    } else {
        println!("✓ Evaluator outputs match cleartext execution");
    }

    // Check that output labels are consistent: garbler_label + value*delta = eval_label
    for (i, (garbler_label, eval_label)) in garbler_output_labels
        .iter()
        .zip(eval_output_labels.iter())
        .enumerate()
    {
        let value = eval_output_values[i];

        // Compute expected eval label: garbler_label XOR (value ? delta : 0)
        let expected_eval_label: [u8; 16] = if value {
            xor_labels(garbler_label, &delta)
        } else {
            *garbler_label
        };

        if &expected_eval_label != eval_label {
            println!("❌ FAILED: Output label {} mismatch!", i);
            println!("   Garbler label: {:?}", garbler_label);
            println!("   Delta:         {:?}", delta);
            println!("   Value:         {}", value);
            println!("   Expected eval: {:?}", expected_eval_label);
            println!("   Got eval:      {:?}", eval_label);
            all_passed = false;
        }
    }

    if all_passed {
        println!("✓ All output labels are consistent");
        println!("\n🎉 All tests passed!");
    } else {
        println!("\n❌ Some tests failed!");
        std::process::exit(1);
    }
}

fn xor_labels(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub async fn test_end_to_end_translate(
    circuit_file: &str,
    input_file: &str,
    rng: &mut ChaCha20Rng,
    garbled_file: Option<&str>,
) {
    let garbled_file = garbled_file.unwrap_or("gc.bin");

    println!("🦃 Running end-to-end test with translation: exec → garble → eval\n");

    // Step 1: Execute in cleartext to get expected outputs
    // Input file is already in bits format
    println!("📊 Step 1: Executing circuit in cleartext...");
    let cleartext_outputs = exec::exec(circuit_file, input_file).await;

    // Step 2: Garble the circuit with translation
    // garble_with_translation reads bits directly and converts to bytes internally
    println!("\n🔒 Step 2: Garbling circuit with translation...");
    let (delta, byte_labels, translation_file, garbler_output_labels) =
        garble_translate::garble_with_translation(
            circuit_file,
            input_file,
            garbled_file,
            rng,
            None, // Generate byte labels with RNG
        )
        .await;

    // Step 3: Evaluate the garbled circuit with translation
    // eval_with_translation reads bits directly and converts to bytes internally
    println!("\n🔓 Step 3: Evaluating garbled circuit with translation...");
    let (eval_output_labels, eval_output_values) = eval_translate::eval_with_translation(
        circuit_file,
        garbled_file,
        &translation_file,
        input_file,
        &byte_labels,
    )
    .await;

    // Step 4: Verify correctness
    println!("\n✅ Step 4: Verifying correctness...\n");

    let mut all_passed = true;

    // Check that evaluator outputs match cleartext execution
    if eval_output_values != cleartext_outputs {
        println!("❌ FAILED: Evaluator outputs don't match cleartext execution!");
        println!("   Expected: {:?}", cleartext_outputs);
        println!("   Got:      {:?}", eval_output_values);
        all_passed = false;
    } else {
        println!("✓ Evaluator outputs match cleartext execution");
    }

    // Check that output labels are consistent: garbler_label + value*delta = eval_label
    for (i, (garbler_label, eval_label)) in garbler_output_labels
        .iter()
        .zip(eval_output_labels.iter())
        .enumerate()
    {
        let value = eval_output_values[i];

        // Compute expected eval label: garbler_label XOR (value ? delta : 0)
        let expected_eval_label: [u8; 16] = if value {
            xor_labels(garbler_label, &delta)
        } else {
            *garbler_label
        };

        if &expected_eval_label != eval_label {
            println!("❌ FAILED: Output label {} mismatch!", i);
            println!("   Garbler label: {:?}", garbler_label);
            println!("   Delta:         {:?}", delta);
            println!("   Value:         {}", value);
            println!("   Expected eval: {:?}", expected_eval_label);
            println!("   Got eval:      {:?}", eval_label);
            all_passed = false;
        }
    }

    if all_passed {
        println!("✓ All output labels are consistent");
        println!("\n🎉 All tests passed!");
    } else {
        println!("\n❌ Some tests failed!");
        std::process::exit(1);
    }
}

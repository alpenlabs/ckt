use crate::eval_translate::EvalTranslationConfig;
use crate::garble::GarblingParams;
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
    let (delta, input_values_bits, input_labels, garbler_output_labels, garbling_params) =
        garble::garble(circuit_file, input_file, garbled_file, rng).await;

    // Step 3: Evaluate the garbled circuit
    // The garbling_params (AES key and public S) are passed to the evaluator
    println!("\n🔓 Step 3: Evaluating garbled circuit...");
    let (eval_output_labels, eval_output_values) = eval::eval(
        circuit_file,
        garbled_file,
        &input_values_bits,
        &input_labels,
        &garbling_params,
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
    println!("📊 Step 1: Executing circuit in cleartext...");
    let cleartext_outputs = exec::exec(circuit_file, input_file).await;

    // Step 2: Garble the circuit with translation
    println!("\n🔒 Step 2: Garbling circuit with translation...");
    let garble_output = garble_translate::garble_with_translation(
        circuit_file,
        input_file,
        garbled_file,
        rng,
        None,
    )
    .await;

    // Step 3: Evaluate the garbled circuit with translation
    println!("\n🔓 Step 3: Evaluating garbled circuit with translation...");
    let garbling_params = GarblingParams {
        aes128_key: garble_output.aes128_key,
        public_s: garble_output.public_s,
    };
    let eval_output = eval_translate::eval_with_translation(EvalTranslationConfig {
        circuit_file,
        ciphertext_file: garbled_file,
        translation_file: &garble_output.translation_file,
        output_translation_file: &garble_output.output_translation_file,
        input_file,
        byte_labels: &garble_output.selected_byte_labels,
        garbling_params: &garbling_params,
    })
    .await;

    // Step 4: Verify correctness
    println!("\n✅ Step 4: Verifying correctness...");

    let mut all_passed = true;

    // Check that evaluator outputs match cleartext execution
    if eval_output.output_values != cleartext_outputs {
        println!("❌ FAILED: Evaluator outputs don't match cleartext execution!");
        println!("   Expected: {:?}", cleartext_outputs);
        println!("   Got:      {:?}", eval_output.output_values);
        all_passed = false;
    } else {
        println!("✓ Evaluator outputs match cleartext execution");
    }

    // Check that output labels are consistent: garbler_label + value*delta = eval_label
    for (i, (garbler_label, eval_label)) in garble_output
        .garbler_output_labels
        .iter()
        .zip(eval_output.output_labels.iter())
        .enumerate()
    {
        let value = eval_output.output_values[i];

        // Compute expected eval label: garbler_label XOR (value ? delta : 0)
        let expected_eval_label: [u8; 16] = if value {
            xor_labels(garbler_label, &garble_output.delta)
        } else {
            *garbler_label
        };

        if &expected_eval_label != eval_label {
            println!("❌ FAILED: Output label {} mismatch!", i);
            println!("   Garbler label: {:?}", garbler_label);
            println!("   Delta:         {:?}", garble_output.delta);
            println!("   Value:         {}", value);
            println!("   Expected eval: {:?}", expected_eval_label);
            println!("   Got eval:      {:?}", eval_label);
            all_passed = false;
        }
    }

    if all_passed {
        println!("✓ All output labels are consistent");
    }

    // Check output translation: secrets should be recovered for false outputs
    for (i, (recovered, expected_secret)) in eval_output
        .recovered_secrets
        .iter()
        .zip(garble_output.secrets.iter())
        .enumerate()
    {
        let value = eval_output.output_values[i];

        if value {
            // True output: should NOT be able to decrypt
            if recovered.is_some() {
                println!("❌ FAILED: Output {} is true but secret was recovered!", i);
                all_passed = false;
            }
        } else {
            // False output: should be able to decrypt and recover correct secret
            match recovered {
                Some(secret) => {
                    if secret != expected_secret {
                        println!("❌ FAILED: Output {} secret mismatch!", i);
                        println!("   Expected: {:?}", expected_secret);
                        println!("   Got:      {:?}", secret);
                        all_passed = false;
                    }
                }
                None => {
                    println!("❌ FAILED: Output {} is false but no secret recovered!", i);
                    all_passed = false;
                }
            }
        }
    }

    if all_passed {
        println!("✓ Output translation secrets verified");
        println!("\n🎉 All tests passed!");
    } else {
        println!("\n❌ Some tests failed!");
        std::process::exit(1);
    }
}

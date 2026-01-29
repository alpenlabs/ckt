//! Output translation layer: embed and recover secrets from output labels
//!
//! This module provides output translation for conditional secret disclosure.
//! The garbler embeds 256-bit secrets that can only be recovered when the
//! circuit output evaluates to false.

use crate::input_translate::BitLabel;
use crate::types::{Label, xor_bytes};

/// 256-bit ciphertext for output translation (one per output bit).
/// Contains: H(L_out,0) ⊕ secret
pub type OutputTranslationCiphertext = [u8; 32];

/// Translation material for all circuit outputs.
pub type OutputTranslationMaterial = Vec<OutputTranslationCiphertext>;

/// Expands a 128-bit label to 256 bits (2× expansion) using Blake3 XOF.
///
/// This is used for output translation to expand a 128-bit label
/// to a 256-bit value for encrypting/decrypting secrets.
///
/// # Arguments
///
/// * `label` - Input label (128 bits)
/// * `index` - Index value for domain separation
///
/// # Returns
///
/// 256-bit hash output (32 bytes)
pub fn wide_hash_2x(label: Label, index: u64) -> [u8; 32] {
    // Convert label to bytes
    let label_bytes: [u8; 16] = label.into();

    // Create input: label (16 bytes) + index (8 bytes, little-endian)
    let mut input = [0u8; 24];
    input[0..16].copy_from_slice(&label_bytes);
    input[16..24].copy_from_slice(&index.to_le_bytes());

    // Hash using Blake3 and get XOF output (32 bytes = 256 bits)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input);
    let mut output = [0u8; 32];
    hasher.finalize_xof().fill(&mut output);

    output
}

/// Generates output translation material for embedding secrets.
///
/// For each output bit, creates a ciphertext C = H(L_out,0) ⊕ secret
/// where H is Blake3 XOF expanding to 256 bits.
///
/// # Arguments
///
/// * `output_labels` - Output labels from garbling (BitLabel per output, contains both false and true labels)
/// * `secrets` - 256-bit secrets to embed (one per output)
///
/// # Returns
///
/// Vector of ciphertexts, one per output
pub fn generate_output_translation_material(
    output_labels: &[BitLabel],
    secrets: &[[u8; 32]],
) -> OutputTranslationMaterial {
    assert_eq!(
        output_labels.len(),
        secrets.len(),
        "Number of output labels must match number of secrets"
    );

    output_labels
        .iter()
        .zip(secrets.iter())
        .enumerate()
        .map(|(i, (label, secret))| {
            // Get the false label (L_out,0)
            let false_label = label.get_label(false);
            // Hash the false label to 256 bits
            let hash = wide_hash_2x(false_label, i as u64);
            // XOR with secret to create ciphertext
            xor_bytes(hash, *secret)
        })
        .collect()
}

/// Translates output labels to recover secrets for outputs that evaluated to false.
///
/// For each output:
/// - If output value is false: evaluator has L_out,0 and can decrypt to get secret
/// - If output value is true: evaluator has L_out,1 and cannot decrypt (returns None)
///
/// # Arguments
///
/// * `output_labels` - Output labels from evaluation (one per output)
/// * `output_values` - Output boolean values (from privacy-free evaluation)
/// * `output_translation_material` - Ciphertexts from garbler
///
/// # Returns
///
/// Vector of Option<[u8; 32]>: Some(secret) for false outputs, None for true outputs
pub fn translate_output(
    output_labels: &[Label],
    output_values: &[bool],
    output_translation_material: &OutputTranslationMaterial,
) -> Vec<Option<[u8; 32]>> {
    assert_eq!(
        output_labels.len(),
        output_values.len(),
        "Number of output labels must match number of output values"
    );
    assert_eq!(
        output_labels.len(),
        output_translation_material.len(),
        "Number of output labels must match number of ciphertexts"
    );

    output_labels
        .iter()
        .zip(output_values.iter())
        .zip(output_translation_material.iter())
        .enumerate()
        .map(|(i, ((label, &value), ciphertext))| {
            if value {
                // Output is true, evaluator has L_out,1, cannot decrypt
                None
            } else {
                // Output is false, evaluator has L_out,0, can decrypt
                let hash = wide_hash_2x(*label, i as u64);
                Some(xor_bytes(hash, *ciphertext))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::expand_seed;

    #[test]
    fn test_output_translation_roundtrip() {
        // Generate random output labels (2 labels per output: false and true)
        let seed = [55u8; 32];
        let (labels, _delta) = expand_seed(seed, 10); // 5 outputs * 2 labels each

        let mut output_labels = Vec::new();
        for i in 0..5 {
            output_labels.push(BitLabel::new([labels[i * 2], labels[i * 2 + 1]]));
        }

        // Generate arbitrary 256-bit secrets
        let mut secrets = Vec::new();
        for i in 0..5 {
            let mut secret = [0u8; 32];
            for (j, byte) in secret.iter_mut().enumerate() {
                *byte = ((i * 32 + j) as u8).wrapping_mul(17);
            }
            secrets.push(secret);
        }

        // Generate output translation material
        let material = generate_output_translation_material(&output_labels, &secrets);
        assert_eq!(material.len(), 5);

        // Test: for false outputs, we should recover the secret
        // Simulate evaluator having false labels
        let eval_labels: Vec<Label> = output_labels.iter().map(|bl| bl.get_label(false)).collect();
        let output_values = vec![false, false, false, false, false];

        let recovered = translate_output(&eval_labels, &output_values, &material);

        for i in 0..5 {
            assert!(recovered[i].is_some(), "Output {} should decrypt", i);
            assert_eq!(recovered[i].unwrap(), secrets[i], "Secret {} mismatch", i);
        }
    }

    #[test]
    fn test_output_translation_false_output_decrypts() {
        // Single output that is false
        let seed = [66u8; 32];
        let (labels, _) = expand_seed(seed, 2);
        let output_label = BitLabel::new([labels[0], labels[1]]);

        let secret = [0xABu8; 32]; // Known secret

        let material = generate_output_translation_material(&[output_label], &[secret]);

        // Evaluator has false label
        let eval_labels = vec![output_label.get_label(false)];
        let output_values = vec![false];

        let recovered = translate_output(&eval_labels, &output_values, &material);

        assert!(recovered[0].is_some());
        assert_eq!(recovered[0].unwrap(), secret);
    }

    #[test]
    fn test_output_translation_true_output_returns_none() {
        // Single output that is true
        let seed = [77u8; 32];
        let (labels, _) = expand_seed(seed, 2);
        let output_label = BitLabel::new([labels[0], labels[1]]);

        let secret = [0xCDu8; 32];

        let material = generate_output_translation_material(&[output_label], &[secret]);

        // Evaluator has TRUE label (cannot decrypt)
        let eval_labels = vec![output_label.get_label(true)];
        let output_values = vec![true];

        let recovered = translate_output(&eval_labels, &output_values, &material);

        assert!(recovered[0].is_none(), "True output should return None");
    }

    #[test]
    fn test_output_translation_mixed_outputs() {
        // Mix of true and false outputs
        let seed = [88u8; 32];
        let (labels, _) = expand_seed(seed, 8); // 4 outputs * 2 labels

        let mut output_labels = Vec::new();
        for i in 0..4 {
            output_labels.push(BitLabel::new([labels[i * 2], labels[i * 2 + 1]]));
        }

        let secrets: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut s = [0u8; 32];
                s.fill(i as u8);
                s
            })
            .collect();

        let material = generate_output_translation_material(&output_labels, &secrets);

        // Outputs: false, true, false, true
        let output_values = vec![false, true, false, true];
        let eval_labels: Vec<Label> = output_labels
            .iter()
            .zip(output_values.iter())
            .map(|(bl, &val)| bl.get_label(val))
            .collect();

        let recovered = translate_output(&eval_labels, &output_values, &material);

        // Output 0: false -> should decrypt
        assert!(recovered[0].is_some());
        assert_eq!(recovered[0].unwrap(), secrets[0]);

        // Output 1: true -> should NOT decrypt
        assert!(recovered[1].is_none());

        // Output 2: false -> should decrypt
        assert!(recovered[2].is_some());
        assert_eq!(recovered[2].unwrap(), secrets[2]);

        // Output 3: true -> should NOT decrypt
        assert!(recovered[3].is_none());
    }
}

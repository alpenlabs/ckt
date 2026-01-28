//! Architecture-agnostic translation layer implementation
//!
//! This module provides translation between byte labels and bit labels,
//! using Blake3 XOF for hash expansion.

use crate::types::{Ciphertext, Label};

/// XOR two 16-byte arrays.
#[inline]
fn xor_bytes(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Bit label type, representing value 0 or 1
#[derive(Debug, Clone, Copy)]
pub struct BitLabel([Label; 2]);

impl BitLabel {
    /// Creates a new BitLabel from an array of 2 labels
    pub const fn new(labels: [Label; 2]) -> Self {
        BitLabel(labels)
    }

    /// Returns the label for the given bit value
    pub const fn get_label(&self, value: bool) -> Label {
        if value { self.0[1] } else { self.0[0] }
    }
}

/// Byte label type, representing value 0-255
#[derive(Debug, Clone, Copy)]
pub struct ByteLabel([Label; 256]);

impl ByteLabel {
    /// Creates a new ByteLabel from an array of 256 labels
    pub const fn new(labels: [Label; 256]) -> Self {
        ByteLabel(labels)
    }

    /// Returns the label for the given byte value
    pub const fn get_label(&self, value: u8) -> Label {
        self.0[value as usize]
    }
}

/// Translation material: `[[Ciphertext; 8]; 256]`
///
/// - 256 possible byte values (0..255)
/// - 8 ciphertexts per byte value (one per input bit position)
/// - Size: 256 × 8 × 16 bytes = 32KB per byte position
pub type TranslationMaterial = [[Ciphertext; 8]; 256];

/// Expands hash to 8x width using Blake3 XOF (extendable output function).
///
/// The implementation uses Blake3's XOF to generate 128 bytes (8 labels * 16 bytes)
/// with proper domain separation via the index parameter.
///
/// # Arguments
///
/// * `label` - Input label (128 bits)
/// * `index` - Index value for domain separation
///
/// # Returns
///
/// Array of 8 labels, each 128 bits (16 bytes)
pub fn wide_hash(label: Label, index: u64) -> [Label; 8] {
    // Convert label to bytes
    let label_bytes: [u8; 16] = label.into();

    // Create input: label (16 bytes) + index (8 bytes, little-endian)
    let mut input = [0u8; 24];
    input[0..16].copy_from_slice(&label_bytes);
    input[16..24].copy_from_slice(&index.to_le_bytes());

    // Hash using Blake3 and get XOF output (128 bytes = 8 labels * 16 bytes)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input);
    let mut output = [0u8; 128]; // 8 labels * 16 bytes
    hasher.finalize_xof().fill(&mut output);

    // Split into 8 labels
    let mut labels = [Label::default(); 8];
    for i in 0..8 {
        let mut label_bytes = [0u8; 16];
        label_bytes.copy_from_slice(&output[i * 16..(i + 1) * 16]);
        labels[i] = Label::from(label_bytes);
    }

    labels
}

/// Generates garbled material required to translate ByteLabel component to BitLabel components.
pub fn generate_translation_material(
    byte_position: u64,
    byte_label: ByteLabel,
    bit_labels: [BitLabel; 8],
) -> TranslationMaterial {
    let mut ciphertexts = [[Ciphertext::default(); 8]; 256];

    // For each possible byte value (0 to 255)
    for (i, row) in ciphertexts.iter_mut().enumerate() {
        // Get the label for this byte value
        let input_label = byte_label.get_label(i as u8);

        // Hash the input label to get 8 labels (one for each input bit position)
        let hashed_labels = wide_hash(input_label, byte_position * 256 + i as u64);

        // For each input bit position (within the byte)
        for bit_position in 0..8 {
            // Extract the bit at position bit_position from the byte value i
            let bit_value = ((i >> bit_position) & 1) == 1;

            // Get the appropriate bit label (0 or 1) based on the bit value of i
            // This implements: C[i][j] = H_j(byte_label[i]) ⊕ bit_labels[j][bit_j_of_i]
            let bit_label = bit_labels[bit_position].get_label(bit_value);

            // XOR the hashed label with the bit label to create the ciphertext
            let hashed_bytes: [u8; 16] = hashed_labels[bit_position].into();
            let bit_label_bytes: [u8; 16] = bit_label.into();
            row[bit_position] = Ciphertext::from(xor_bytes(hashed_bytes, bit_label_bytes));
        }
    }

    ciphertexts
}

/// Translates a ByteLabel component to 8 BitLabel components using the translation material.
///
/// Given a label for a specific byte value, this function recovers the 8 bit labels
/// corresponding to each bit of that byte value.
pub fn translate(
    byte_position: u64,
    byte_label_component: Label,
    value: u8,
    translation_material: TranslationMaterial,
) -> [Label; 8] {
    // Hash the byte label component to get 8 hashed labels (one for each input bit position)
    let hashed_labels = wide_hash(byte_label_component, byte_position * 256 + value as u64);

    // Get the ciphertexts for this specific byte value
    let ciphertexts = translation_material[value as usize];

    // Decrypt each ciphertext to recover the input bit labels
    // Since C[i][j] = H_j(byte_label[i]) ⊕ bit_label[j]
    // We can recover: bit_label[j] = C[i][j] ⊕ H_j(byte_label[i])
    let mut bit_labels = [Label::default(); 8];
    for bit_position in 0..8 {
        let ciphertext_bytes: [u8; 16] = ciphertexts[bit_position].into();
        let hashed_bytes: [u8; 16] = hashed_labels[bit_position].into();
        bit_labels[bit_position] = Label::from(xor_bytes(ciphertext_bytes, hashed_bytes));
    }

    bit_labels
}

/// 256-bit ciphertext for output translation (one per output bit).
/// Contains: H(L_out,0) ⊕ secret
pub type OutputTranslationCiphertext = [u8; 32];

/// Translation material for all circuit outputs.
pub type OutputTranslationMaterial = Vec<OutputTranslationCiphertext>;

/// XOR two 32-byte arrays.
#[inline]
fn xor_bytes_32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Expands a 128-bit label to 256 bits using Blake3 XOF.
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
pub fn wide_hash_256(label: Label, index: u64) -> [u8; 32] {
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
            let hash = wide_hash_256(false_label, i as u64);
            // XOR with secret to create ciphertext
            xor_bytes_32(hash, *secret)
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
pub fn translate_outputs(
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
                let hash = wide_hash_256(*label, i as u64);
                Some(xor_bytes_32(hash, *ciphertext))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "aarch64")]
    use crate::aarch64::expand_seed;

    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::expand_seed;

    #[test]
    fn test_translation_roundtrip() {
        // Generate random labels for a ByteLabel (256 labels, one for each byte value)
        let seed = [42u8; 32];
        let (byte_labels, _) = expand_seed(seed, 256);
        let byte_label = ByteLabel::new(byte_labels.try_into().unwrap());

        // Generate random labels for 8 BitLabels (each has 2 labels: for 0 and 1)
        let seed2 = [43u8; 32];
        let (bit_labels_flat, _) = expand_seed(seed2, 16); // 8 bits * 2 labels each
        let default_label = Label::default();
        let mut bit_labels = [BitLabel::new([default_label, default_label]); 8];
        for i in 0..8 {
            bit_labels[i] = BitLabel::new([bit_labels_flat[i * 2], bit_labels_flat[i * 2 + 1]]);
        }

        // Generate translation material
        let translation_material = generate_translation_material(0, byte_label, bit_labels);

        // Test translation for various byte values
        for test_value in [0u8, 1, 7, 15, 42, 128, 255] {
            // Get the byte label for this value
            let byte_label_component = byte_label.get_label(test_value);

            // Translate to get 8 bit labels
            let recovered_labels =
                translate(0, byte_label_component, test_value, translation_material);

            // Verify each bit label matches the expected value
            for bit_position in 0..8 {
                // Extract the bit value at this position from test_value
                let bit_value = ((test_value >> bit_position) & 1) == 1;

                // Get the expected label for this bit value
                let expected_label = bit_labels[bit_position].get_label(bit_value);

                // Compare the recovered label with the expected label
                let recovered_bytes: [u8; 16] = recovered_labels[bit_position].into();
                let expected_bytes: [u8; 16] = expected_label.into();

                assert_eq!(
                    recovered_bytes, expected_bytes,
                    "Mismatch for value {} at bit position {}: expected bit value {}",
                    test_value, bit_position, bit_value
                );
            }
        }
    }

    #[test]
    fn test_translation_all_values() {
        // Test all 256 possible byte values
        let seed = [99u8; 32];
        let (byte_labels, _) = expand_seed(seed, 256);
        let byte_label = ByteLabel::new(byte_labels.try_into().unwrap());

        let seed2 = [100u8; 32];
        let (bit_labels_flat, _) = expand_seed(seed2, 16);
        let default_label = Label::default();
        let mut bit_labels = [BitLabel::new([default_label, default_label]); 8];
        for i in 0..8 {
            bit_labels[i] = BitLabel::new([bit_labels_flat[i * 2], bit_labels_flat[i * 2 + 1]]);
        }

        let translation_material = generate_translation_material(0, byte_label, bit_labels);

        // Test all 256 possible byte values
        for test_value in 0u8..=255 {
            let byte_label_component = byte_label.get_label(test_value);
            let recovered_labels =
                translate(0, byte_label_component, test_value, translation_material);

            // Verify all 8 bits
            for bit_position in 0..8 {
                let bit_value = ((test_value >> bit_position) & 1) == 1;
                let expected_label = bit_labels[bit_position].get_label(bit_value);

                let recovered_bytes: [u8; 16] = recovered_labels[bit_position].into();
                let expected_bytes: [u8; 16] = expected_label.into();

                assert_eq!(
                    recovered_bytes, expected_bytes,
                    "Mismatch for value {} at bit position {}",
                    test_value, bit_position
                );
            }
        }
    }

    #[test]
    fn test_translation_bit_patterns() {
        // Test specific bit patterns: all zeros, all ones, alternating patterns
        let seed = [77u8; 32];
        let (byte_labels, _) = expand_seed(seed, 256);
        let byte_label = ByteLabel::new(byte_labels.try_into().unwrap());

        let seed2 = [88u8; 32];
        let (bit_labels_flat, _) = expand_seed(seed2, 16);
        let default_label = Label::default();
        let mut bit_labels = [BitLabel::new([default_label, default_label]); 8];
        for i in 0..8 {
            bit_labels[i] = BitLabel::new([bit_labels_flat[i * 2], bit_labels_flat[i * 2 + 1]]);
        }

        let translation_material = generate_translation_material(0, byte_label, bit_labels);

        // Test specific patterns
        let test_patterns = [
            0b00000000, // All zeros
            0b11111111, // All ones
            0b10101010, // Alternating 1010...
            0b01010101, // Alternating 0101...
            0b11110000, // Half and half
            0b00001111, // Other half
        ];

        for &test_value in &test_patterns {
            let byte_label_component = byte_label.get_label(test_value);
            let recovered_labels =
                translate(0, byte_label_component, test_value, translation_material);

            for bit_position in 0..8 {
                let bit_value = ((test_value >> bit_position) & 1) == 1;
                let expected_label = bit_labels[bit_position].get_label(bit_value);

                let recovered_bytes: [u8; 16] = recovered_labels[bit_position].into();
                let expected_bytes: [u8; 16] = expected_label.into();

                assert_eq!(
                    recovered_bytes, expected_bytes,
                    "Mismatch for pattern {:08b} (value {}) at bit position {}",
                    test_value, test_value, bit_position
                );
            }
        }
    }

    // ==================== Output Translation Tests ====================

    #[test]
    fn test_output_translation_roundtrip() {
        use super::{generate_output_translation_material, translate_outputs};

        // Generate random output labels (2 labels per output: false and true)
        let seed = [55u8; 32];
        let (labels, _delta) = expand_seed(seed, 10); // 5 outputs * 2 labels each

        let mut output_labels = Vec::new();
        for i in 0..5 {
            output_labels.push(BitLabel::new([labels[i * 2], labels[i * 2 + 1]]));
        }

        // Generate random 256-bit secrets
        let mut secrets = Vec::new();
        for i in 0..5 {
            let mut secret = [0u8; 32];
            for j in 0..32 {
                secret[j] = ((i * 32 + j) as u8).wrapping_mul(17);
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

        let recovered = translate_outputs(&eval_labels, &output_values, &material);

        for i in 0..5 {
            assert!(recovered[i].is_some(), "Output {} should decrypt", i);
            assert_eq!(recovered[i].unwrap(), secrets[i], "Secret {} mismatch", i);
        }
    }

    #[test]
    fn test_output_translation_false_output_decrypts() {
        use super::{generate_output_translation_material, translate_outputs};

        // Single output that is false
        let seed = [66u8; 32];
        let (labels, _) = expand_seed(seed, 2);
        let output_label = BitLabel::new([labels[0], labels[1]]);

        let secret = [0xABu8; 32]; // Known secret

        let material = generate_output_translation_material(&[output_label], &[secret]);

        // Evaluator has false label
        let eval_labels = vec![output_label.get_label(false)];
        let output_values = vec![false];

        let recovered = translate_outputs(&eval_labels, &output_values, &material);

        assert!(recovered[0].is_some());
        assert_eq!(recovered[0].unwrap(), secret);
    }

    #[test]
    fn test_output_translation_true_output_returns_none() {
        use super::{generate_output_translation_material, translate_outputs};

        // Single output that is true
        let seed = [77u8; 32];
        let (labels, _) = expand_seed(seed, 2);
        let output_label = BitLabel::new([labels[0], labels[1]]);

        let secret = [0xCDu8; 32];

        let material = generate_output_translation_material(&[output_label], &[secret]);

        // Evaluator has TRUE label (cannot decrypt)
        let eval_labels = vec![output_label.get_label(true)];
        let output_values = vec![true];

        let recovered = translate_outputs(&eval_labels, &output_values, &material);

        assert!(recovered[0].is_none(), "True output should return None");
    }

    #[test]
    fn test_output_translation_mixed_outputs() {
        use super::{generate_output_translation_material, translate_outputs};

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

        let recovered = translate_outputs(&eval_labels, &output_values, &material);

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

//! Architecture-agnostic translation layer implementation
//!
//! This module provides translation between byte labels and bit labels,
//! supporting both aarch64 and x86_64 architectures through conditional compilation.

// Conditional imports based on target architecture
#[cfg(target_arch = "aarch64")]
use crate::aarch64::{Ciphertext, Label, hash, index_to_tweak, xor128};

#[cfg(target_arch = "x86_64")]
use crate::x86_64::{Ciphertext, Label, hash, index_to_tweak, xor128};

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

/// Macro to generate translation functions with architecture-specific target features.
/// This avoids duplicating function bodies while allowing different target_feature attributes.
macro_rules! impl_translation_fns {
    ($($target_feature:literal),+) => {
        /// Expands hash to 8x width using Fixed Key AES and different tweaks for each bit position.
        ///
        /// # Safety
        ///
        /// The caller must ensure the CPU supports the required target features (AES and NEON/SSE2).
        $(#[target_feature(enable = $target_feature)])+
        pub unsafe fn wide_hash(label: Label, index: u64) -> [Label; 8] {
            let mut labels = [Label::default(); 8];
            for i in 0..8 {
                labels[i] = Label(unsafe { hash(label.0, index_to_tweak(index*8 + i as u64)) });
            }
            labels
        }

        /// Generates garbled material required to translate ByteLabel component to BitLabel components.
        ///
        /// # Safety
        ///
        /// The caller must ensure the CPU supports the required target features (AES and NEON/SSE2).
        $(#[target_feature(enable = $target_feature)])+
        pub unsafe fn generate_translation_material(
            byte_position: u64,
            byte_label: ByteLabel,
            bit_labels: [BitLabel; 8],
        ) -> TranslationMaterial {
            let mut ciphertexts = [[Ciphertext(Label::default().0); 8]; 256];

            // For each possible byte value (0 to 255)
            for i in 0..256 {
                // Get the label for this byte value
                let input_label = byte_label.get_label(i as u8);

                // Hash the input label to get 8 labels (one for each input bit position)
                let hashed_labels = unsafe { wide_hash(input_label, byte_position*256 + i as u64) };

                // For each input bit position (within the byte)
                for bit_position in 0..8 {
                    // Extract the bit at position bit_position from the byte value i
                    let bit_value = ((i >> bit_position) & 1) == 1;

                    // Get the appropriate bit label (0 or 1) based on the bit value of i
                    // This implements: C[i][j] = H_j(byte_label[i]) ⊕ bit_labels[j][bit_j_of_i]
                    let bit_label = bit_labels[bit_position].get_label(bit_value);

                    // XOR the hashed label with the bit label to create the ciphertext
                    let ciphertext = unsafe { xor128(hashed_labels[bit_position].0, bit_label.0) };
                    ciphertexts[i][bit_position] = Ciphertext(ciphertext);
                }
            }

            ciphertexts
        }

        /// Translates a ByteLabel component to 8 BitLabel components using the translation material.
        ///
        /// Given a label for a specific byte value, this function recovers the 8 bit labels
        /// corresponding to each bit of that byte value.
        ///
        /// # Safety
        ///
        /// The caller must ensure the CPU supports the required target features (AES and NEON/SSE2).
        $(#[target_feature(enable = $target_feature)])+
        pub unsafe fn translate(
            byte_position: u64,
            byte_label_component: Label,
            value: u8,
            translation_material: TranslationMaterial,
        ) -> [Label; 8] {
            // Hash the byte label component to get 8 hashed labels (one for each input bit position)
            let hashed_labels = unsafe { wide_hash(byte_label_component, byte_position*256 + value as u64) };

            // Get the ciphertexts for this specific byte value
            let ciphertexts = translation_material[value as usize];

            // Decrypt each ciphertext to recover the input bit labels
            // Since C[i][j] = H_j(byte_label[i]) ⊕ bit_label[j]
            // We can recover: bit_label[j] = C[i][j] ⊕ H_j(byte_label[i])
            let mut bit_labels = [Label::default(); 8];
            for bit_position in 0..8 {
                bit_labels[bit_position] =
                    Label(unsafe { xor128(ciphertexts[bit_position].0, hashed_labels[bit_position].0) });
            }

            bit_labels
        }
    };
}

#[cfg(target_arch = "aarch64")]
impl_translation_fns!("aes", "neon");

#[cfg(target_arch = "x86_64")]
impl_translation_fns!("aes", "sse2");

use blake3;

/// Expands hash to 8x width using Blake3 XOF (extendable output function).
///
/// This is an alternative implementation to `wide_hash` that uses Blake3's
/// standard XOF instead of Fixed Key AES with tweaks.
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
pub fn wide_hash_blake3(label: Label, index: u64) -> [Label; 8] {
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
        let translation_material =
            unsafe { generate_translation_material(0, byte_label, bit_labels) };

        // Test translation for various byte values
        for test_value in [0u8, 1, 7, 15, 42, 128, 255] {
            // Get the byte label for this value
            let byte_label_component = byte_label.get_label(test_value);

            // Translate to get 8 bit labels
            let recovered_labels =
                unsafe { translate(0, byte_label_component, test_value, translation_material) };

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

        let translation_material =
            unsafe { generate_translation_material(0, byte_label, bit_labels) };

        // Test all 256 possible byte values
        for test_value in 0u8..=255 {
            let byte_label_component = byte_label.get_label(test_value);
            let recovered_labels =
                unsafe { translate(0, byte_label_component, test_value, translation_material) };

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

        let translation_material =
            unsafe { generate_translation_material(0, byte_label, bit_labels) };

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
                unsafe { translate(0, byte_label_component, test_value, translation_material) };

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
}

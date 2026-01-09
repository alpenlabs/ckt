//! Architecture-agnostic Label and Ciphertext types.
//!
//! These types wrap architecture-specific SIMD types (uint8x16_t on ARM, __m128i on x86)
//! and provide a unified interface for the rest of the crate.

use std::mem::transmute;

// Architecture-specific inner type
#[cfg(target_arch = "aarch64")]
pub(crate) type Inner = std::arch::aarch64::uint8x16_t;

#[cfg(target_arch = "x86_64")]
pub(crate) type Inner = std::arch::x86_64::__m128i;

// Constants for Label::zero() and Label::one()
const LABEL_ZERO_BYTES: [u8; 16] = [98u8; 16];
const LABEL_ONE_BYTES: [u8; 16] = [25u8; 16];

/// A 128-bit label used in garbled circuits.
///
/// Labels are the fundamental unit of garbled circuit computation.
/// Each wire has two labels: one for the value 0 and one for the value 1.
#[derive(Debug, Clone, Copy)]
pub struct Label(pub Inner);

impl Label {
    /// Returns the public constant label for zero.
    pub fn zero() -> Self {
        Label::from(LABEL_ZERO_BYTES)
    }

    /// Returns the public constant label for one.
    pub fn one() -> Self {
        Label::from(LABEL_ONE_BYTES)
    }
}

impl Default for Label {
    fn default() -> Self {
        Label::from([0u8; 16])
    }
}

impl From<[u8; 16]> for Label {
    fn from(bytes: [u8; 16]) -> Self {
        Label(unsafe { transmute::<[u8; 16], Inner>(bytes) })
    }
}

impl From<Label> for [u8; 16] {
    fn from(label: Label) -> Self {
        unsafe { transmute::<Inner, [u8; 16]>(label.0) }
    }
}

/// A 128-bit ciphertext produced during garbling.
///
/// Ciphertexts are produced for AND gates and stored in the garbled circuit.
#[derive(Debug, Clone, Copy)]
pub struct Ciphertext(pub Inner);

impl Default for Ciphertext {
    fn default() -> Self {
        Ciphertext::from([0u8; 16])
    }
}

impl From<[u8; 16]> for Ciphertext {
    fn from(bytes: [u8; 16]) -> Self {
        Ciphertext(unsafe { transmute::<[u8; 16], Inner>(bytes) })
    }
}

impl From<Ciphertext> for [u8; 16] {
    fn from(ciphertext: Ciphertext) -> Self {
        unsafe { transmute::<Inner, [u8; 16]>(ciphertext.0) }
    }
}

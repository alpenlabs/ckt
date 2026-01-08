//! Core crate for garbling, executing and evaluating garbled/boolean circuits.

pub mod traits;
pub mod translate;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use hex_literal::hex;

/// Main AES key used for gate hashing.
///
/// Taken from <https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/armv8/test_expand.rs>
/// Corresponding to FIPS 197 Appendix A.1
///
/// Note that this key is intentionally arbitrary, fixed, and public.
pub const AES128_KEY_BYTES: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");

/// Precomputed round keys used for gate hashing.
pub const AES128_ROUND_KEY_BYTES: [[u8; 16]; 10] = [
    hex!("a0fafe1788542cb123a339392a6c7605"),
    hex!("f2c295f27a96b9435935807a7359f67f"),
    hex!("3d80477d4716fe3e1e237e446d7a883b"),
    hex!("ef44a541a8525b7fb671253bdb0bad00"),
    hex!("d4d1c6f87c839d87caf2b8bc11f915bc"),
    hex!("6d88a37a110b3efddbf98641ca0093fd"),
    hex!("4e54f70e5f5fc9f384a64fb24ea6dc4f"),
    hex!("ead27321b58dbad2312bf5607f8d292f"),
    hex!("ac7766f319fadc2128d12941575c006e"),
    hex!("d014f9a8c9ee2589e13f0cc8b6630ca6"),
];

/// Architecture-specific types re-exported at a consistent path.
#[cfg(target_arch = "aarch64")]
mod arch {
    pub use crate::aarch64::{
        Aarch64GobbleEngine as Engine, Ciphertext, Label,
        eval::Aarch64EvaluationInstance as EvaluationInstance,
        exec::Aarch64ExecutionInstance as ExecutionInstance,
        garb::Aarch64GarblingInstance as GarblingInstance,
    };
}

/// Architecture-specific types re-exported at a consistent path.
#[cfg(target_arch = "x86_64")]
mod arch {
    pub use crate::x86_64::{
        Ciphertext, Label, X86_64GobbleEngine as Engine,
        eval::X86_64EvaluationInstance as EvaluationInstance,
        exec::X86_64ExecutionInstance as ExecutionInstance,
        garb::X86_64GarblingInstance as GarblingInstance,
    };
}

// Re-export translation types at crate root
pub use translate::{
    BitLabel, ByteLabel, TranslationMaterial, generate_translation_material, translate, wide_hash,
};

pub use arch::*;

#[cfg(test)]
mod tests {
    // Fixes a compiler warning
    use criterion as _;
}

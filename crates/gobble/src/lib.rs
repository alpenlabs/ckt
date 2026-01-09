//! Core crate for garbling, executing and evaluating garbled/boolean circuits.

pub mod traits;
pub mod types;

// Architecture-specific intrinsics
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Unified implementations (architecture-independent logic)
pub mod eval;
pub mod exec;
pub mod garb;

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

// Re-export types at crate root
pub use eval::EvaluationInstanceImpl as EvaluationInstance;
pub use exec::CleartextExecutionInstance as ExecutionInstance;
pub use garb::GarblingInstanceImpl as GarblingInstance;
pub use types::{Ciphertext, Label};

use traits::{
    EvaluationInstanceConfig, ExecutionInstanceConfig, GarblingInstanceConfig, GobbleEngine,
};

/// Primary engine for garbling, executing, and evaluating circuits.
///
/// This is the main entry point for using the gobble crate. It implements
/// the [`GobbleEngine`] trait and provides factory methods for creating
/// garbling, execution, and evaluation instances.
#[derive(Debug)]
pub struct Engine;

impl GobbleEngine for Engine {
    fn new() -> Self {
        Self
    }

    type GarblingInstance = GarblingInstance;
    type EvaluationInstance = EvaluationInstance;
    type ExecutionInstance = ExecutionInstance;

    fn new_garbling_instance<'labels>(
        &self,
        config: GarblingInstanceConfig<'labels>,
    ) -> Self::GarblingInstance {
        GarblingInstance::new(config)
    }

    fn new_execution_instance<'values>(
        &self,
        config: ExecutionInstanceConfig<'values>,
    ) -> Self::ExecutionInstance {
        ExecutionInstance::new(config)
    }

    fn new_evaluation_instance<'labels>(
        &self,
        config: EvaluationInstanceConfig<'labels>,
    ) -> Self::EvaluationInstance {
        EvaluationInstance::new(config)
    }
}

#[cfg(test)]
mod tests {
    // Fixes a compiler warning
    use criterion as _;
}

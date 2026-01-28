//! Core crate for garbling, executing and evaluating garbled/boolean circuits.

pub mod traits;
pub mod translate;
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

// Re-export types at crate root
pub use eval::EvaluationInstanceImpl as EvaluationInstance;
pub use exec::CleartextExecutionInstance as ExecutionInstance;
pub use garb::GarblingInstanceImpl as GarblingInstance;
pub use translate::{
    BitLabel, ByteLabel, TranslationMaterial, generate_translation_material, translate, wide_hash,
};
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

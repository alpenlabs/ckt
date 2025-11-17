//! Core crate for garbling, executing and evaluating garbled/boolean circuits.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod traits;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// Dynamically switching type alias that changes between architecture specific
/// [`GobbleEngine`] implementations.
#[cfg(target_arch = "aarch64")]
pub type Engine = aarch64::Aarch64GobbleEngine;
#[cfg(target_arch = "x86_64")]
pub type Engine = x86_64::X86_64GobbleEngine;

#[cfg(test)]
mod tests {
    use criterion as _;
}

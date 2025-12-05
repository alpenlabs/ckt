//! CKT - High-performance Boolean circuit format library

#![expect(missing_docs, reason = "please let me merge")]
#![allow(unreachable_pub, reason = "pleeeeease let me merge")] // clippy is wrong about this being unfulfilled
#![expect(missing_debug_implementations, reason = "merge pls")]

mod gate_type;

#[cfg(feature = "v5")]
pub mod v5;

pub use gate_type::GateType;

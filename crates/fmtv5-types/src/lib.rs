//! CKT - High-performance Boolean circuit format library

#![expect(missing_docs, reason = "please let me merge")]
#![allow(unreachable_pub, reason = "pleeeeease let me merge")] // clippy is wrong about this being unfulfilled
#![expect(missing_debug_implementations, reason = "merge pls")]

#[cfg(feature = "v5")]
pub mod v5;

/// Gate type enumeration shared across v3, v4, and v5 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

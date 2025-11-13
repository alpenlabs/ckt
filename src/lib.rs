//! CKT - High-performance Boolean circuit format library

#[cfg(feature = "v5")]
pub mod v5;

/// Gate type enumeration shared across v3, v4, and v5 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

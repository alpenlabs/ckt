//! CKT - High-performance Boolean circuit format library

#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;
#[cfg(feature = "v3")]
pub mod v3;
#[cfg(feature = "v4")]
pub mod v4;
#[cfg(feature = "v5")]
pub mod v5;

/// Gate type enumeration shared across v3, v4, and v5 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

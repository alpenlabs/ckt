//! CKT - High-performance Boolean circuit format library

pub mod v1;
pub mod v2;
pub mod v3;

/// Gate type enumeration shared across v3 variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

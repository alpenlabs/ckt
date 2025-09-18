//! CKT - High-performance Boolean circuit format library

pub mod v1;
pub mod v2;
pub mod v3;

// Re-export v1 types at root level for backward compatibility
pub use v1::{CircuitHeader, CompactGate, GateBatch, GateType};

// Re-export v1 reader/writer for backward compatibility
pub mod reader {
    pub use crate::v1::reader::*;
}

pub mod writer {
    pub use crate::v1::writer::*;
}

// High-performance v1 implementation - re-export from v1 module
#[cfg(feature = "high-performance")]
pub mod hp {
    pub use crate::v1::hp::*;
}

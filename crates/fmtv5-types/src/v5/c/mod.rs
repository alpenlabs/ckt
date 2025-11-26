//! CKT Format v5c - Flat production format with execution-ordered gates
//!
//! This module implements the v5c format specification with:
//! - 32-bit memory addresses (not wire IDs)
//! - Flat array organization (no level structure)
//! - 256 KiB blocks optimized for 1 MB L2 cache
//! - Bit-compacted gate types (1 bit per gate)
//! - Gates stored in execution order
//!
//! v5c is designed for garbling workloads where both gate data and ciphertext
//! accumulation buffers fit comfortably in L2 cache, with Arc-sharing support
//! for distributing blocks to multiple worker threads.

mod block;
mod chunk;
mod constants;
mod gate;
mod header;
mod stats;

mod reader;
mod writer;

pub use block::*;
pub use chunk::*;
pub use constants::*;
pub use gate::*;
pub use header::*;
pub use reader::*;
pub use stats::*;
pub use writer::*;

#[cfg(test)]
mod integration;

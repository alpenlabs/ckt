//! Circuit transformation utilities for CKT format conversion.
//!
//! This crate provides tools for converting v5a circuits to v5c flat format
//! with wire address preallocation.
//!
//! # Key Features
//! - **Preallocation**: Convert v5a (wire IDs + credits) to v5c (memory addresses)
//! - **Memory efficient**: Uses slab allocation for minimal memory footprint
//!
//! # Example
//! ```ignore
//! use ckt_lvl::prealloc;
//!
//! prealloc::prealloc("input.v5a", "output.v5c").await;
//! ```

/// Wire address preallocation (v5a to v5c conversion).
pub mod prealloc;
/// Slab-style allocator for wire memory addresses.
pub mod slab;
/// Compact wire identifier types.
pub mod types;

// Dependencies of the `lvl` binary only.
use clap as _;
use mimalloc as _;
use monoio as _;

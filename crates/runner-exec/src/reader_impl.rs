//! [`CircuitReader`] wrapper for [`ReaderV5c`].

use std::io;

use ckt_fmtv5_types::v5::c::{Chunk, HeaderV5c, ReaderV5c};
use ckt_runner_types::CircuitReader;

/// Wrapper around [`ReaderV5c`] that implements [`CircuitReader`].
// this is in a weird place and the inner thing doesn't implement it because I
// didn't want to think through restructuring the crates again to make it make
// the most elegant possible
#[derive(Debug)]
pub struct ReaderV5cWrapper(pub ReaderV5c);

impl ReaderV5cWrapper {
    /// Create a new reader wrapper.
    pub fn new(reader: ReaderV5c) -> Self {
        Self(reader)
    }

    /// Unwrap and return the inner reader.
    pub fn into_inner(self) -> ReaderV5c {
        self.0
    }
}

impl CircuitReader for ReaderV5cWrapper {
    fn header(&self) -> &HeaderV5c {
        self.0.header()
    }

    fn outputs(&self) -> &[u32] {
        self.0.outputs()
    }

    async fn next_chunk(&mut self) -> io::Result<Option<Chunk<'_>>> {
        self.0.next_blocks_chunk().await
    }
}

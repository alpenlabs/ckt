//! Runner task traits.

use std::error::Error;

use ckt_fmtv5_types::v5::c::HeaderV5c;

use crate::block::GateBlock;

/// Represents a task that walks over processing blocks of gates from a circuit.
pub trait CircuitTask {
    /// Error type for whatever errors might happen.
    type Error: Error + Sync + Send + 'static;

    /// Additional input data needed to initialize the task.
    type InitInput;

    /// Running task state.
    type State;

    /// Output produced by the task.
    type Output;

    /// Visits the header to initialize whatever needs to be and produce a
    /// running task state.
    ///
    /// This is called first and once.
    fn initialize(&self, header: &HeaderV5c, init_input: Self::InitInput) -> Result<Self::State, Self::Error>;

    /// Visits a block of gates for processing.  This modifies the passed task
    /// state as needed by the task.
    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error>;

    /// Called after each block in a chunk has been processed.
    fn on_after_chunk(&self, state: &mut Self::State) -> Result<(), Self::Error>;

    /// Called at the end after we've processed all the chunks, consuming the
    /// final task state to produce an output.
    fn finish(
        &self,
        state: Self::State,
        output_wire_idxs: &[u64],
    ) -> Result<Self::Output, Self::Error>;

    /// Called if an error occurs to be able to perform graceful cleanup.
    ///
    /// This is not called if an error occurs in `finish`.
    fn on_abort(&self, state: Self::State);
}

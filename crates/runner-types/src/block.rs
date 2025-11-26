use ckt_fmtv5_types::GateType;
use ckt_fmtv5_types::v5::c::*;

/// Safer container around the gates in a block.
pub struct GateBlock<'b> {
    raw_block: &'b Block,
    num_gates: usize,
}

impl<'b> GateBlock<'b> {
    /// Creates a new instance.
    ///
    /// # Safety
    ///
    /// Must be called such that we don't try to read outside the bounds of the
    /// arrays in the `raw_block`.
    pub fn new(raw_block: &'b Block, num_gates: usize) -> Self {
        Self {
            raw_block,
            num_gates,
        }
    }

    pub fn num_gates(&self) -> usize {
        self.num_gates
    }

    /// Gets an iterator over the gates and their types.
    pub fn gates_iter(&self) -> impl Iterator<Item = (GateV5c, GateType)> {
        (0..self.num_gates).map(|i| (self.raw_block.gates[i], self.raw_block.gate_type(i)))
    }
}

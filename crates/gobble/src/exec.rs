//! Cleartext circuit execution implementation.

use bitvec::vec::BitVec;

use crate::traits::{ExecutionInstance, ExecutionInstanceConfig};

/// Cleartext execution instance for boolean circuit evaluation.
///
/// This executes the circuit without any garbling, useful for testing
/// and computing expected outputs.
#[derive(Debug)]
pub struct CleartextExecutionInstance {
    working_space: BitVec,
}

impl CleartextExecutionInstance {
    /// Creates a new execution instance with the given configuration.
    pub fn new(config: ExecutionInstanceConfig<'_>) -> Self {
        let mut working_space = BitVec::repeat(false, config.scratch_space as usize);
        // Wire 0 is constant false, wire 1 is constant true
        working_space.set(0, false);
        working_space.set(1, true);
        // Set primary input wires starting at position 2
        for (value, i) in config.input_values.iter().zip(2..) {
            working_space.set(i, *value);
        }
        Self { working_space }
    }
}

impl ExecutionInstance for CleartextExecutionInstance {
    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let val = self.working_space[in1_addr] ^ self.working_space[in2_addr];
        self.working_space.set(out_addr, val);
    }

    fn feed_and_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let val = self.working_space[in1_addr] & self.working_space[in2_addr];
        self.working_space.set(out_addr, val);
    }

    fn get_values(&self, wires: &[u64], values: &mut [bool]) {
        for (i, wire_id) in wires.iter().enumerate() {
            values[i] = self.working_space[*wire_id as usize];
        }
    }
}

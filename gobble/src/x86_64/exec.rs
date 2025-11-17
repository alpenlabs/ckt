//! x86_64-specific execution instance implementation.

use bitvec::vec::BitVec;

use crate::traits::{ExecutionInstance, ExecutionInstanceConfig};

/// x86_64-specific execution instance implementation.
#[derive(Debug)]
pub struct X86_64ExecutionInstance {
    working_space: BitVec,
}

impl X86_64ExecutionInstance {
    /// Creates a new X86_64ExecutionInstance with the given configuration.
    pub fn new<'values>(config: ExecutionInstanceConfig<'values>) -> Self {
        let mut working_space = BitVec::repeat(false, config.scratch_space as usize);
        for (value, i) in config.input_values.iter().zip(2..) {
            working_space.set(i, *value);
        }
        Self { working_space }
    }
}

impl ExecutionInstance for X86_64ExecutionInstance {
    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let val = self.working_space[in1_addr] ^ self.working_space[in2_addr];
        self.working_space.set(out_addr, val);
    }

    fn feed_and_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let val = self.working_space[in1_addr] & self.working_space[in2_addr];
        self.working_space.set(out_addr, val);
    }

    fn finish(&self, output_wires: &[u64], output_labels: &mut [bool]) {
        for wire_id in output_wires {
            output_labels[*wire_id as usize] = self.working_space[*wire_id as usize];
        }
    }
}

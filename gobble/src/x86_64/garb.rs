//! x86_64-specific garbling implementation
use std::arch::x86_64::__m128i;

use crate::{
    traits::{GarblingInstance, GarblingInstanceConfig},
    x86_64::{Ciphertext, Label, hash, index_to_tweak, xor128},
};
use bitvec::vec::BitVec;

/// x86_64-specific garbling instance
#[derive(Debug)]
pub struct X86_64GarblingInstance {
    gate_ctr: u64,
    and_ctr: u64,
    working_space: Vec<Label>,
    delta: __m128i,
}

impl GarblingInstance for X86_64GarblingInstance {
    type Ciphertext = Ciphertext;

    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];
        self.working_space[out_addr] = Label(unsafe { xor128(in1.0, in2.0) });
        self.gate_ctr += 1;
    }

    fn feed_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
    ) -> Self::Ciphertext {
        // Retrieve input labels for in1_0 and in2_0
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];

        let t = unsafe { index_to_tweak(self.gate_ctr) };
        let xor_in1_delta = unsafe { xor128(in1.0, self.delta) };

        let h_in1_t = unsafe { hash(in1.0, t) };

        let h_in1_delta_t = unsafe { hash(xor_in1_delta, t) };

        let ciphertext = unsafe { xor128(xor128(h_in1_t, h_in1_delta_t), in2.0) };

        // Write output label to working space
        self.working_space[out_addr] = Label(h_in1_t);

        // Increment gate counter to enforce uniqueness
        self.gate_ctr += 1;
        self.and_ctr += 1;
        Ciphertext(ciphertext)
    }

    fn get_selected_labels(&self, wires: &[u64], values: &BitVec, labels: &mut [[u8; 16]]) {
        for (i, wire_id) in wires.iter().enumerate() {
            let wire_id = *wire_id as usize;
            let false_label = self.working_space[wire_id];
            let value = values[i];

            let selected_label = if value {
                // label = false_label XOR delta (when bit is 1)
                Label(unsafe { xor128(false_label.0, self.delta) })
            } else {
                // label = false_label (when bit is 0)
                false_label
            };

            labels[i] = unsafe { std::mem::transmute(selected_label.0) };
        }
    }
}

impl X86_64GarblingInstance {
    /// Creates a new X86_64GarblingInstance with the given configuration.
    pub fn new<'a>(config: GarblingInstanceConfig<'a>) -> Self {
        let bytes = [0u8; 16];
        let empty_label = unsafe { std::mem::transmute(bytes) };
        let mut working_space = vec![Label(empty_label); config.scratch_space as usize];
        for (label, i) in config.primary_input_false_labels.iter().zip(2..) {
            working_space[i] = Label(unsafe { std::mem::transmute(*label) });
        }

        X86_64GarblingInstance {
            gate_ctr: 0,
            working_space,
            delta: unsafe { std::mem::transmute(config.delta) },
            and_ctr: 0,
        }
    }
}

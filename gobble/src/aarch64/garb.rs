//! Aarch64-specific garbling implementation
use std::arch::aarch64::uint8x16_t;

use crate::{
    aarch64::{Ciphertext, Label, hash, index_to_tweak, xor128},
    traits::{GarblingInstance, GarblingInstanceConfig},
};

/// Aarch64-specific garbling instance
#[derive(Debug)]
pub struct Aarch64GarblingInstance {
    gate_ctr: u64,
    and_ctr: u64,
    working_space: Vec<Label>,
    delta: uint8x16_t,
}

impl GarblingInstance for Aarch64GarblingInstance {
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

    fn finish(&self, output_wires: &[u64], output_labels: &mut [[u8; 16]]) {
        for (i, wire) in output_wires.iter().enumerate() {
            let label = unsafe { std::mem::transmute(self.working_space[(*wire) as usize].0) };
            output_labels[i] = label;
        }
    }
}

impl Aarch64GarblingInstance {
    /// Creates a new Aarch64GarblingInstance with the given configuration.
    pub fn new<'a>(config: GarblingInstanceConfig<'a>) -> Self {
        let bytes = [0u8; 16];
        let empty_label = unsafe { std::mem::transmute(bytes) };
        let mut working_space = vec![Label(empty_label); config.scratch_space as usize];
        for (label, i) in config.primary_input_false_labels.iter().zip(2..) {
            working_space[i] = Label(unsafe { std::mem::transmute(*label) });
        }

        Aarch64GarblingInstance {
            gate_ctr: 0,
            working_space,
            delta: unsafe { std::mem::transmute(config.delta) },
            and_ctr: 0,
        }
    }
}

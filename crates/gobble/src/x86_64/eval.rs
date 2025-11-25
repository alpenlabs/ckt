//! Implements x86_64-specific evaluation instance.

use bitvec::vec::BitVec;

use crate::{
    traits::{EvaluationInstance, EvaluationInstanceConfig},
    x86_64::{Ciphertext, Label, hash, index_to_tweak, xor128},
};

/// x86_64-specific evaluation instance.
#[derive(Debug)]
pub struct X86_64EvaluationInstance {
    /// Counter for the number of gates evaluated.
    gate_ctr: u64,
    /// Counter for the number of AND gates evaluated.
    and_ctr: u64,
    /// Working/scratch space for wire labels.
    working_space: Vec<Label>,
    /// Working/scratch space for wire values.
    working_space_bits: BitVec,
}

impl EvaluationInstance for X86_64EvaluationInstance {
    type Ciphertext = Ciphertext;

    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];
        self.working_space[out_addr] = Label(unsafe { xor128(in1.0, in2.0) });
        let value = self.working_space_bits[in1_addr] ^ self.working_space_bits[in2_addr];
        self.working_space_bits.set(out_addr, value);
        self.gate_ctr += 1;
    }

    fn feed_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
        ciphertext: Ciphertext,
    ) {
        // Retrieve input labels for in1_0 and in2_0
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];

        let t = unsafe { index_to_tweak(self.gate_ctr) };
        let permute_bit = self.working_space_bits[in1_addr];

        let mut out_label = unsafe { hash(in1.0, t) };
        if permute_bit {
            out_label = unsafe { xor128(out_label, xor128(ciphertext.0, in2.0)) };
        }

        // Write output label to working space
        self.working_space[out_addr] = Label(out_label);
        let value = self.working_space_bits[in1_addr] && self.working_space_bits[in2_addr];
        self.working_space_bits.set(out_addr, value);

        // Increment gate counter to enforce uniqueness
        self.gate_ctr += 1;
        self.and_ctr += 1;
    }

    fn get_labels(&self, wires: &[u64], labels: &mut [[u8; 16]]) {
        for (i, wire_id) in wires.iter().enumerate() {
            let wire_id = *wire_id as usize;
            labels[i] = unsafe {
                std::mem::transmute::<std::arch::x86_64::__m128i, [u8; 16]>(
                    self.working_space[wire_id].0,
                )
            };
        }
    }

    fn get_values(&self, wires: &[u64], values: &mut [bool]) {
        for (i, wire_id) in wires.iter().enumerate() {
            values[i] = self.working_space_bits[*wire_id as usize];
        }
    }
}

impl X86_64EvaluationInstance {
    /// Initialize a new evaluation instance with the given configuration.
    pub fn new<'labels>(config: EvaluationInstanceConfig<'labels>) -> Self {
        let bytes = [0u8; 16];
        let empty_label =
            unsafe { std::mem::transmute::<[u8; 16], std::arch::x86_64::__m128i>(bytes) };
        let mut working_space = vec![Label(empty_label); config.scratch_space as usize];

        for (label, i) in config.selected_primary_input_labels.iter().zip(2..) {
            working_space[i] = Label(unsafe {
                std::mem::transmute::<[u8; 16], std::arch::x86_64::__m128i>(*label)
            });
        }

        let mut working_space_bits = BitVec::repeat(false, config.scratch_space as usize);
        for (value, i) in config.selected_primary_input_values.iter().zip(2..) {
            working_space_bits.set(i, *value);
        }

        X86_64EvaluationInstance {
            gate_ctr: 0,
            and_ctr: 0,
            working_space,
            working_space_bits,
        }
    }
}

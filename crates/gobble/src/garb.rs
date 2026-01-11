//! Unified garbling implementation.
//!
//! Uses conditional compilation to select the appropriate intrinsics
//! while sharing all the garbling logic.

use std::mem::transmute;

use bitvec::vec::BitVec;

use crate::traits::{GarblingInstance, GarblingInstanceConfig};
use crate::types::{Ciphertext, Inner, Label};

// Conditional imports for architecture-specific intrinsics
#[cfg(target_arch = "aarch64")]
use crate::aarch64::{hash, index_to_tweak, xor128};

#[cfg(target_arch = "x86_64")]
use crate::x86_64::{hash, index_to_tweak, xor128};

/// Garbling instance that produces a garbled circuit.
#[derive(Debug)]
pub struct GarblingInstanceImpl {
    gate_ctr: u64,
    and_ctr: u64,
    working_space: Vec<Label>,
    delta: Inner,
}

impl GarblingInstanceImpl {
    /// Creates a new garbling instance with the given configuration.
    ///
    /// # Safety
    ///
    /// The caller must ensure the CPU supports the required target features (AES and NEON/SSE2).
    pub fn new(config: GarblingInstanceConfig<'_>) -> Self {
        let empty_label = Label::default();
        let mut working_space = vec![empty_label; config.scratch_space as usize];

        // Wire 0 is constant false label, wire 1 is constant true label
        working_space[0] = Label::zero();
        working_space[1] =
            Label(unsafe { xor128(Label::one().0, transmute::<[u8; 16], Inner>(config.delta)) });

        // Set primary input labels starting at position 2
        for (label, i) in config.primary_input_false_labels.iter().zip(2..) {
            working_space[i] = Label(unsafe { transmute::<[u8; 16], Inner>(*label) });
        }

        GarblingInstanceImpl {
            gate_ctr: 0,
            working_space,
            delta: unsafe { transmute::<[u8; 16], Inner>(config.delta) },
            and_ctr: 0,
        }
    }
}

/// Implements the GarblingInstance trait using the privacy-free half-gates
/// construction from ZRE15 <https://eprint.iacr.org/2014/756>.
impl GarblingInstance for GarblingInstanceImpl {
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
        // Retrieve input labels
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];

        // PFHG garbling: ciphertext = H(in1, t) ⊕ H(in1 ⊕ delta, t) ⊕ in2
        let t = unsafe { index_to_tweak(self.gate_ctr) };
        let xor_in1_delta = unsafe { xor128(in1.0, self.delta) };

        let h_in1_t = unsafe { hash(in1.0, t) };
        let h_in1_delta_t = unsafe { hash(xor_in1_delta, t) };

        let ciphertext = unsafe { xor128(xor128(h_in1_t, h_in1_delta_t), in2.0) };

        // Write output label to working space (H(in1, t))
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

            labels[i] = unsafe { transmute::<Inner, [u8; 16]>(selected_label.0) };
        }
    }
}

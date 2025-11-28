//! Garbling task implementation.

use std::io::Write;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_fmtv5_types::GateType;
use ckt_gobble::{
    Engine, GarblingInstance as PlatformGarblingInstance,
    traits::{GarblingInstance, GarblingInstanceConfig, GobbleEngine},
};
use ckt_runner_types::{CircuitTask, GateBlock};

/// Internal garbling state.
pub struct GarbleState<W> {
    /// The garbling instance.
    pub instance: PlatformGarblingInstance,
    writer: W,
}

/// Output from the garbling task.
#[derive(Debug)]
pub struct GarbleTaskOutput {
    /// The garbling instance, for extracting labels after garbling.
    pub instance: PlatformGarblingInstance,
    /// The garbler's output labels.
    pub garbler_output_labels: Vec<[u8; 16]>,
    /// The output values (all false, used for label selection).
    pub output_values: BitVec,
}

/// Task for garbling a circuit.
pub struct GarbleTask<'c, W> {
    garb_config: GarblingInstanceConfig<'c>,
    _phantom: std::marker::PhantomData<W>,
}

impl<'c, W> GarbleTask<'c, W> {
    /// Create a new garbling task with the given configuration.
    pub fn new(garb_config: GarblingInstanceConfig<'c>) -> Self {
        Self {
            garb_config,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'c, W: Write> CircuitTask for GarbleTask<'c, W> {
    type Error = std::io::Error;
    type InitInput = W;
    type State = GarbleState<W>;
    type Output = GarbleTaskOutput;

    fn initialize(
        &self,
        _header: &HeaderV5c,
        writer: Self::InitInput,
    ) -> Result<Self::State, Self::Error> {
        // Create the engine.
        let engine = Engine::new();
        let instance = engine.new_garbling_instance(self.garb_config);

        Ok(GarbleState { instance, writer })
    }

    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error> {
        for (ginfo, gty) in block.gates_iter() {
            match gty {
                GateType::AND => {
                    let ct = state.instance.feed_and_gate(
                        ginfo.in1 as usize,
                        ginfo.in2 as usize,
                        ginfo.out as usize,
                    );

                    let bytes: [u8; 16] = unsafe { std::mem::transmute(ct.0) };

                    state
                        .writer
                        .write_all(&bytes)
                        .expect("garble: write output table");
                }

                GateType::XOR => state.instance.feed_xor_gate(
                    ginfo.in1 as usize,
                    ginfo.in2 as usize,
                    ginfo.out as usize,
                ),
            }
        }

        Ok(())
    }

    fn on_after_chunk(&self, _state: &mut Self::State) -> Result<(), Self::Error> {
        Ok(())
    }

    fn finish(
        &self,
        mut state: Self::State,
        output_wire_idxs: &[u64],
    ) -> Result<Self::Output, Self::Error> {
        // Cleanup.
        state.writer.flush().expect("garble: flush output table");

        // Extract output values.
        let mut garbler_output_labels = vec![[0u8; 16]; output_wire_idxs.len()];
        let output_values = BitVec::repeat(false, output_wire_idxs.len());
        state.instance.get_selected_labels(
            output_wire_idxs,
            &output_values,
            &mut garbler_output_labels,
        );

        Ok(GarbleTaskOutput {
            instance: state.instance,
            garbler_output_labels,
            output_values,
        })
    }

    fn on_abort(&self, mut state: Self::State) {
        state
            .writer
            .flush()
            .expect("garble: flush output table on abort");
    }
}

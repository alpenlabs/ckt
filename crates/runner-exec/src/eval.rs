//! Evaluation task implementation.

use std::io::Read;

use ckt_fmtv5_types::GateType;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_gobble::{
    Ciphertext, Engine, EvaluationInstance as PlatformEvaluationInstance,
    traits::{EvaluationInstance, EvaluationInstanceConfig, GobbleEngine},
};
use ckt_runner_types::{CircuitTask, GateBlock};

/// Internal evaluation state.
pub struct EvalState<R> {
    instance: PlatformEvaluationInstance,
    ct_reader: R,
}

/// Output from the evaluation task.
#[derive(Debug)]
pub struct EvalTaskOutput {
    /// The output wire labels.
    pub output_labels: Vec<[u8; 16]>,
    /// The output values.
    pub output_values: Vec<bool>,
}

/// Task for evaluating a garbled circuit.
pub struct EvalTask<'c, R> {
    eval_config: EvaluationInstanceConfig<'c>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'c, R> EvalTask<'c, R> {
    /// Create a new evaluation task with the given configuration.
    pub fn new(eval_config: EvaluationInstanceConfig<'c>) -> Self {
        Self {
            eval_config,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'c, R: Read> CircuitTask for EvalTask<'c, R> {
    type Error = std::io::Error;
    type InitInput = R;
    type State = EvalState<R>;
    type Output = EvalTaskOutput;

    fn initialize(
        &self,
        _header: &HeaderV5c,
        ct_reader: Self::InitInput,
    ) -> Result<Self::State, Self::Error> {
        // Create the engine and evaluation instance.
        let engine = Engine::new();
        let instance = engine.new_evaluation_instance(self.eval_config);

        Ok(EvalState {
            instance,
            ct_reader,
        })
    }

    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error> {
        for (ginfo, gty) in block.gates_iter() {
            match gty {
                GateType::AND => {
                    let mut ct_bytes = [0u8; 16];
                    state.ct_reader.read_exact(&mut ct_bytes)?;
                    let ct = Ciphertext(unsafe {
                        std::mem::transmute::<[u8; 16], std::arch::x86_64::__m128i>(ct_bytes)
                    });

                    state.instance.feed_and_gate(
                        ginfo.in1 as usize,
                        ginfo.in2 as usize,
                        ginfo.out as usize,
                        ct,
                    );
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
        state: Self::State,
        output_wire_idxs: &[u64],
    ) -> Result<Self::Output, Self::Error> {
        let mut output_labels = vec![[0u8; 16]; output_wire_idxs.len()];
        let mut output_values = vec![false; output_wire_idxs.len()];
        state
            .instance
            .get_labels(output_wire_idxs, &mut output_labels);
        state
            .instance
            .get_values(output_wire_idxs, &mut output_values);

        Ok(EvalTaskOutput {
            output_labels,
            output_values,
        })
    }

    fn on_abort(&self, _state: Self::State) {
        // Nothing to clean up for evaluation.
    }
}

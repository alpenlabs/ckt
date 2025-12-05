//! Execution task implementation.

use ckt_fmtv5_types::GateType;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_gobble::{
    Engine, ExecutionInstance as PlatformExecutionInstance,
    traits::{ExecutionInstance, ExecutionInstanceConfig, GobbleEngine},
};
use ckt_runner_types::{CircuitTask, GateBlock};

/// Internal execution state.
pub struct ExecState {
    instance: PlatformExecutionInstance,
}

/// Output from the execution task.
#[derive(Debug)]
pub struct ExecTaskOutput {
    /// The output values.
    pub output_values: Vec<bool>,
}

/// Task for executing a circuit in plaintext.
pub struct ExecTask<'c> {
    exec_config: ExecutionInstanceConfig<'c>,
}

impl<'c> ExecTask<'c> {
    /// Create a new execution task with the given configuration.
    pub fn new(exec_config: ExecutionInstanceConfig<'c>) -> Self {
        Self { exec_config }
    }
}

impl<'c> CircuitTask for ExecTask<'c> {
    type Error = std::io::Error;
    type InitInput = ();
    type State = ExecState;
    type Output = ExecTaskOutput;

    fn initialize(
        &self,
        _header: &HeaderV5c,
        _init_input: Self::InitInput,
    ) -> Result<Self::State, Self::Error> {
        // Create the engine and execution instance.
        let engine = Engine::new();
        let instance = engine.new_execution_instance(self.exec_config);

        Ok(ExecState { instance })
    }

    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error> {
        for (ginfo, gty) in block.gates_iter() {
            match gty {
                GateType::AND => {
                    state.instance.feed_and_gate(
                        ginfo.in1 as usize,
                        ginfo.in2 as usize,
                        ginfo.out as usize,
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
        let mut output_values = vec![false; output_wire_idxs.len()];
        state
            .instance
            .get_values(output_wire_idxs, &mut output_values);

        Ok(ExecTaskOutput { output_values })
    }

    fn on_abort(&self, _state: Self::State) {
        // Nothing to clean up for execution.
    }
}

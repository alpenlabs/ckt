//! Traits for genericising architecture specific [`GobbleEngine`]s

use bitvec::vec::BitVec;

use crate::aarch64::Ciphertext;

/// A generic trait for describing an instance used for garbling a boolean circuit.
pub trait GarblingInstance {
    /// The ciphertext type used by this implementation.
    type Ciphertext;

    /// Feed an XOR gate into the instance. Accepts the memory addresses of the
    /// inputs and output.
    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize);

    /// Feed an AND gate into the instance. Accepts the memory addresses of the
    /// inputs and output. Produces a single ciphertext according to PFHG.
    fn feed_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
    ) -> Self::Ciphertext;

    /// Return selected labels for the given wires and values.
    fn get_selected_labels(&self, wires: &[u64], values: &BitVec, labels: &mut [[u8; 16]]);
}

/// A generic trait for describing an instance used for evaluating a garbled boolean circuit.
pub trait EvaluationInstance {
    /// The ciphertext type used by this implementation.
    type Ciphertext;

    /// Feed an XOR gate into the instance. Accepts the memory addresses of the
    /// inputs and output.
    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize);

    /// Feeds an AND gate into the instance. Accepts the memory addresses of the
    /// inputs, output, and ciphertext used to reconstruct the output label.
    fn feed_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
        ciphertext: Ciphertext,
    );

    /// Extract wires with IDs `wires` to `labels`. Panics if the number of wires does not match the
    /// number of labels.
    fn get_labels(&self, wires: &[u64], labels: &mut [[u8; 16]]);

    /// Return values for the given wires. Panics if the number of wires does not match the
    /// number of values.
    fn get_values(&self, wires: &[u64], values: &mut [bool]);
}

/// A generic trait for describing an instance used for executing a boolean circuit.
pub trait ExecutionInstance {
    /// Feed a XOR gate with inputs at `in1_addr` and `in2_addr` to output at `out_addr`.
    /// This XOR's the value of the inputs and stores the result in the output address.
    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize);

    /// Feed an AND gate with inputs at `in1_addr` and `in2_addr` to output at `out_addr`.
    /// This AND's the value of the inputs and stores the result in the output address.
    fn feed_and_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize);

    /// Extract wires with IDs `wires` to `values`. Panics if the number of wires does not match the
    /// number of values.
    fn get_values(&self, wires: &[u64], values: &mut [bool]);
}

/// Configuration for garbling a boolean circuit
#[derive(Debug)]
pub struct GarblingInstanceConfig<'labels> {
    /// Max live wires used at any point in the circuit. See ckt v5 architecture
    /// for additional details.
    pub scratch_space: u32,
    /// The delta is a global offset constant used for garbling a circuit.
    /// Carried over to the evaluator for recomputation.
    pub delta: [u8; 16],
    /// Input false labels for the circuit.
    pub primary_input_false_labels: &'labels [[u8; 16]],
}

/// Configuration for executing a boolean circuit
#[derive(Debug)]
pub struct ExecutionInstanceConfig<'values> {
    /// Max live wires used at any point in the circuit. See ckt v5 architecture
    /// for additional details.
    pub scratch_space: u32,
    /// Bitpacked input bits for the circuit.
    pub input_values: &'values BitVec,
}

/// Configuration for evaluating a garbled circuit
#[derive(Debug)]
pub struct EvaluationInstanceConfig<'labels> {
    /// Max live wires used at any point in the circuit. See ckt v5 architecture
    /// for additional details.
    pub scratch_space: u32,
    /// Selected labels (each wire has two, one for true, one for false) for
    /// the primary inputs.
    pub selected_primary_input_labels: &'labels [[u8; 16]],
    /// Selected values for each wire (1 bit per wire, boolean)
    pub selected_primary_input_values: &'labels BitVec,
}

/// GobbleEngine is the primary interface of `gobble`. It
/// provides methods for creating garbling instances, execution instances,
/// and evaluation instances.
///
/// This allows for architecture specific implementations of the garbling,
/// execution, and evaluation instances. You can access the one for your platform
/// via [`gobble::Engine`].
pub trait GobbleEngine {
    /// Create a new instance of the engine.
    fn new() -> Self;

    /// The garbling instance implementation for this engine.
    type GarblingInstance: GarblingInstance;
    /// The evaluation instance implementation for this engine.
    type EvaluationInstance: EvaluationInstance;
    /// The execution instance implementation for this engine.
    type ExecutionInstance: ExecutionInstance;

    /// Creates a new garbling instance using a specified config.
    fn new_garbling_instance<'labels>(
        &self,
        config: GarblingInstanceConfig<'labels>,
    ) -> Self::GarblingInstance;

    /// Creates a new execution instance using a specified config.
    fn new_execution_instance<'values>(
        &self,
        config: ExecutionInstanceConfig<'values>,
    ) -> Self::ExecutionInstance;

    /// Creates a new evaluation instance using a specified config.
    fn new_evaluation_instance<'labels>(
        &self,
        config: EvaluationInstanceConfig<'labels>,
    ) -> Self::EvaluationInstance;
}

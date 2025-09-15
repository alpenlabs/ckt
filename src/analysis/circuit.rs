//! Circuit representation and evaluation.

use std::collections::*;

use super::coords::*;
use super::gate::*;

/// Builder for circuit data in memory that performs analysis in the process.
pub struct Circuit {
    /// The number of inputs.
    num_inputs: usize,

    /// List of wires, either inputs or produced as gate outputs.
    wires: Vec<Wire>,

    /// Index of the readers of each wire.
    ///
    /// The vec entries here are naturally sorted in increasing order.
    wire_readers: Vec<Vec<AbsWireIdx>>,
}

impl Circuit {
    pub fn new(num_inputs: usize) -> Self {
        Self {
            num_inputs,
            wires: vec![Wire::Input; num_inputs],
            wire_readers: vec![Vec::new(); num_inputs],
        }
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    pub fn num_wires(&self) -> u32 {
        self.wires.len() as u32
    }

    /// Returns an iterator over the indexes of input wires.
    // The `+ Clone` here is a horrible hack to make this ergonomic.
    pub fn input_idxs_iter(&self) -> impl Iterator<Item = AbsWireIdx> + Clone {
        (0..self.num_inputs()).map(AbsWireIdx::from)
    }

    /// Returns an iterator over the indexes of gate wires, assuming it was
    /// constructed properly.
    pub fn gate_idxs_iter(&self) -> impl Iterator<Item = AbsWireIdx> + Clone {
        ((self.num_inputs() + 1)..self.wires.len()).map(AbsWireIdx::from)
    }

    fn add_wire_reader(&mut self, i: AbsWireIdx, r: AbsWireIdx) {
        let v: &mut Vec<AbsWireIdx> = self
            .wire_readers
            .get_mut(Into::<usize>::into(i))
            .expect("builder: oob wire idx");
        v.push(r);
    }

    fn add_gate_inner(&mut self, g: Gate) -> AbsWireIdx {
        let idx = AbsWireIdx::from(self.wires.len() as u32);
        self.wires.push(Wire::Gate(g));
        self.wire_readers.push(Vec::new());
        idx
    }

    /// Adds a gate, connecting up the readers.
    pub fn add_gate(&mut self, g: Gate) -> AbsWireIdx {
        let idx = self.add_gate_inner(g);
        self.add_wire_reader(g.inp1(), idx);
        self.add_wire_reader(g.inp2(), idx);
        idx
    }

    pub fn get_wire(&self, i: AbsWireIdx) -> Option<&Wire> {
        self.wires.get(<AbsWireIdx as Into<u32>>::into(i) as usize)
    }

    pub fn get_wire_as_gate(&self, i: AbsWireIdx) -> Option<&Gate> {
        match self.get_wire(i)? {
            Wire::Input => None,
            Wire::Gate(gate) => Some(gate),
        }
    }

    pub fn get_wire_uses(&self, i: AbsWireIdx) -> Option<&[AbsWireIdx]> {
        self.wire_readers
            .get(Into::<usize>::into(i))
            .map(|e| e.as_ref())
    }

    /// Gets the index of the gate that's the first user of a wire, if it's ever used.
    pub fn get_first_use(&mut self, i: AbsWireIdx) -> Option<AbsWireIdx> {
        self.wire_readers
            .get(Into::<usize>::into(i))
            .and_then(|r| r.first())
            .copied()
    }

    /// Gets the index of the gate that's the last user of a wire, if it's ever used.
    pub fn get_last_use(&mut self, i: AbsWireIdx) -> Option<AbsWireIdx> {
        self.wire_readers
            .get(Into::<usize>::into(i))
            .and_then(|r| r.last())
            .copied()
    }
}

/// Simple direct circuit evaluator for ground truth testing.
///
/// Evaluates a circuit by topologically sorting gates and evaluating them in order.
/// Returns a mapping from all wire indices to their boolean values.
pub fn evaluate_circuit_direct(
    circuit: &Circuit,
    inputs: impl IntoIterator<Item = bool>,
) -> HashMap<AbsWireIdx, bool> {
    // Collect the inputs into a map we can keep adding to later.
    let mut wire_values: HashMap<AbsWireIdx, bool> = inputs
        .into_iter()
        .enumerate()
        .map(|(i, b)| (AbsWireIdx::from(i), b))
        .collect();

    // Make sure we have enough inputs.
    assert_eq!(
        wire_values.len(),
        circuit.num_inputs(),
        "circuit: expected number of inputs (got {}, need {})",
        wire_values.len(),
        circuit.num_inputs(),
    );

    // Evaluate each gate in order, which is fine because they're required to
    // be topologically sorted.
    for wire_idx in circuit.gate_idxs_iter() {
        if let Some(gate) = circuit.get_wire_as_gate(wire_idx) {
            // Get input values, panic here impossible since they should already
            // have been computed.
            let input1_val = wire_values[&gate.inp1()];
            let input2_val = wire_values[&gate.inp2()];

            // Compute output based on gate type.
            let output_val = match gate.ty() {
                GateType::AND => input1_val & input2_val,
                GateType::XOR => input1_val ^ input2_val,
            };

            wire_values.insert(wire_idx, output_val);
        } else {
            panic!("circuit: wire {wire_idx:?} is not a gate!");
        }
    }

    wire_values
}

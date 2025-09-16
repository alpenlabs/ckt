//! Circuit representation and evaluation.

use std::collections::*;

use rand::seq::SliceRandom;
use rand::rng;

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
        (self.num_inputs()..self.wires.len()).map(AbsWireIdx::from)
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

/// Information about the wires that are made available at a particular level,
/// either as an input or as an output of an evaluatable gate.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct LevelWires {
    wires: Vec<AbsWireIdx>,
}

impl LevelWires {
    pub fn new(wires: Vec<AbsWireIdx>) -> Self {
        Self { wires }
    }

    pub fn new_inputs(inputs: usize) -> Self {
        Self::new((0..inputs).map(AbsWireIdx::from).collect())
    }

    pub fn wires(&self) -> &[AbsWireIdx] {
        &self.wires
    }
}

/// Circuit evaluator based on layer clustering outputs.
///
/// Evaluates a circuit level by level using the provided layer clustering,
/// where each level contains wires that can be evaluated in parallel.
pub fn evaluate_circuit_layered(
    circuit: &Circuit,
    level_wires: Vec<LevelWires>,
    inputs: &[bool],
) -> BTreeMap<AbsWireIdx, bool> {
    // Validate inputs
    assert_eq!(
        inputs.len(),
        circuit.num_inputs(),
        "circuit: expected {} inputs, got {}",
        circuit.num_inputs(),
        inputs.len()
    );

    let mut wire_values = BTreeMap::new();
    let mut rng = rng();

    // Process each level
    for (level_idx, level) in level_wires.iter().enumerate() {
        if level_idx == 0 {
            // Level 0: input wires
            for (i, &wire_idx) in level.wires().iter().enumerate() {
                wire_values.insert(wire_idx, inputs[i]);
            }
        } else {
            // Level > 0: gate wires in random order
            // Create index vector and shuffle it
            let mut indices: Vec<u32> = (0..level.wires().len() as u32).collect();
            indices.shuffle(&mut rng);

            for &idx in &indices {
                let wire_idx = level.wires()[idx as usize];
                if let Some(gate) = circuit.get_wire_as_gate(wire_idx) {
                    // Get input values
                    let input1_val = wire_values[&gate.inp1()];
                    let input2_val = wire_values[&gate.inp2()];

                    // Compute output based on gate type
                    let output_val = match gate.ty() {
                        GateType::AND => input1_val & input2_val,
                        GateType::XOR => input1_val ^ input2_val,
                    };

                    wire_values.insert(wire_idx, output_val);
                }
            }
        }
    }

    wire_values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::builder::gen_level_allocs;
    use crate::analysis::example_circuits::build_two_bit_equality_circuit;

    /// Common test function that verifies all evaluators produce the same results
    /// for a given circuit and set of input test cases.
    fn test_evaluators_consistency(circuit: &Circuit, test_cases: Vec<Vec<bool>>) {
        for inputs in test_cases {
            // Generate level allocations
            let level_wires = gen_level_allocs(circuit);

            // Run direct evaluator
            let direct_result = evaluate_circuit_direct(circuit, inputs.clone());

            // Run layered evaluator multiple times to test randomization
            for trial in 0..5 {
                let layered_result = evaluate_circuit_layered(circuit, level_wires.clone(), &inputs);

                // Convert HashMap to BTreeMap for comparison
                let direct_btree: BTreeMap<AbsWireIdx, bool> = direct_result.iter().map(|(&k, &v)| (k, v)).collect();

                // Compare results
                assert_eq!(
                    direct_btree, layered_result,
                    "Evaluators produced different results on trial {} for inputs: {:?}", trial, inputs
                );
            }
        }
    }

    /// Generate all possible input combinations for a circuit with n inputs
    fn generate_all_inputs(num_inputs: usize) -> Vec<Vec<bool>> {
        let mut test_cases = Vec::new();
        for i in 0..(1 << num_inputs) {
            let mut inputs = Vec::new();
            for j in 0..num_inputs {
                inputs.push((i & (1 << j)) != 0);
            }
            test_cases.push(inputs);
        }
        test_cases
    }

    #[test]
    fn test_layered_vs_direct_evaluator() {
        // Create a test circuit: (a & b) ^ (c & d)
        let mut circuit = Circuit::new(4);

        // Add gates: gate0 = a & b, gate1 = c & d, gate2 = gate0 ^ gate1
        let gate0 = Gate::new(AbsWireIdx::from(0u32), AbsWireIdx::from(1u32), GateType::AND);
        let gate1 = Gate::new(AbsWireIdx::from(2u32), AbsWireIdx::from(3u32), GateType::AND);
        let gate0_wire = circuit.add_gate(gate0);
        let gate1_wire = circuit.add_gate(gate1);
        let gate2 = Gate::new(gate0_wire, gate1_wire, GateType::XOR);
        let _gate2_wire = circuit.add_gate(gate2);

        // Test with all possible input combinations
        let test_cases = generate_all_inputs(4);
        test_evaluators_consistency(&circuit, test_cases);
    }

    #[test]
    fn test_single_gate_circuit() {
        // Test simple single gate circuit: a & b
        let mut circuit = Circuit::new(2);
        let gate = Gate::new(AbsWireIdx::from(0u32), AbsWireIdx::from(1u32), GateType::AND);
        let _gate_wire = circuit.add_gate(gate);

        let test_cases = generate_all_inputs(2);
        test_evaluators_consistency(&circuit, test_cases);
    }

    #[test]
    fn test_two_bit_equality_adder_circuit() {
        // Use the complex adder circuit from example_circuits
        let circuit = build_two_bit_equality_circuit();

        // Test with specific meaningful cases for the 2-bit adder equality checker
        let test_cases = vec![
            // Test case 1: 1+2 == 2+1 (should be equal, output=false)
            // a=01 (1), b=10 (2), c=10 (2), d=01 (1)
            // Input order: [a0,a1,b0,b1,c0,c1,d0,d1]
            vec![true, false, false, true, false, true, true, false],

            // Test case 2: 2+1 != 0+0 (should be different, output=true)
            // a=10 (2), b=01 (1), c=00 (0), d=00 (0)
            vec![false, true, true, false, false, false, false, false],

            // Test case 3: 0+0 == 0+0 (should be equal, output=false)
            // a=00 (0), b=00 (0), c=00 (0), d=00 (0)
            vec![false, false, false, false, false, false, false, false],

            // Test case 4: 3+3 != 2+2 (6 != 4, should be different, output=true)
            // a=11 (3), b=11 (3), c=10 (2), d=10 (2)
            vec![true, true, true, true, false, true, false, true],

            // Test case 5: 1+1 == 2+0 (both equal 2, should be equal, output=false)
            // a=01 (1), b=01 (1), c=10 (2), d=00 (0)
            vec![true, false, true, false, false, true, false, false],
        ];

        test_evaluators_consistency(&circuit, test_cases);
    }

    #[test]
    fn test_comprehensive_two_bit_adder() {
        // Test all possible combinations for the 2-bit adder circuit
        let circuit = build_two_bit_equality_circuit();

        // This circuit has 8 inputs, but testing all 2^8=256 combinations might be slow
        // Let's test a reasonable subset
        let mut test_cases = Vec::new();

        // Test some systematic patterns
        for a in 0..4 {  // 2-bit values 0-3
            for b in 0..4 {
                for c in 0..2 {  // Limited to reduce test time
                    for d in 0..2 {
                        let mut inputs = vec![false; 8];
                        // Convert to bit arrays: [a0,a1,b0,b1,c0,c1,d0,d1]
                        inputs[0] = (a & 1) != 0;      // a0
                        inputs[1] = (a & 2) != 0;      // a1
                        inputs[2] = (b & 1) != 0;      // b0
                        inputs[3] = (b & 2) != 0;      // b1
                        inputs[4] = (c & 1) != 0;      // c0
                        inputs[5] = (c & 2) != 0;      // c1
                        inputs[6] = (d & 1) != 0;      // d0
                        inputs[7] = (d & 2) != 0;      // d1
                        test_cases.push(inputs);
                    }
                }
            }
        }

        test_evaluators_consistency(&circuit, test_cases);
    }
}

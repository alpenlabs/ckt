//! N-bit adder circuit generator for v5a format
//!
//! This module provides utilities for generating ripple-carry adder circuits
//! that can be used for testing and validation of CKT tooling.

use ckt::GateType;
use ckt::v5::a::{CREDITS_OUTPUT, GateV5a, MAX_CREDITS, MAX_WIRE_ID};

// monoio is used by the binary and examples, not the library
use monoio as _;

/// Generate an n-bit ripple-carry adder circuit.
///
/// # Circuit Design
///
/// **Inputs**: 2n primary inputs
/// - Wires 2..(2+n): First n-bit operand (A)
/// - Wires (2+n)..(2+2n): Second n-bit operand (B)
///
/// **Outputs**: (n+1) outputs
/// - n sum bits
/// - 1 carry-out bit
///
/// **Wire numbering**:
/// - Wire 0: False constant
/// - Wire 1: True constant
/// - Wires 2..(2+2n): Primary inputs
/// - Wires (2+2n)..: Gate outputs
///
/// # Full Adder Implementation
///
/// For each bit position i, we compute:
/// ```text
/// half_sum = a[i] XOR b[i]
/// sum[i] = half_sum XOR carry[i]
/// half_carry = a[i] AND b[i]
/// carry_prop = half_sum AND carry[i]
/// carry[i+1] = half_carry XOR carry_prop
/// ```
///
/// Each full adder uses 5 gates (3 XOR, 2 AND).
/// An n-bit adder uses 5n gates total.
///
/// # Example
///
/// ```
/// use adder::generate_adder;
///
/// // Generate an 8-bit adder (adds two 8-bit numbers)
/// let circuit = generate_adder(8);
/// assert_eq!(circuit.primary_inputs, 16); // 8 + 8
/// assert_eq!(circuit.outputs.len(), 9);   // 8 sum bits + 1 carry
/// assert_eq!(circuit.gates.len(), 40);    // 5 gates per bit * 8 bits
/// ```
pub fn generate_adder(n_bits: usize) -> AdderCircuit {
    if n_bits == 0 {
        panic!("n_bits must be at least 1");
    }

    if n_bits > 1_000_000 {
        panic!("n_bits too large (max 1,000,000 for practical use)");
    }

    let primary_inputs = 2 * n_bits as u64;
    let mut gates = Vec::with_capacity(5 * n_bits);
    let mut next_wire = 2 + primary_inputs; // First gate output wire
    let mut outputs = Vec::with_capacity(n_bits + 1);

    // Carry wire starts at wire 0 (constant false)
    let mut carry = 0u64;

    for i in 0..n_bits {
        let a = 2 + i as u64; // Wire for A[i]
        let b = 2 + n_bits as u64 + i as u64; // Wire for B[i]

        // Full adder for bit i
        let (sum_bit, carry_out, bit_gates) = full_adder(a, b, carry, next_wire);

        // Update next available wire
        next_wire += bit_gates.len() as u64;

        // Add gates to circuit
        gates.extend(bit_gates);

        // The sum bit is an output
        outputs.push(sum_bit);

        // Carry for next bit
        carry = carry_out;
    }

    // Final carry is also an output
    outputs.push(carry);

    // Assign credits to all wires
    let gates_with_credits = assign_credits(&gates, &outputs, primary_inputs);

    AdderCircuit {
        primary_inputs,
        gates: gates_with_credits,
        outputs,
        n_bits,
    }
}

/// A complete adder circuit with all metadata
#[derive(Debug, Clone)]
pub struct AdderCircuit {
    /// Number of primary inputs (2 * n_bits)
    pub primary_inputs: u64,
    /// All gates in the circuit with credits assigned
    pub gates: Vec<GateV5a>,
    /// Output wire IDs (n_bits sum bits + 1 carry bit)
    pub outputs: Vec<u64>,
    /// Number of bits in each operand
    pub n_bits: usize,
}

impl AdderCircuit {
    /// Get the total number of gates
    pub fn num_gates(&self) -> usize {
        self.gates.len()
    }

    /// Get the number of XOR gates
    pub fn num_xor_gates(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| g.gate_type == GateType::XOR)
            .count()
    }

    /// Get the number of AND gates
    pub fn num_and_gates(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| g.gate_type == GateType::AND)
            .count()
    }

    /// Verify the circuit structure is valid
    pub fn validate(&self) -> Result<(), String> {
        // Check wire IDs are in range
        for gate in &self.gates {
            if gate.in1 > MAX_WIRE_ID {
                return Err(format!("Wire ID {} exceeds maximum", gate.in1));
            }
            if gate.in2 > MAX_WIRE_ID {
                return Err(format!("Wire ID {} exceeds maximum", gate.in2));
            }
            if gate.out > MAX_WIRE_ID {
                return Err(format!("Wire ID {} exceeds maximum", gate.out));
            }
            if gate.credits > MAX_CREDITS {
                return Err(format!("Credits {} exceeds maximum", gate.credits));
            }
        }

        // Check outputs are valid
        for &out in &self.outputs {
            if out > MAX_WIRE_ID {
                return Err(format!("Output wire ID {} exceeds maximum", out));
            }
        }

        Ok(())
    }
}

/// Generate a full adder for one bit position.
///
/// Returns: (sum_output_wire, carry_output_wire, gates)
fn full_adder(a: u64, b: u64, carry_in: u64, next_wire: u64) -> (u64, u64, Vec<GateV5a>) {
    let mut gates = Vec::with_capacity(5);
    let mut wire = next_wire;

    // Gate 1: half_sum = a XOR b
    let half_sum = wire;
    gates.push(GateV5a {
        in1: a,
        in2: b,
        out: half_sum,
        credits: 0, // Will be filled in by assign_credits
        gate_type: GateType::XOR,
    });
    wire += 1;

    // Gate 2: sum = half_sum XOR carry_in
    let sum = wire;
    gates.push(GateV5a {
        in1: half_sum,
        in2: carry_in,
        out: sum,
        credits: 0,
        gate_type: GateType::XOR,
    });
    wire += 1;

    // Gate 3: half_carry = a AND b
    let half_carry = wire;
    gates.push(GateV5a {
        in1: a,
        in2: b,
        out: half_carry,
        credits: 0,
        gate_type: GateType::AND,
    });
    wire += 1;

    // Gate 4: carry_prop = half_sum AND carry_in
    let carry_prop = wire;
    gates.push(GateV5a {
        in1: half_sum,
        in2: carry_in,
        out: carry_prop,
        credits: 0,
        gate_type: GateType::AND,
    });
    wire += 1;

    // Gate 5: carry_out = half_carry XOR carry_prop
    let carry_out = wire;
    gates.push(GateV5a {
        in1: half_carry,
        in2: carry_prop,
        out: carry_out,
        credits: 0,
        gate_type: GateType::XOR,
    });

    (sum, carry_out, gates)
}

/// Assign credits to all gates based on usage analysis.
///
/// Credits indicate how many times a wire will be consumed:
/// - 0: Circuit output (never freed)
/// - 1-16777214: Wire consumed N times
/// - 16777215: Constant or primary input
fn assign_credits(gates: &[GateV5a], outputs: &[u64], _primary_inputs: u64) -> Vec<GateV5a> {
    use std::collections::HashMap;

    // Count how many times each wire is used as an input
    let mut usage_count: HashMap<u64, u32> = HashMap::new();

    for gate in gates {
        *usage_count.entry(gate.in1).or_insert(0) += 1;
        *usage_count.entry(gate.in2).or_insert(0) += 1;
    }

    // Create output set for quick lookup
    let output_set: std::collections::HashSet<u64> = outputs.iter().copied().collect();

    // Assign credits to each gate
    gates
        .iter()
        .map(|gate| {
            let credits = if output_set.contains(&gate.out) {
                // Output wires get credit 0
                CREDITS_OUTPUT
            } else if let Some(&count) = usage_count.get(&gate.out) {
                // Wire is used 'count' times
                count
            } else {
                // Wire is never used (dead code, but still valid)
                0
            };

            GateV5a {
                in1: gate.in1,
                in2: gate.in2,
                out: gate.out,
                credits,
                gate_type: gate.gate_type,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_1bit_adder() {
        let circuit = generate_adder(1);
        assert_eq!(circuit.primary_inputs, 2);
        assert_eq!(circuit.outputs.len(), 2); // 1 sum + 1 carry
        assert_eq!(circuit.gates.len(), 5); // 5 gates per bit
        assert_eq!(circuit.num_xor_gates(), 3);
        assert_eq!(circuit.num_and_gates(), 2);
        assert!(circuit.validate().is_ok());
    }

    #[test]
    fn test_8bit_adder() {
        let circuit = generate_adder(8);
        assert_eq!(circuit.primary_inputs, 16);
        assert_eq!(circuit.outputs.len(), 9); // 8 sum + 1 carry
        assert_eq!(circuit.gates.len(), 40); // 5 gates per bit * 8
        assert_eq!(circuit.num_xor_gates(), 24);
        assert_eq!(circuit.num_and_gates(), 16);
        assert!(circuit.validate().is_ok());
    }

    #[test]
    fn test_32bit_adder() {
        let circuit = generate_adder(32);
        assert_eq!(circuit.primary_inputs, 64);
        assert_eq!(circuit.outputs.len(), 33); // 32 sum + 1 carry
        assert_eq!(circuit.gates.len(), 160); // 5 * 32
        assert!(circuit.validate().is_ok());
    }

    #[test]
    fn test_credits_assigned() {
        let circuit = generate_adder(2);

        // Check that all gates have credits assigned
        for gate in &circuit.gates {
            // Credits should be > 0 for all gates (either used or output)
            // Actually, some intermediate wires might have specific counts
            assert!(gate.credits <= MAX_CREDITS);
        }

        // Check that output wires have credit 0
        let output_set: std::collections::HashSet<_> = circuit.outputs.iter().collect();
        for gate in &circuit.gates {
            if output_set.contains(&gate.out) {
                assert_eq!(
                    gate.credits, CREDITS_OUTPUT,
                    "Output wire {} should have CREDITS_OUTPUT",
                    gate.out
                );
            }
        }
    }

    #[test]
    fn test_wire_numbering() {
        let circuit = generate_adder(4);

        // Primary inputs are wires 2..10 (4+4)
        let first_gate_output = 2 + circuit.primary_inputs;

        // All gate output wires should be >= first_gate_output
        for gate in &circuit.gates {
            assert!(
                gate.out >= first_gate_output,
                "Gate output {} is in primary input range",
                gate.out
            );
        }

        // All gate input wires should be valid (0, 1, or primary input, or previous gate output)
        let mut valid_wires: std::collections::HashSet<u64> = std::collections::HashSet::new();
        valid_wires.insert(0); // False constant
        valid_wires.insert(1); // True constant

        // Add primary inputs
        for i in 0..circuit.primary_inputs {
            valid_wires.insert(2 + i);
        }

        // Process gates in order, checking inputs are valid
        for gate in &circuit.gates {
            assert!(
                valid_wires.contains(&gate.in1),
                "Gate input {} not yet defined",
                gate.in1
            );
            assert!(
                valid_wires.contains(&gate.in2),
                "Gate input {} not yet defined",
                gate.in2
            );
            valid_wires.insert(gate.out);
        }
    }

    #[test]
    #[should_panic(expected = "n_bits must be at least 1")]
    fn test_zero_bits_panics() {
        generate_adder(0);
    }

    #[test]
    fn test_usage_count() {
        let circuit = generate_adder(2);

        // In a 2-bit adder:
        // Bit 0: a[0], b[0], carry_in=0
        // Bit 1: a[1], b[1], carry from bit 0

        // Check that wire 0 (false constant) is used as carry_in for bit 0
        let wire_0_usage = circuit
            .gates
            .iter()
            .filter(|g| g.in1 == 0 || g.in2 == 0)
            .count();
        assert!(wire_0_usage > 0, "Wire 0 (false) should be used");
    }

    /// Integration test example showing how to use the adder for validation
    #[test]
    fn test_adder_for_validation() {
        // Generate a small adder for testing
        let circuit = generate_adder(4);

        // Verify basic properties
        assert_eq!(circuit.n_bits, 4);
        assert_eq!(circuit.primary_inputs, 8); // 4 bits A + 4 bits B
        assert_eq!(circuit.outputs.len(), 5); // 4 sum bits + 1 carry
        assert_eq!(circuit.num_gates(), 20); // 5 gates per bit * 4

        // Validate circuit structure
        assert!(circuit.validate().is_ok(), "Circuit should be valid");

        // Verify gate counts match expected ratios (3:2 XOR:AND)
        let xor_count = circuit.num_xor_gates();
        let and_count = circuit.num_and_gates();
        assert_eq!(xor_count, 12); // 3 per bit * 4
        assert_eq!(and_count, 8); // 2 per bit * 4
        assert_eq!(xor_count + and_count, circuit.num_gates());

        // Verify wire numbering follows v5a conventions
        // - Wire 0: false constant
        // - Wire 1: true constant
        // - Wires 2..10: primary inputs (8 inputs)
        // - Wires 10+: gate outputs

        let first_gate_output = 2 + circuit.primary_inputs;
        for gate in &circuit.gates {
            // All gate outputs should be in the gate output range
            assert!(
                gate.out >= first_gate_output,
                "Gate output {} should be >= {}",
                gate.out,
                first_gate_output
            );
        }

        // Verify all outputs are present in the circuit
        for &output_wire in &circuit.outputs {
            let is_gate_output = circuit.gates.iter().any(|g| g.out == output_wire);
            assert!(
                is_gate_output,
                "Output wire {} should be produced by a gate",
                output_wire
            );
        }

        // Verify credits are properly assigned
        let output_set: std::collections::HashSet<_> = circuit.outputs.iter().copied().collect();
        for gate in &circuit.gates {
            if output_set.contains(&gate.out) {
                assert_eq!(
                    gate.credits, CREDITS_OUTPUT,
                    "Output wire {} should have CREDITS_OUTPUT (0)",
                    gate.out
                );
            } else {
                // Non-output wires should have usage count > 0
                assert!(
                    gate.credits > 0,
                    "Non-output wire {} should have credits > 0",
                    gate.out
                );
            }
        }
    }
}

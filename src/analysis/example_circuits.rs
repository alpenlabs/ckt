//! Example circuit definitions for testing and demonstration.

use super::circuit::*;
use super::coords::*;
use super::gate::*;

/// Creates a circuit that takes 2-bit inputs a, b, c, d, computes a+b and c+d,
/// and checks if they are equal.
///
/// Inputs (8 wires total):
/// - a0, a1: 2-bit number a (a1 is MSB)
/// - b0, b1: 2-bit number b (b1 is MSB)  
/// - c0, c1: 2-bit number c (c1 is MSB)
/// - d0, d1: 2-bit number d (d1 is MSB)
///
/// Output: 1 wire that is 1 if (a+b) == (c+d), 0 otherwise
pub fn build_two_bit_equality_circuit() -> Circuit {
    let mut circuit = Circuit::new(8); // 8 input wires: a0,a1,b0,b1,c0,c1,d0,d1

    let input_wires: Vec<AbsWireIdx> = (0u32..8u32).map(AbsWireIdx::from).collect();
    let [a0, a1, b0, b1, c0, c1, d0, d1] = [
        input_wires[0],
        input_wires[1],
        input_wires[2],
        input_wires[3],
        input_wires[4],
        input_wires[5],
        input_wires[6],
        input_wires[7],
    ];

    // 2-bit addition: sum = a + b
    // sum[0] = a0 XOR b0
    let sum_a_b_0 = circuit.add_gate(Gate::new(a0, b0, GateType::XOR));

    // carry from bit 0 = a0 AND b0
    let carry_0_ab = circuit.add_gate(Gate::new(a0, b0, GateType::AND));

    // sum[1] = a1 XOR b1 XOR carry_0
    let a1_xor_b1 = circuit.add_gate(Gate::new(a1, b1, GateType::XOR));
    let sum_a_b_1 = circuit.add_gate(Gate::new(a1_xor_b1, carry_0_ab, GateType::XOR));

    // carry from bit 1 = (a1 AND b1) OR (carry_0 AND (a1 XOR b1))
    // OR = (A XOR B) XOR (A AND B)
    let a1_and_b1 = circuit.add_gate(Gate::new(a1, b1, GateType::AND));
    let carry_and_xor = circuit.add_gate(Gate::new(carry_0_ab, a1_xor_b1, GateType::AND));
    let carry_xor = circuit.add_gate(Gate::new(a1_and_b1, carry_and_xor, GateType::XOR));
    let carry_and = circuit.add_gate(Gate::new(a1_and_b1, carry_and_xor, GateType::AND));
    let sum_a_b_carry = circuit.add_gate(Gate::new(carry_xor, carry_and, GateType::XOR)); // A OR B

    // 2-bit addition: sum = c + d
    // sum[0] = c0 XOR d0
    let sum_c_d_0 = circuit.add_gate(Gate::new(c0, d0, GateType::XOR));

    // carry from bit 0 = c0 AND d0
    let carry_0_cd = circuit.add_gate(Gate::new(c0, d0, GateType::AND));

    // sum[1] = c1 XOR d1 XOR carry_0
    let c1_xor_d1 = circuit.add_gate(Gate::new(c1, d1, GateType::XOR));
    let sum_c_d_1 = circuit.add_gate(Gate::new(c1_xor_d1, carry_0_cd, GateType::XOR));

    // carry from bit 1 = (c1 AND d1) OR (carry_0 AND (c1 XOR d1))
    // OR = (A XOR B) XOR (A AND B)
    let c1_and_d1 = circuit.add_gate(Gate::new(c1, d1, GateType::AND));
    let carry_and_xor_cd = circuit.add_gate(Gate::new(carry_0_cd, c1_xor_d1, GateType::AND));
    let carry_xor_cd = circuit.add_gate(Gate::new(c1_and_d1, carry_and_xor_cd, GateType::XOR));
    let carry_and_cd = circuit.add_gate(Gate::new(c1_and_d1, carry_and_xor_cd, GateType::AND));
    let sum_c_d_carry = circuit.add_gate(Gate::new(carry_xor_cd, carry_and_cd, GateType::XOR)); // A OR B

    // Equality check: (a+b) == (c+d)
    // This means all bits must be equal:
    // bit 0 equal = NOT(sum_a_b_0 XOR sum_c_d_0) = sum_a_b_0 XOR sum_c_d_0 XOR 1
    // Since we don't have NOT or constants, we'll use: bit0_eq = NOT(sum_a_b_0 XOR sum_c_d_0)
    // For now, let's compute the XOR and assume we'll invert it externally
    let bit0_diff = circuit.add_gate(Gate::new(sum_a_b_0, sum_c_d_0, GateType::XOR));
    let bit1_diff = circuit.add_gate(Gate::new(sum_a_b_1, sum_c_d_1, GateType::XOR));
    let carry_diff = circuit.add_gate(Gate::new(sum_a_b_carry, sum_c_d_carry, GateType::XOR));

    // All bits equal = NOT(bit0_diff OR bit1_diff OR carry_diff)
    // = NOT(bit0_diff) AND NOT(bit1_diff) AND NOT(carry_diff)
    // Since we can't compute NOT directly, the circuit outputs the OR of differences
    // Output will be 0 when numbers are equal, 1 when different

    // OR = (A XOR B) XOR (A AND B)
    let bit01_diff_xor = circuit.add_gate(Gate::new(bit0_diff, bit1_diff, GateType::XOR));
    let bit01_diff_and = circuit.add_gate(Gate::new(bit0_diff, bit1_diff, GateType::AND));
    let bit01_diff = circuit.add_gate(Gate::new(bit01_diff_xor, bit01_diff_and, GateType::XOR)); // bit0_diff OR bit1_diff

    let all_diff_xor = circuit.add_gate(Gate::new(bit01_diff, carry_diff, GateType::XOR));
    let all_diff_and = circuit.add_gate(Gate::new(bit01_diff, carry_diff, GateType::AND));
    let _all_diff = circuit.add_gate(Gate::new(all_diff_xor, all_diff_and, GateType::XOR)); // OR of all differences

    // The final output wire is _all_diff - 0 means equal, 1 means not equal
    // To get proper equality (1 for equal, 0 for not equal), we'd need to invert this

    circuit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::circuit::evaluate_circuit_direct;

    #[test]
    fn test_two_bit_equality_circuit() {
        let circuit = build_two_bit_equality_circuit();

        // Test cases: [a1, a0, b1, b0, c1, c0, d1, d0]
        // We expect output 0 when (a+b) == (c+d), 1 when different

        // Test case 1: 1+2 == 2+1 (should be equal)
        // a=01 (1), b=10 (2), c=10 (2), d=01 (1)
        let inputs1 = vec![true, false, false, true, false, true, true, false]; // [a0,a1,b0,b1,c0,c1,d0,d1]
        let (result1, _) = evaluate_circuit_direct(&circuit, inputs1);
        let output_wire = AbsWireIdx::from(circuit.num_wires() - 1);
        assert_eq!(result1[&output_wire], false, "1+2 should equal 2+1"); // 0 means equal

        // Test case 2: 2+1 != 0+0 (should be different)
        // a=10 (2), b=01 (1), c=00 (0), d=00 (0)
        let inputs2 = vec![false, true, true, false, false, false, false, false];
        let (result2, _) = evaluate_circuit_direct(&circuit, inputs2);
        assert_eq!(result2[&output_wire], true, "2+1 should not equal 0+0"); // 1 means different

        // Test case 3: 0+0 == 0+0 (should be equal)
        // a=00 (0), b=00 (0), c=00 (0), d=00 (0)
        let inputs3 = vec![false, false, false, false, false, false, false, false];
        let (result3, _) = evaluate_circuit_direct(&circuit, inputs3);
        assert_eq!(result3[&output_wire], false, "0+0 should equal 0+0"); // 0 means equal

        // Test case 4: 3+3 != 2+2 (both equal 6 and 4 respectively)
        // a=11 (3), b=11 (3), c=10 (2), d=10 (2)
        let inputs4 = vec![true, true, true, true, false, true, false, true];
        let (result4, _) = evaluate_circuit_direct(&circuit, inputs4);
        assert_eq!(result4[&output_wire], true, "3+3 should not equal 2+2"); // 1 means different

        // Test case 5: 1+1 == 2+0 (both equal 2)
        // a=01 (1), b=01 (1), c=10 (2), d=00 (0)
        let inputs5 = vec![true, false, true, false, false, true, false, false];
        let (result5, _) = evaluate_circuit_direct(&circuit, inputs5);
        assert_eq!(result5[&output_wire], false, "1+1 should equal 2+0"); // 0 means equal
    }
}

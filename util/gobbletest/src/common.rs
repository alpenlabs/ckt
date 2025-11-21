use bitvec::vec::BitVec;
use std::fs::File;
use std::io::{BufReader, Read};

/// Read input bits from a text file containing 0s and 1s
pub fn read_inputs(input_file: &str, expected_num_inputs: usize) -> BitVec {
    let mut input_string = String::new();
    let file = File::open(input_file)
        .unwrap_or_else(|_| panic!("Failed to open input file: {}", input_file));
    let mut reader = BufReader::new(file);
    reader.read_to_string(&mut input_string).unwrap();

    let input_string = input_string.trim();

    assert_eq!(
        input_string.len(),
        expected_num_inputs,
        "Input file has {} bits but circuit expects {}",
        input_string.len(),
        expected_num_inputs
    );

    let mut input_values_bits = BitVec::repeat(false, expected_num_inputs);
    for (idx, char) in input_string.chars().enumerate() {
        match char {
            '0' => input_values_bits.set(idx, false),
            '1' => input_values_bits.set(idx, true),
            _ => panic!("Invalid input character '{}' at position {}", char, idx),
        }
    }

    input_values_bits
}

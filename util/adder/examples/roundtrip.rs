//! Example: Write and read back an adder circuit to verify v5a format correctness.
//!
//! This example demonstrates:
//! 1. Generating an n-bit adder circuit
//! 2. Writing it to a v5a format file
//! 3. Reading it back
//! 4. Verifying all data matches (gates, outputs, metadata)
//!
//! Run with: cargo run --example roundtrip

use adder::generate_adder;
use ckt::v5::a::reader::CircuitReaderV5a;
use ckt::v5::a::writer::CircuitWriterV5a;
use std::path::PathBuf;

fn main() {
    println!("=== CKT v5a Format Roundtrip Test ===\n");

    // Generate an 8-bit adder
    let n_bits = 8;
    println!("Generating {}-bit adder circuit...", n_bits);
    let circuit = generate_adder(n_bits);

    println!("  Primary inputs: {}", circuit.primary_inputs);
    println!("  Outputs:        {}", circuit.outputs.len());
    println!("  Total gates:    {}", circuit.num_gates());
    println!("  XOR gates:      {}", circuit.num_xor_gates());
    println!("  AND gates:      {}", circuit.num_and_gates());
    println!();

    // Create temporary file path
    let temp_file = PathBuf::from("/tmp/roundtrip_adder.ckt");

    // Create monoio runtime for async operations
    let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .build()
        .expect("Failed to create runtime");

    rt.block_on(async {
        // ===== WRITE PHASE =====
        println!("Writing circuit to {}...", temp_file.display());

        let mut writer =
            CircuitWriterV5a::new(&temp_file, circuit.primary_inputs, circuit.outputs.clone())
                .await
                .expect("Failed to create writer");

        writer
            .write_gates(&circuit.gates)
            .await
            .expect("Failed to write gates");

        let stats = writer.finalize().await.expect("Failed to finalize");

        println!("  Bytes written:  {}", stats.total_gates * 16); // approximate
        println!("  BLAKE3 checksum: {}", hex::encode(&stats.checksum));
        println!();

        // ===== READ PHASE =====
        println!("Reading circuit back from file...");

        let mut reader = CircuitReaderV5a::open(&temp_file).expect("Failed to create reader");

        let header = reader.header();
        println!("  Header:");
        println!("    XOR gates:      {}", header.xor_gates);
        println!("    AND gates:      {}", header.and_gates);
        println!("    Primary inputs: {}", header.primary_inputs);
        println!("    Outputs:        {}", header.num_outputs);
        println!();

        // Get outputs (already loaded during open)
        let outputs = reader.outputs().to_vec();
        println!("  Read {} outputs", outputs.len());

        // Read all gates block by block
        let mut gates_read = Vec::new();
        while let Some(block_gates) = reader.next_block().await.expect("Failed to read block") {
            gates_read.extend(block_gates);
        }
        println!("  Read {} gates", gates_read.len());
        println!();

        // ===== VERIFICATION PHASE =====
        println!("Verifying data integrity...");

        // Check metadata
        assert_eq!(
            header.primary_inputs, circuit.primary_inputs,
            "Primary inputs mismatch"
        );
        assert_eq!(
            header.num_outputs,
            circuit.outputs.len() as u64,
            "Output count mismatch"
        );
        assert_eq!(
            header.xor_gates,
            circuit.num_xor_gates() as u64,
            "XOR gate count mismatch"
        );
        assert_eq!(
            header.and_gates,
            circuit.num_and_gates() as u64,
            "AND gate count mismatch"
        );
        println!("  ✓ Metadata matches");

        // Check outputs
        assert_eq!(
            outputs.len(),
            circuit.outputs.len(),
            "Output count mismatch"
        );
        for (i, (&expected, &actual)) in circuit.outputs.iter().zip(outputs.iter()).enumerate() {
            assert_eq!(actual, expected, "Output {} mismatch", i);
        }
        println!("  ✓ All {} outputs match", outputs.len());

        // Check gates
        assert_eq!(gates_read.len(), circuit.gates.len(), "Gate count mismatch");
        for (i, (expected, actual)) in circuit.gates.iter().zip(gates_read.iter()).enumerate() {
            assert_eq!(actual.in1, expected.in1, "Gate {} in1 mismatch", i);
            assert_eq!(actual.in2, expected.in2, "Gate {} in2 mismatch", i);
            assert_eq!(actual.out, expected.out, "Gate {} out mismatch", i);
            assert_eq!(
                actual.credits, expected.credits,
                "Gate {} credits mismatch",
                i
            );
            assert_eq!(
                actual.gate_type, expected.gate_type,
                "Gate {} type mismatch",
                i
            );
        }
        println!("  ✓ All {} gates match", gates_read.len());

        println!();
        println!("=== Roundtrip Test PASSED ===");
        println!();
        println!("The v5a format correctly preserves:");
        println!("  • Circuit metadata (inputs, outputs, gate counts)");
        println!("  • All output wire IDs");
        println!("  • All gate data (in1, in2, out, credits, type)");
        println!("  • Data integrity via BLAKE3 checksum");
    });

    // Clean up
    let _ = std::fs::remove_file(&temp_file);
}

// Simple hex encoding helper
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

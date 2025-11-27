//! CLI tool for generating n-bit adder circuits in v5a format.

use adder::generate_adder;
use ckt::v5::a::writer::CircuitWriterV5a;
use monoio::{FusionDriver, RuntimeBuilder};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <n_bits> [output_file]", args[0]);
        eprintln!();
        eprintln!("Generate an n-bit ripple-carry adder circuit in v5a format.");
        eprintln!();
        eprintln!("Arguments:");
        eprintln!("  n_bits       Number of bits for each operand (1-1000000)");
        eprintln!("  output_file  Output file path (default: adder_<n>bit.ckt)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} 8              # Generate 8-bit adder", args[0]);
        eprintln!(
            "  {} 32 adder.ckt   # Generate 32-bit adder to adder.ckt",
            args[0]
        );
        std::process::exit(1);
    }

    let n_bits: usize = args[1].parse().unwrap_or_else(|_| {
        eprintln!("Error: n_bits must be a positive integer");
        std::process::exit(1);
    });

    if n_bits == 0 {
        eprintln!("Error: n_bits must be at least 1");
        std::process::exit(1);
    }

    if n_bits > 1_000_000 {
        eprintln!("Error: n_bits too large (max 1,000,000)");
        std::process::exit(1);
    }

    let output_file = if args.len() >= 3 {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from(format!("adder_{}bit.ckt", n_bits))
    };

    println!("Generating {}-bit adder circuit...", n_bits);

    // Generate the circuit
    let circuit = generate_adder(n_bits);

    println!("Circuit statistics:");
    println!("  Primary inputs:  {}", circuit.primary_inputs);
    println!("  Outputs:         {}", circuit.outputs.len());
    println!("  Total gates:     {}", circuit.num_gates());
    println!("  XOR gates:       {}", circuit.num_xor_gates());
    println!("  AND gates:       {}", circuit.num_and_gates());

    // Validate circuit
    if let Err(e) = circuit.validate() {
        eprintln!("Error: Circuit validation failed: {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Writing to {}...", output_file.display());

    // Write the circuit using monoio runtime
    let mut rt = RuntimeBuilder::<FusionDriver>::new()
        .build()
        .expect("Failed to create monoio runtime");

    rt.block_on(async {
        // Create writer
        let mut writer = CircuitWriterV5a::new(
            &output_file,
            circuit.primary_inputs,
            circuit.outputs.clone(),
        )
        .await
        .unwrap_or_else(|e| {
            eprintln!("Error: Failed to create writer: {}", e);
            std::process::exit(1);
        });

        // Write all gates
        writer
            .write_gates(&circuit.gates)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Error: Failed to write gates: {}", e);
                std::process::exit(1);
            });

        // Finalize and get stats
        let stats = writer.finalize().await.unwrap_or_else(|e| {
            eprintln!("Error: Failed to finalize circuit: {}", e);
            std::process::exit(1);
        });

        println!("Successfully wrote circuit!");
        println!();
        println!("File statistics:");
        println!("  File size:       {} bytes", stats.total_gates * 16); // approximate
        println!("  Checksum (BLAKE3): {}", hex::encode(&stats.checksum));
    });

    println!();
    println!("Done! Circuit written to {}", output_file.display());
    println!();
    println!("Circuit description:");
    println!("  Inputs:  A[0..{}] (wires 2..{})", n_bits - 1, 2 + n_bits);
    println!(
        "           B[0..{}] (wires {}..{})",
        n_bits - 1,
        2 + n_bits,
        2 + 2 * n_bits
    );
    println!(
        "  Outputs: Sum[0..{}] + Carry (total {} outputs)",
        n_bits - 1,
        circuit.outputs.len()
    );
    println!();
    println!("To verify: Use CKT reader tools to validate the file format.");
}

// Simple hex encoding helper (to avoid adding hex crate dependency)
mod hex {
    pub(crate) fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

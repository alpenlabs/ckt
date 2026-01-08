mod common;
mod e2e;
mod eval;
mod eval_translate;
mod exec;
mod garble;
mod garble_translate;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[monoio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <mode> [args...]", args[0]);
        eprintln!("Modes:");
        eprintln!("  garble <circuit>                              - Run garble test");
        eprintln!(
            "  e2e <circuit> <inputs> [garbled_circuit_path] - Run end-to-end test: exec → garble → eval"
        );
        eprintln!(
            "  e2e-translate <circuit> <inputs> [garbled_circuit_path] - Run end-to-end test with translation"
        );
        std::process::exit(1);
    }

    let mode = &args[1];
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    match mode.as_str() {
        "garble" => {
            if args.len() != 3 {
                eprintln!("Usage: {} garble <circuit>", args[0]);
                std::process::exit(1);
            }
            let circuit = &args[2];
            let garbler_output_labels = garble::garble_discard(circuit, &mut rng).await;
            println!("{:?}", garbler_output_labels);
        }
        "e2e" => {
            if args.len() != 4 && args.len() != 5 {
                eprintln!(
                    "Usage: {} e2e <circuit> <inputs> [garbled_circuit_path]",
                    args[0]
                );
                std::process::exit(1);
            }
            let circuit = &args[2];
            let inputs = &args[3];
            let garbled_path = args.get(4).map(|s| s.as_str());
            e2e::test_end_to_end(circuit, inputs, &mut rng, garbled_path).await;
        }
        "e2e-translate" => {
            if args.len() != 4 && args.len() != 5 {
                eprintln!(
                    "Usage: {} e2e-translate <circuit> <inputs> [garbled_circuit_path]",
                    args[0]
                );
                std::process::exit(1);
            }
            let circuit = &args[2];
            let inputs = &args[3];
            let garbled_path = args.get(4).map(|s| s.as_str());
            e2e::test_end_to_end_translate(circuit, inputs, &mut rng, garbled_path).await;
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            eprintln!("Valid modes: garble, e2e, e2e-translate");
            std::process::exit(1);
        }
    }
}

mod garble;
mod eval;
mod exec;
mod common;
mod e2e;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

#[monoio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: {} <circuit> <inputs>", args[0]);
        eprintln!("Run end-to-end test: exec → garble → eval");
        std::process::exit(1);
    }
    
    let circuit = &args[1];
    let inputs = &args[2];
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    
    e2e::test_end_to_end(circuit, inputs, &mut rng).await;
}

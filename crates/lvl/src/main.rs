mod cli;

use ckt_lvl::prealloc;
use cli::{Cli, Command};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[monoio::main(timer_enabled = true)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse_args();

    match args.command {
        Command::Prealloc(prealloc_args) => run_prealloc(prealloc_args).await,
    }
}

async fn run_prealloc(args: cli::PreallocCommand) -> Result<(), Box<dyn std::error::Error>> {
    println!("Circuit Preallocation - v5a to v5c Converter");
    println!("=============================================");
    println!("Input:  {}", args.input.display());
    println!("Output: {}", args.output.display());
    println!();

    prealloc::prealloc(args.input.to_str().unwrap(), args.output.to_str().unwrap()).await;

    println!();
    println!("Conversion complete!");
    Ok(())
}

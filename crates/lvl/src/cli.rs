use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Circuit Level Organizer - Tools for circuit transformation
#[derive(Parser, Debug)]
#[command(name = "lvl")]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Preallocate wires and convert v5a to v5c flat format
    Prealloc(PreallocCommand),
}

#[derive(Parser, Debug)]
pub(crate) struct PreallocCommand {
    /// Input v5a CKT file path
    #[arg(value_name = "INPUT")]
    pub(crate) input: PathBuf,

    /// Output v5c CKT file path
    #[arg(value_name = "OUTPUT")]
    pub(crate) output: PathBuf,
}

impl Cli {
    /// Parse command line arguments
    pub(crate) fn parse_args() -> Self {
        Cli::parse()
    }
}

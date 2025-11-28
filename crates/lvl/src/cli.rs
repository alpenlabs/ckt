use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Circuit Level Organizer - Tools for circuit transformation
#[derive(Parser, Debug)]
#[command(name = "lvl")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Convert v5a circuits to v5b level-based format
    Level(LevelCommand),
    /// Preallocate wires and convert v5a to v5c flat format
    Prealloc(PreallocCommand),
}

#[derive(Parser, Debug)]
pub struct LevelCommand {
    /// Input v5a CKT file path
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output v5b CKT file path
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Target number of pending gates to keep in memory
    #[arg(
        short = 't',
        long = "target-pending",
        default_value_t = 10_000_000,
        value_name = "GATES",
        help = "Maximum gates to buffer in memory before forcing level creation"
    )]
    pub target_pending: usize,

    /// Interval for checking and refilling gate buffer
    #[arg(
        short = 'c',
        long = "check-interval",
        default_value_t = 10_000,
        value_name = "GATES",
        help = "Check buffer and refill every N gates processed"
    )]
    pub check_interval: usize,

    /// Batch size for loading gates when stalled
    #[arg(
        short = 's',
        long = "stuck-batch-size",
        default_value_t = 50_000,
        value_name = "GATES",
        help = "Number of gates to load when stalled"
    )]
    pub stuck_batch_size: usize,

    /// Verbose output
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,

    /// Memory limit in gigabytes
    #[arg(
        short = 'm',
        long = "memory-limit",
        default_value_t = 1000,
        value_name = "GB",
        help = "Maximum memory usage in gigabytes"
    )]
    pub memory_limit_gb: usize,
}

#[derive(Parser, Debug)]
pub struct PreallocCommand {
    /// Input v5a CKT file path
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output v5c CKT file path
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

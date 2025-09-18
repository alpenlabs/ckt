use clap::Parser;
use std::path::PathBuf;

/// Circuit Level Organizer - Converts v3a circuits to v3b level-based format
#[derive(Parser, Debug)]
#[command(name = "lvl")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Input v3a CKT file path
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output v3b CKT file path
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
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

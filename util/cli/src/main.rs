mod stream;
mod writer;

use ckt::GateType;
use ckt::v1::reader::CircuitReader as CircuitReaderV1;
use ckt::v1::writer::CircuitWriter as CircuitWriterV1;
use ckt::v1::{CompactGate, hp as hp_v1};
use ckt::v4::a::hp::reader::verify_checksum_async as verify_checksum_v4a;
use ckt::v4::b::hp::reader::verify_checksum_async as verify_checksum_v4b;
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use kanal::unbounded_async;
use monoio::FusionDriver;
use monoio::blocking::DefaultThreadPool;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use stream::BufferedLineStream;

use crate::writer::RemoteWriter;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(name = "ckt")]
#[command(about = "Circuit format converter and analyzer", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert Bristol format to CKT format
    Convert {
        /// Input Bristol format file
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Output CKT format file (defaults to input.ckt)
        #[arg(short, long, value_name = "OUTPUT")]
        output: Option<PathBuf>,

        /// Output format version (v1 or v4a)
        #[arg(short, long, default_value = "v4a", value_name = "VERSION")]
        version: String,

        /// Number of primary inputs (required for v4a format)
        #[arg(
            short = 'p',
            long,
            value_name = "COUNT",
            required_if_eq("version", "v4a")
        )]
        primary_inputs: Option<u64>,
    },

    /// Verify and analyze a circuit file
    Verify {
        /// Input file (Bristol or CKT format)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Version of CKT format to verify (3a or 3b)
        #[arg(short, long, value_name = "VERSION")]
        version: Option<String>,

        /// Show detailed statistics
        #[arg(short, long)]
        detailed: bool,
    },

    /// Get information about a circuit file
    Info {
        /// Input file (Bristol or CKT format)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Version of CKT format (v1 or v4a, for CKT files)
        #[arg(short, long, value_name = "VERSION")]
        version: Option<String>,
    },

    /// Compare two circuit files
    Compare {
        /// First circuit file
        #[arg(value_name = "FILE1")]
        file1: PathBuf,

        /// Second circuit file
        #[arg(value_name = "FILE2")]
        file2: PathBuf,
    },

    /// Extract CKT format back to Bristol format
    Extract {
        /// Input CKT file
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Output Bristol file (defaults to input.bristol)
        #[arg(short, long, value_name = "OUTPUT")]
        output: Option<PathBuf>,

        /// Version of CKT format (v1 or v4a)
        #[arg(short, long, default_value = "v1", value_name = "VERSION")]
        version: String,
    },

    /// Search for gates with specific inputs or outputs in a CKT file
    Search {
        /// Input CKT format file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Input wire IDs to search for (can specify multiple)
        #[arg(short, long, value_name = "INPUT", num_args = 1..)]
        inputs: Vec<u32>,

        /// Output wire IDs to search for (can specify multiple)
        #[arg(short, long, value_name = "OUTPUT", num_args = 1..)]
        outputs: Vec<u32>,

        /// Version of CKT format (v1 or v4a)
        #[arg(short, long, default_value = "v1", value_name = "VERSION")]
        version: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Create monoio runtime and run the async main
    monoio::RuntimeBuilder::<FusionDriver>::new()
        .attach_thread_pool(Box::new(DefaultThreadPool::new(
            std::thread::available_parallelism().unwrap().get(),
        )))
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Convert {
            input,
            output,
            version,
            primary_inputs,
        } => {
            let output = output.unwrap_or_else(|| {
                let mut path = input.clone();
                path.set_extension("ckt");
                path
            });

            match version.as_str() {
                "v1" => convert_bristol_to_ckt_v1(&input, &output).await?,

                _ => {
                    return Err(
                        format!("Unsupported version: {}. Use 'v1' or 'v4a'", version).into(),
                    );
                }
            }
        }

        Commands::Verify {
            file,
            version,
            detailed,
        } => {
            if file.extension().and_then(|s| s.to_str()) == Some("ckt") {
                let version = version.ok_or("Version is required for CKT files")?;
                match version.as_str() {
                    "4a" | "v4a" => {
                        verify_ckt_file_v4(&file, "4a").await?;
                    }
                    "4b" | "v4b" => {
                        verify_ckt_file_v4(&file, "4b").await?;
                    }
                    _ => {
                        return Err(
                            format!("Unsupported version: {}. Use '4a' or '4b'", version).into(),
                        );
                    }
                }
            } else {
                let stats = verify_bristol_file(&file).await?;
                stats.print_summary();
                if detailed {
                    stats.print_detailed();
                }
            }
        }

        Commands::Info { file, version } => {
            print_file_info(&file, version)?;
        }

        Commands::Compare { file1, file2 } => {
            // Try to auto-detect versions for comparison
            compare_circuits(&file1, &file2).await?;
        }

        Commands::Extract {
            input,
            output,
            version,
        } => {
            let output = output.unwrap_or_else(|| {
                let mut path = input.clone();
                path.set_extension("bristol");
                path
            });

            match version.as_str() {
                "v1" => extract_ckt_to_bristol_v1(&input, &output)?,

                _ => {
                    return Err(
                        format!("Unsupported version: {}. Use 'v1' or 'v4a'", version).into(),
                    );
                }
            }
        }

        Commands::Search {
            file,
            inputs,
            outputs,
            version,
        } => match version.as_str() {
            "v1" => search_ckt_file_v1(&file, &inputs, &outputs).await?,

            _ => {
                return Err(format!("Unsupported version: {}. Use 'v1' or 'v4a'", version).into());
            }
        },
    }

    Ok(())
}

/// Format a number with underscores for readability
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push('_');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Parse a Bristol format gate line
fn parse_bristol_gate_line(line: &str) -> Result<(GateType, CompactGate)> {
    let mut tokens = line.split_whitespace();
    let count = tokens.by_ref().count();
    if count != 6 {
        return Err(format!(
            "Invalid Bristol gate line: expected 6 tokens, got {}: '{}'",
            count, line
        )
        .into());
    };
    let mut gate = CompactGate::default();
    let mut gate_type = GateType::AND;
    for (i, token) in line.split_whitespace().enumerate() {
        match i {
            2 => {
                gate.input1 = token
                    .parse()
                    .map_err(|_| format!("Invalid input1 wire ID: '{}'", token))?
            }
            3 => {
                gate.input2 = token
                    .parse()
                    .map_err(|_| format!("Invalid input2 wire ID: '{}'", token))?
            }
            4 => {
                gate.output = token
                    .parse()
                    .map_err(|_| format!("Invalid output wire ID: '{}'", token))?
            }
            5 => {
                gate_type = match token {
                    "XOR" => GateType::XOR,
                    "AND" => GateType::AND,
                    _ => {
                        return Err(format!(
                            "Unsupported gate type: '{}'. Only XOR and AND are supported.",
                            token
                        )
                        .into());
                    }
                };
            }
            _ => {}
        }
    }

    Ok((gate_type, gate))
}

/// Convert Bristol format to CKT format with parallel parsing
async fn convert_bristol_to_ckt_v1(bristol_path: &Path, ckt_path: &Path) -> Result<()> {
    println!(
        "Converting {} -> {}",
        bristol_path.display(),
        ckt_path.display()
    );

    let (bristol_tx, bristol_rx) = unbounded_async();
    let (writer_tx, writer_rx) = unbounded_async();

    let bristol_path_clone = bristol_path.to_owned();
    let reader_task = monoio::spawn(async move {
        const CHUNK_SIZE: usize = 1_000_000; // Lines per chunk
        let bristol_file = monoio::fs::File::open(bristol_path_clone)
            .await
            .map_err(|e| format!("Failed to open file: {}", e))?;
        let mut bristol_stream = BufferedLineStream::new(bristol_file);
        let mut chunk = Vec::with_capacity(CHUNK_SIZE);

        while let Some(line_result) = bristol_stream.next_line().await {
            let line = line_result.map_err(|e| format!("Failed to read line: {}", e))?;
            if !line.trim().is_empty() {
                chunk.push(line.to_string());
            }

            if chunk.len() >= CHUNK_SIZE {
                // Parse chunk in parallel
                let parsed_gates: Vec<_> = chunk
                    .par_iter()
                    .map(|line| parse_bristol_gate_line(line).unwrap())
                    .collect();

                bristol_tx
                    .send(parsed_gates)
                    .await
                    .map_err(|e| format!("Channel send error: {}", e))?;
                chunk.clear();
            }
        }

        // Send remaining gates
        if !chunk.is_empty() {
            let parsed_gates: Vec<_> = chunk
                .par_iter()
                .map(|line| parse_bristol_gate_line(line).unwrap())
                .collect();

            bristol_tx
                .send(parsed_gates)
                .await
                .map_err(|e| format!("Channel send error: {}", e))?;
        }

        Ok::<(), String>(())
    });
    let bristol_path_clone = bristol_path.to_owned();
    let ckt_path_clone = ckt_path.to_owned();
    let encoder_thread = monoio::spawn_blocking(move || {
        let writer = RemoteWriter::new(writer_tx.to_sync(), 0);
        let mut writer = CircuitWriterV1::new(writer)
            .map_err(|e| format!("Create circuit writer error: {}", e))?;
        let mut stats = ConversionStats::new();
        let start_time = Instant::now();
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        pb.set_message("Converting Bristol to CKT format...");
        for gates in bristol_rx.to_sync() {
            for (gate_type, gate) in gates {
                writer
                    .write_gate(gate, gate_type)
                    .map_err(|e| format!("Write gate error: {}", e))?;

                match gate_type {
                    GateType::AND => stats.and_gates += 1,
                    GateType::XOR => stats.xor_gates += 1,
                }
                stats.total_gates += 1;

                if stats.total_gates % 1_000_000 == 0 {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let rate = if elapsed > 0.0 {
                        format!(
                            "{}/s",
                            format_number((stats.total_gates as f64 / elapsed) as usize)
                        )
                    } else {
                        "calculating...".to_string()
                    };
                    pb.set_message(format!(
                        "Converted {} gates ({} XOR, {} AND) [{}]",
                        format_number(stats.total_gates),
                        format_number(stats.xor_gates),
                        format_number(stats.and_gates),
                        rate
                    ));
                }
            }
        }
        let (_file, gates_written) = writer
            .finish()
            .map_err(|e| format!("Failed to finish writing: {}", e))?;

        let elapsed = start_time.elapsed();
        pb.finish_with_message(format!(
            "✓ Converted {} gates in {:.2?}",
            format_number(gates_written),
            elapsed
        ));

        // Calculate file sizes
        stats.bristol_file_size = std::fs::metadata(bristol_path_clone).unwrap().len();
        stats.binary_file_size = std::fs::metadata(ckt_path_clone).unwrap().len();
        stats.compression_ratio = stats.bristol_file_size as f64 / stats.binary_file_size as f64;
        Ok::<ConversionStats, String>(stats)
    });
    let ckt_path_clone = ckt_path.to_owned();
    let writer_task = monoio::spawn(async move {
        let output_file = monoio::fs::File::create(ckt_path_clone)
            .await
            .map_err(|e| format!("Failed to create file: {}", e))?;
        while let Ok((pos, data)) = writer_rx.recv().await {
            output_file
                .write_all_at(data, pos)
                .await
                .0
                .map_err(|e| format!("Failed to write at position {}: {}", pos, e))?;
        }
        Ok::<(), String>(())
    });

    reader_task.await?;
    writer_task.await?;
    let stats = encoder_thread.await.unwrap()?;
    stats.print_summary();

    Ok(())
}

/// Verify a CKT format file
async fn verify_ckt_file_v4(path: &Path, version: &str) -> Result<()> {
    println!("Verifying CKT v{} file: {}", version, path.display());

    let start_time = Instant::now();
    let file = monoio::fs::File::open(path).await?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.set_message(format!("Verifying checksum for v{} format...", version));

    let checksum_result = match version {
        "4a" => verify_checksum_v4a(file)
            .await
            .map_err(|e| format!("Failed to verify v4a checksum: {}", e)),
        "4b" => verify_checksum_v4b(file)
            .await
            .map_err(|e| format!("Failed to verify v4b checksum: {}", e)),
        _ => return Err(format!("Unsupported version: {}", version).into()),
    };

    let elapsed = start_time.elapsed();

    match checksum_result {
        Ok(checksum) => {
            pb.finish_with_message(format!("✓ Checksum verification PASSED in {:.2?}", elapsed));
            println!("\n✅ File integrity verified successfully!");

            // Display checksum in hex format
            let checksum_hex = checksum
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            println!("BLAKE3 checksum: {}", checksum_hex);
        }
        Err(e) => {
            pb.finish_with_message(format!("✗ Checksum verification FAILED in {:.2?}", elapsed));
            println!("\n❌ File integrity check failed!");
            return Err(e.into());
        }
    }

    // Get file size for additional info
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("Error getting file metadata: {}", e))?
        .len();

    println!("File size: {} bytes", format_number(file_size as usize));

    Ok(())
}

/// Verify a CKT v1 format file (legacy function, kept for compatibility)
async fn verify_ckt_file_v1(path: &Path) -> Result<VerificationStats> {
    let file = monoio::fs::File::open(path).await?;
    let mut reader = hp_v1::reader::CircuitReader::new(file, 1_000_000)
        .await
        .map_err(|e| format!("Failed to create CircuitReader: {}", e))?;

    // Get gate counts from reader
    let total_gates = reader.total_gates();
    let xor_gates = reader.xor_gates();
    let and_gates = reader.and_gates();

    let pb = ProgressBar::new(total_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/blue} {pos:>7}/{len:7} [{elapsed_precise}] {msg} [{per_sec}]")
            .unwrap(),
    );
    pb.set_message("Verifying CKT circuit...");

    let start_time = Instant::now();
    let mut stats = VerificationStats::new();
    stats.xor_gates = xor_gates as usize;
    stats.and_gates = and_gates as usize;
    stats.total_gates = total_gates as usize;

    let mut recorded_xors = 0;
    let mut recorded_ands = 0;

    // Read through to verify file integrity
    let mut verified_count = 0;
    while let Some((batch, count)) = reader
        .next_batch()
        .await
        .map_err(|e| format!("Error reading gate: {}", e))?
    {
        for i in 0..count {
            match batch.gate_type(i) {
                GateType::XOR => recorded_xors += 1,
                GateType::AND => recorded_ands += 1,
            }
        }
        verified_count += count;
        if verified_count % 10_000_000 == 0 {
            pb.set_position(verified_count as u64);
        }
    }

    assert_eq!(recorded_ands, and_gates);
    assert_eq!(recorded_xors, xor_gates);

    pb.finish_with_message(format!(
        "✓ Verified {} gates",
        format_number(stats.total_gates)
    ));

    stats.file_size = std::fs::metadata(path)
        .map_err(|e| format!("Error getting file metadata: {}", e))?
        .len();
    stats.processing_time = start_time.elapsed();
    Ok(stats)
}

/// Verify a Bristol format file
async fn verify_bristol_file(path: &Path) -> Result<VerificationStats> {
    let file = monoio::fs::File::open(path).await?;
    let mut stream = BufferedLineStream::new(file);

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner().template("{spinner:.green} [{elapsed_precise}] {msg}")?,
    );
    pb.set_message("Verifying Bristol circuit...");

    let start_time = Instant::now();
    let mut stats = VerificationStats::new();

    while let Some(line_result) = stream.next_line().await {
        let line = line_result?;

        if line.trim().is_empty() {
            continue;
        }

        let (gate_type, _) = parse_bristol_gate_line(line)?;

        match gate_type {
            GateType::AND => stats.and_gates += 1,
            GateType::XOR => stats.xor_gates += 1,
        }
        stats.total_gates += 1;

        if stats.total_gates % 1_000_000 == 0 {
            pb.set_message(format!(
                "Verified {} gates ({} XOR, {} AND)",
                format_number(stats.total_gates),
                format_number(stats.xor_gates),
                format_number(stats.and_gates)
            ));
        }
    }

    pb.finish_with_message(format!(
        "✓ Verified {} gates",
        format_number(stats.total_gates)
    ));

    stats.file_size = std::fs::metadata(path)?.len();
    stats.processing_time = start_time.elapsed();

    Ok(stats)
}

/// Print information about a file
fn print_file_info(path: &Path, version: Option<String>) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    println!("File: {}", path.display());
    println!(
        "Size: {:.2} MB ({} bytes)",
        file_size as f64 / 1_048_576.0,
        format_number(file_size as usize)
    );

    if path.extension().and_then(|s| s.to_str()) == Some("ckt") {
        // Try to detect version or use provided one
        let detected_version = version.unwrap_or_else(|| "v1".to_string());

        match detected_version.as_str() {
            "v1" => {
                let file = File::open(path)?;
                let len = file.metadata()?.len() as usize;
                let buf_reader = BufReader::new(file);

                match CircuitReaderV1::new(buf_reader, len) {
                    Ok(reader) => {
                        let gate_count = reader.total_gates();
                        println!("Format: CKT v1 (compressed binary)");
                        println!("Gates: {}", format_number(gate_count as usize));
                        println!(
                            "Bytes per gate: {:.2}",
                            file_size as f64 / gate_count as f64
                        );
                    }
                    Err(_) => {
                        println!("Format: CKT v1 (compressed binary)");
                        println!("Gates: Unable to read header");
                    }
                }
            }

            _ => {
                println!("Format: CKT (version unknown)");
                println!("Specify version with -v flag");
            }
        }
    } else {
        println!("Format: Bristol (text)");
        println!("Use 'ckt verify' for detailed gate count");
    }

    Ok(())
}

/// Compare two circuit files
async fn compare_circuits(path1: &Path, path2: &Path) -> Result<()> {
    println!("Comparing circuits...\n");
    println!("Note: Assuming v1 format for CKT files. Use verify command for v4 formats.\n");

    let stats1 = if path1.extension().and_then(|s| s.to_str()) == Some("ckt") {
        verify_ckt_file_v1(path1).await?
    } else {
        verify_bristol_file(path1).await?
    };

    let stats2 = if path2.extension().and_then(|s| s.to_str()) == Some("ckt") {
        verify_ckt_file_v1(path2).await?
    } else {
        verify_bristol_file(path2).await?
    };

    println!("File 1: {}", path1.display());
    println!("  Gates: {}", format_number(stats1.total_gates));
    println!(
        "  XOR: {} ({:.1}%)",
        format_number(stats1.xor_gates),
        (stats1.xor_gates as f64 / stats1.total_gates as f64) * 100.0
    );
    println!(
        "  AND: {} ({:.1}%)",
        format_number(stats1.and_gates),
        (stats1.and_gates as f64 / stats1.total_gates as f64) * 100.0
    );
    println!("  Size: {:.2} MB", stats1.file_size as f64 / 1_048_576.0);

    println!("\nFile 2: {}", path2.display());
    println!("  Gates: {}", format_number(stats2.total_gates));
    println!(
        "  XOR: {} ({:.1}%)",
        format_number(stats2.xor_gates),
        (stats2.xor_gates as f64 / stats2.total_gates as f64) * 100.0
    );
    println!(
        "  AND: {} ({:.1}%)",
        format_number(stats2.and_gates),
        (stats2.and_gates as f64 / stats2.total_gates as f64) * 100.0
    );
    println!("  Size: {:.2} MB", stats2.file_size as f64 / 1_048_576.0);

    println!("\nDifferences:");
    if stats1.total_gates == stats2.total_gates {
        println!("  ✓ Same number of gates");
    } else {
        let diff = (stats1.total_gates as i64 - stats2.total_gates as i64).abs();
        println!("  ✗ Gate count differs by {}", format_number(diff as usize));
    }

    if stats1.xor_gates == stats2.xor_gates && stats1.and_gates == stats2.and_gates {
        println!("  ✓ Same gate type distribution");
    } else {
        println!("  ✗ Different gate type distribution");
    }

    let size_ratio = stats1.file_size as f64 / stats2.file_size as f64;
    if size_ratio > 1.0 {
        println!("  File 1 is {size_ratio:.2}x larger");
    } else {
        println!("  File 2 is {:.2}x larger", 1.0 / size_ratio);
    }

    Ok(())
}

/// Extract CKT v1 format back to Bristol format
fn extract_ckt_to_bristol_v1(ckt_path: &Path, bristol_path: &Path) -> Result<()> {
    println!(
        "Extracting {} -> {}",
        ckt_path.display(),
        bristol_path.display()
    );

    let input_file = File::open(ckt_path)?;
    let len = input_file.metadata()?.len() as usize;
    let buf_reader = BufReader::new(input_file);
    let mut reader = CircuitReaderV1::new(buf_reader, len)?;

    // Get gate count from reader
    let gate_count = reader.total_gates();

    let output_file = File::create(bristol_path)?;
    let mut writer = BufWriter::new(output_file);

    let pb = ProgressBar::new(gate_count as u64);
    pb.set_style(
        ProgressStyle::default_bar().template(
            "{bar:40.cyan/blue} {pos:>7}/{len:7} [{elapsed_precise}] {msg} [{per_sec}]",
        )?,
    );
    pb.set_message("Extracting to Bristol format...");

    let start_time = Instant::now();
    let mut count = 0;

    while let Some((batch, num_gates)) = reader.next_batch()? {
        for i in 0..num_gates {
            let (gate, gate_type) = batch.get_gate(i);
            let gate_str = match gate_type {
                GateType::XOR => "XOR",
                GateType::AND => "AND",
            };

            writeln!(
                writer,
                "2 1 {} {} {} {}",
                gate.input1, gate.input2, gate.output, gate_str
            )?;

            count += 1;
            if count % 1_000_000 == 0 {
                pb.set_position(count as u64);
            }
        }
    }

    writer.flush()?;
    pb.finish_with_message(format!(
        "✓ Extracted {} gates in {:.2?}",
        format_number(count),
        start_time.elapsed()
    ));

    Ok(())
}

/// Search for gates with specific inputs or outputs in a CKT v1 file
async fn search_ckt_file_v1(file: &Path, inputs: &[u32], outputs: &[u32]) -> Result<()> {
    if inputs.is_empty() && outputs.is_empty() {
        eprintln!("Error: Must specify at least one input (-i) or output (-o) to search for");
        std::process::exit(1);
    }

    println!("🔍 Searching CKT file: {}", file.display());
    println!("   Looking for:");
    if !inputs.is_empty() {
        println!("   - Inputs: {:?}", inputs);
    }
    if !outputs.is_empty() {
        println!("   - Outputs: {:?}", outputs);
    }
    println!();

    let start = std::time::Instant::now();

    // Open file with high performance reader
    let file = monoio::fs::File::open(file).await?;
    let mut reader = hp_v1::reader::CircuitReader::new(file, 1_000_000).await?;

    println!("📊 Circuit Info:");
    println!(
        "   Total gates: {}",
        format_number(reader.total_gates() as usize)
    );
    println!(
        "   XOR gates: {}",
        format_number(reader.xor_gates() as usize)
    );
    println!(
        "   AND gates: {}",
        format_number(reader.and_gates() as usize)
    );
    println!();

    let mut gate_index = 0u64;
    let mut matches_found = 0u64;

    println!("🔎 Searching for matches...\n");

    // Process all gate batches
    while let Some((batch, gates_in_batch)) = reader.next_batch().await? {
        for i in 0..gates_in_batch {
            let (gate, gate_type) = batch.get_gate(i);

            let mut is_match = false;
            let mut match_reason = Vec::new();

            // Check if any of the inputs match
            for &input in inputs {
                if gate.input1 == input {
                    is_match = true;
                    match_reason.push(format!("input1={}", input));
                }
                if gate.input2 == input {
                    is_match = true;
                    match_reason.push(format!("input2={}", input));
                }
            }

            // Check if the output matches
            for &output in outputs {
                if gate.output == output {
                    is_match = true;
                    match_reason.push(format!("output={}", output));
                }
            }

            if is_match {
                matches_found += 1;
                println!("✓ Match #{} at gate index {}", matches_found, gate_index);
                println!("  Type: {:?}", gate_type);
                println!(
                    "  Gate: ({}, {}) -> {}",
                    gate.input1, gate.input2, gate.output
                );
                println!("  Matched: {}", match_reason.join(", "));
                println!();
            }

            gate_index += 1;
        }
    }

    let elapsed = start.elapsed();

    println!("📈 Search Complete:");
    println!("   Gates examined: {}", format_number(gate_index as usize));
    println!(
        "   Matches found: {}",
        format_number(matches_found as usize)
    );
    println!("   Time: {:.2?}", elapsed);

    if matches_found == 0 {
        println!("\n⚠️  No matching gates found");
    }

    Ok(())
}

#[derive(Debug)]
struct VerificationStats {
    total_gates: usize,
    xor_gates: usize,
    and_gates: usize,
    file_size: u64,
    processing_time: std::time::Duration,
}

impl VerificationStats {
    fn new() -> Self {
        Self {
            total_gates: 0,
            xor_gates: 0,
            and_gates: 0,
            file_size: 0,
            processing_time: std::time::Duration::default(),
        }
    }

    fn print_summary(&self) {
        println!("\nVerification Summary:");
        println!("  Total gates: {}", format_number(self.total_gates));
        println!(
            "  XOR gates: {} ({:.1}%)",
            format_number(self.xor_gates),
            (self.xor_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  AND gates: {} ({:.1}%)",
            format_number(self.and_gates),
            (self.and_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!("  File size: {:.2} MB", self.file_size as f64 / 1_048_576.0);
        println!(
            "  Bytes per gate: {:.2}",
            self.file_size as f64 / self.total_gates as f64
        );
        println!("  Processing time: {:.2?}", self.processing_time);

        let rate = self.total_gates as f64 / self.processing_time.as_secs_f64();
        println!(
            "  Processing rate: {} gates/sec",
            format_number(rate as usize)
        );
    }

    fn print_detailed(&self) {
        println!("\nDetailed Statistics:");
        println!(
            "  File size: {} bytes",
            format_number(self.file_size as usize)
        );

        if self.total_gates > 0 {
            let xor_ratio = self.xor_gates as f64 / self.total_gates as f64;
            let entropy = if xor_ratio > 0.0 && xor_ratio < 1.0 {
                -xor_ratio * xor_ratio.log2() - (1.0 - xor_ratio) * (1.0 - xor_ratio).log2()
            } else {
                0.0
            };
            println!("  Gate type entropy: {entropy:.3} bits");
        }
    }
}

/// Statistics from conversion
#[derive(Debug)]
struct ConversionStats {
    total_gates: usize,
    xor_gates: usize,
    and_gates: usize,
    bristol_file_size: u64,
    binary_file_size: u64,
    compression_ratio: f64,
}

impl ConversionStats {
    fn new() -> Self {
        Self {
            total_gates: 0,
            xor_gates: 0,
            and_gates: 0,
            bristol_file_size: 0,
            binary_file_size: 0,
            compression_ratio: 0.0,
        }
    }

    fn print_summary(&self) {
        println!("\nConversion Summary:");
        println!("  Total gates: {}", format_number(self.total_gates));
        println!(
            "  XOR gates: {} ({:.1}%)",
            format_number(self.xor_gates),
            (self.xor_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  AND gates: {} ({:.1}%)",
            format_number(self.and_gates),
            (self.and_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  Bristol file size: {:.2} GB",
            self.bristol_file_size as f64 / 1_000_000_000.0
        );
        println!(
            "  Binary file size: {:.2} GB",
            self.binary_file_size as f64 / 1_000_000_000.0
        );
        println!("  Compression ratio: {:.2}x", self.compression_ratio);
        println!(
            "  Space saved: {:.1}%",
            (1.0 - 1.0 / self.compression_ratio) * 100.0
        );
    }
}

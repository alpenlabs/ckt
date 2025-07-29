# CKT - Compressed Circuit Format

A high-performance binary format for storing and processing Boolean circuits, with 5-10x compression
and 10x+ faster parsing compared to the text-based Bristol format. This is a preliminary
implementation and will get faster with future iteration.

## Overview

CKT provides:
- **Efficient binary format** with zstd compression
- **Streaming API** for processing huge circuits with minimal memory
- **Generic Read/Write traits** for flexible I/O (files, memory, network)
- **Full-featured CLI** for format conversion and analysis
- **Bristol format compatibility** with bidirectional conversion

## Installation

### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
ckt = "0.1.0"
```

### CLI

```bash
cargo install --path cli
```

## Quick Start

### CLI Usage

```bash
# Convert Bristol to CKT format
ckt convert circuit.bristol -o circuit.ckt

# Verify and analyze circuits
ckt verify circuit.ckt --detailed

# Compare two circuits
ckt compare circuit1.bristol circuit2.ckt

# Extract CKT back to Bristol
ckt extract circuit.ckt -o circuit.bristol

# Get quick file information
ckt info circuit.ckt
```

### Library Usage

```rust
use ckt::{CircuitWriter, CircuitReader, GateType};
use std::fs::File;
use std::io::{BufReader, BufWriter};

// Writing circuits
let file = File::create("circuit.ckt")?;
let mut writer = CircuitWriter::new(BufWriter::new(file));

writer.write_header(1000)?; // Total number of gates
writer.write_gate(0, 1, 2, GateType::XOR)?;
writer.write_gate(2, 3, 4, GateType::AND)?;
// ... write more gates ...

let (output, gates_written) = writer.finish_without_header()?;

// Reading circuits
let file = File::open("circuit.ckt")?;
let mut reader = CircuitReader::new(BufReader::new(file));

reader.read_header()?;
let total_gates = reader.total_gates_expected();

while let Some((gate, gate_type)) = reader.next_gate()? {
    println!("Gate: {} {} -> {}", gate.input1, gate.input2, gate.output);
}
```

## Format Specification

### CKT Binary Format

The CKT format consists of:

1. **Header** (8 bytes, uncompressed)
   - xor_gate_count as little-endian u32
   - and_gate_count as little-endian u32

2. **Compressed gate data** (zstd compressed)
   - Gates are packed in batches of 8
   - Each batch is exactly 97 bytes:
     - 8 gates × 12 bytes per gate = 96 bytes
     - 1 byte for gate types (bit-packed)

### Gate Structure

Each gate is 12 bytes:
- `input1`: 4 bytes (little-endian u32)
- `input2`: 4 bytes (little-endian u32)
- `output`: 4 bytes (little-endian u32)

Gate types are bit-packed:
- Bit 0 = gate 0 type (0=XOR, 1=AND)
- Bit 1 = gate 1 type
- ... and so on

## Architecture

The library is designed with flexibility in mind:

```rust
// Works with any Read/Write implementation
impl<W: Write> CircuitWriter<W> { ... }
impl<R: Read> CircuitReader<R> { ... }
```

This allows usage with:
- Files (`File`, `BufReader`, `BufWriter`)
- Memory (`Vec<u8>`, `Cursor`)
- Network streams
- Custom implementations

## Bristol Format Support

The CLI seamlessly handles Bristol format files:

```
2 1 0 1 2 XOR
2 1 3 4 5 AND
2 1 6 7 8 XOR
```

Where each line represents: `num_inputs num_outputs input1 input2 output GATE_TYPE`

Currently supports:
- ✅ 2-input, 1-output gates
- ✅ XOR gates
- ✅ AND gates
- ❌ Other gate types (OR, NOT, etc.)

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run library tests only
cargo test --lib

# Run CLI integration tests
cargo test -p ckt-cli
```

### Project Structure

```
ckt/
├── src/
│   └── lib.rs          # Core library implementation
├── cli/
│   ├── src/
│   │   ├── main.rs     # CLI implementation
│   │   └── stream.rs   # Streaming Bristol parser
│   └── tests/
│       └── integration_tests.rs
├── Cargo.toml          # Workspace configuration
└── README.md
```

## License

MIT or Apache 2.0

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

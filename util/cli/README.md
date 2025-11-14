# CKT CLI - Circuit Format Converter and Analyzer

A command-line tool for converting between Bristol and CKT (compressed binary) circuit formats, with verification and analysis capabilities.

## Installation

From the workspace root:

```bash
cargo install --path cli
```

Or build directly:

```bash
cargo build --release -p ckt-cli
```

## Usage

```bash
ckt [COMMAND]
```

### Commands

#### Convert Bristol to CKT Format

Convert a Bristol format circuit file to the compressed CKT binary format:

```bash
ckt convert input.bristol -o output.ckt
```

Options:
- `-o, --output <OUTPUT>`: Output file path (defaults to input.ckt)
- `-l, --compression-level <LEVEL>`: Compression level 0-22 (default: 3)

#### Verify Circuit Files

Verify and analyze circuit files (supports both Bristol and CKT formats):

```bash
ckt verify circuit.ckt
ckt verify circuit.bristol --detailed
```

Options:
- `-d, --detailed`: Show detailed statistics including entropy calculations

#### Get File Information

Quick information about a circuit file without full verification:

```bash
ckt info circuit.ckt
```

#### Compare Two Circuits

Compare two circuit files to check if they represent the same circuit:

```bash
ckt compare circuit1.bristol circuit2.ckt
```

#### Extract CKT to Bristol

Convert a CKT file back to Bristol format:

```bash
ckt extract circuit.ckt -o circuit.bristol
```

Options:
- `-o, --output <OUTPUT>`: Output file path (defaults to input.bristol)

## File Formats

### Bristol Format
- Text-based format
- One gate per line: `2 1 input1 input2 output GATE_TYPE`
- Supports XOR and AND gates
- Human-readable but space-inefficient

### CKT Format
- Binary format with zstd compression
- 4-byte header with total gate count
- Gates packed in batches of 8 (97 bytes per batch)
- ~5-10x smaller than Bristol format
- Much faster to parse

## Performance

The CKT format provides significant performance improvements:

- **Space**: 5-10x compression ratio compared to Bristol format
- **Speed**: 10-100x faster parsing than Bristol format
- **Memory**: Streaming support for processing large circuits

## Examples

### Convert a large circuit
```bash
# Convert with progress bar
ckt convert large_circuit.bristol

# Output:
# Converting large_circuit.bristol -> large_circuit.ckt
# ✓ Converted 1,234,567,890 gates in 45.23s
```

### Verify and compare formats
```bash
# Verify Bristol file
ckt verify circuit.bristol

# Verify CKT file (much faster)
ckt verify circuit.ckt

# Compare to ensure conversion was correct
ckt compare circuit.bristol circuit.ckt
```

### Check file sizes
```bash
ckt info circuit.bristol
# File: circuit.bristol
# Size: 45678.90 MB (45,678,901,234 bytes)
# Format: Bristol (text)

ckt info circuit.ckt
# File: circuit.ckt
# Size: 4567.89 MB (4,567,890,123 bytes)
# Format: CKT (compressed binary)
# Gates: 123,456,789
# Bytes per gate: 37.00
```

## Implementation Details

The CLI uses:
- **Streaming parsers** for memory-efficient processing of large files
- **Progress bars** with throughput indicators
- **Buffered I/O** with large buffers (256MB) for optimal performance
- **Zero-copy parsing** where possible
- **zstd compression** for excellent compression ratios

## Error Handling

The CLI provides clear error messages for common issues:
- Invalid gate formats
- Unsupported gate types (only XOR and AND)
- File I/O errors
- Corrupted binary formats

## License

Same as the parent ckt crate.
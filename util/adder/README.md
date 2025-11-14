# Adder Circuit Generator

A utility for generating n-bit ripple-carry adder circuits in CKT v5a format. This tool is designed for testing and validation of CKT tooling.

## Overview

The adder generator creates binary addition circuits that can be used to verify:
- Circuit file format correctness
- Reader/writer implementations
- Circuit evaluation logic
- Format conversion tools
- Performance benchmarking

## Circuit Design

### Ripple-Carry Adder

The generator produces a ripple-carry adder using the following full adder design:

```
For each bit position i:
  half_sum = A[i] XOR B[i]
  sum[i] = half_sum XOR carry[i]
  half_carry = A[i] AND B[i]
  carry_prop = half_sum AND carry[i]
  carry[i+1] = half_carry XOR carry_prop
```

Each full adder uses **5 gates** (3 XOR, 2 AND), so an n-bit adder has **5n gates** total.

### Wire Numbering

Following CKT v5a conventions:

- **Wire 0**: Boolean false constant
- **Wire 1**: Boolean true constant
- **Wires 2..(2+n)**: First operand A[0..n-1]
- **Wires (2+n)..(2+2n)**: Second operand B[0..n-1]
- **Wires (2+2n)..**: Gate outputs

### Inputs and Outputs

- **Primary Inputs**: 2n wires (n bits for A, n bits for B)
- **Outputs**: n+1 wires (n sum bits + 1 carry-out bit)

## Building

```bash
cargo build --release -p adder
```

## Usage

### Command Line

```bash
# Generate an 8-bit adder
cargo run --release -p adder -- 8

# Generate a 32-bit adder with custom output path
cargo run --release -p adder -- 32 my_adder.ckt

# Generate a 256-bit adder for large-scale testing
cargo run --release -p adder -- 256
```

### As a Library

```rust
use adder::generate_adder;

// Generate an 8-bit adder
let circuit = generate_adder(8);

// Access circuit properties
println!("Primary inputs: {}", circuit.primary_inputs); // 16
println!("Outputs: {}", circuit.outputs.len());         // 9 (8 sum + 1 carry)
println!("Total gates: {}", circuit.num_gates());       // 40 (5 * 8)
println!("XOR gates: {}", circuit.num_xor_gates());     // 16
println!("AND gates: {}", circuit.num_and_gates());     // 24

// Validate circuit structure
circuit.validate().unwrap();

// Write to v5a format
use ckt::v5::a::writer::CircuitWriterV5a;

let mut writer = CircuitWriterV5a::new(
    "adder_8bit.ckt",
    circuit.primary_inputs,
    circuit.outputs.clone(),
)
.await?;

writer.write_gates(&circuit.gates).await?;
let stats = writer.finalize().await?;
```

## Examples

### 1-bit Adder (Half Adder)

```
Inputs:  A[0] (wire 2), B[0] (wire 3)
Outputs: Sum[0], Carry
Gates:   5 gates (3 XOR, 2 AND)
```

### 8-bit Adder

```
Inputs:  A[0..7] (wires 2..9), B[0..7] (wires 10..17)
Outputs: Sum[0..7] + Carry (9 outputs)
Gates:   40 gates (24 XOR, 16 AND)
File:    ~640 bytes (v5a format)
```

### 32-bit Adder

```
Inputs:  A[0..31] (wires 2..33), B[0..31] (wires 34..65)
Outputs: Sum[0..31] + Carry (33 outputs)
Gates:   160 gates (96 XOR, 64 AND)
File:    ~2.5 KB (v5a format)
```

### 256-bit Adder

```
Inputs:  512 primary inputs
Outputs: 257 outputs
Gates:   1,280 gates (768 XOR, 512 AND)
File:    ~20 KB (v5a format)
```

## Testing Circuit Correctness

To verify the adder works correctly, you can:

1. **Generate a small circuit**:
   ```bash
   cargo run -p adder -- 4
   ```

2. **Read and validate the file**:
   ```bash
   # Use CKT reader tools to verify format
   cargo run -p ckt -- verify adder_4bit.ckt
   ```

3. **Evaluate with test inputs**:
   - A = 0b0011 (3), B = 0b0101 (5)
   - Expected: Sum = 0b1000 (8), Carry = 0
   
   - A = 0b1111 (15), B = 0b0001 (1)
   - Expected: Sum = 0b0000 (0), Carry = 1

## Use Cases

### Format Validation
Generate circuits of various sizes to test reader implementations:
```bash
for bits in 1 8 16 32 64 128 256; do
    cargo run -p adder -- $bits adder_${bits}bit.ckt
done
```

### Performance Benchmarking
Use large adders to benchmark I/O and processing:
```bash
# 1K-bit adder = 5,000 gates
cargo run --release -p adder -- 1000

# 10K-bit adder = 50,000 gates
cargo run --release -p adder -- 10000

# 100K-bit adder = 500,000 gates
cargo run --release -p adder -- 100000
```

### Correctness Testing
Use adders to verify circuit evaluation engines produce correct results.

## Circuit Properties

| n (bits) | Primary Inputs | Outputs | Total Gates | XOR Gates | AND Gates | File Size (v5a) |
|----------|----------------|---------|-------------|-----------|-----------|-----------------|
| 1        | 2              | 2       | 5           | 3         | 2         | ~320 B          |
| 8        | 16             | 9       | 40          | 24        | 16        | ~640 B          |
| 16       | 32             | 17      | 80          | 48        | 32        | ~1.3 KB         |
| 32       | 64             | 33      | 160         | 96        | 64        | ~2.5 KB         |
| 64       | 128            | 65      | 320         | 192       | 128       | ~5 KB           |
| 256      | 512            | 257     | 1,280       | 768       | 512       | ~20 KB          |
| 1,024    | 2,048          | 1,025   | 5,120       | 3,072     | 2,048     | ~81 KB          |

## Implementation Details

### Credits Assignment

The generator automatically assigns credits to all wires:
- **Circuit outputs**: Credit = 0 (CREDITS_OUTPUT)
- **Intermediate wires**: Credit = number of times wire is used as input
- **Constants/Primary inputs**: Credit = 16,777,215 (CREDITS_CONSTANT)

### Gate Ordering

Gates are generated in topological order, ensuring all inputs are defined before use.

### Validation

The `AdderCircuit::validate()` method checks:
- All wire IDs are within the valid range (< 2^34)
- All credits are within the valid range (< 2^24)
- Circuit structure is sound

## License

MIT OR Apache-2.0 (same as parent project)
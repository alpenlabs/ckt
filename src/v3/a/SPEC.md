# CKT Format v3a Specification

## Overview

Version 3a (v3a) is an intermediate storage format designed for unoptimized Boolean circuits before they undergo topological optimization. It extends wire ID support from v1's 32-bit to 34-bit values, enabling circuits with up to 17 billion (2^34) unique wires. This format is intentionally simple to make it easy for synthesis tools and circuit generators to produce.

### Key Features
- **Extended Wire IDs**: Support for up to 2^34 (~17 billion) unique wires
- **Simple Generation**: Easy for tools to output without complex optimization
- **Batch Processing**: Gates packed in batches of 8 for streaming I/O
- **Version Detection**: Explicit version and type bytes for format identification
- **Pre-optimization Format**: Designed as input to levelling algorithms

## Format Structure

### File Layout

```
[Header (50 bytes)]
[GateBatch 0 (103 bytes)]
[GateBatch 1 (103 bytes)]
...
[GateBatch N (103 bytes)]
```

### Header Structure (Fixed Size: 50 bytes)

```rust
struct HeaderV3A {
    version: u8,        // 1 byte: Always 0x03 for v3
    format_type: u8,    // 1 byte: Always 0x00 for TypeA
    checksum: [u8; 32], // 32 bytes: BLAKE3 hash of all data after checksum
    xor_gates: u64,     // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,     // 8 bytes: Total AND gates (little-endian)
}
```

#### Header Fields

- **version**: Must be `3` to identify v3 format
- **format_type**: Must be `0` to identify TypeA variant
- **checksum**: BLAKE3 hash of all bytes from position 34 to end of file (everything after the checksum field)
- **xor_gates**: Total number of XOR gates in the circuit
- **and_gates**: Total number of AND gates in the circuit

## Gate Batch Structure

### Batch Layout (Fixed Size: 103 bytes)

Each batch contains exactly 8 gates with their types:

```rust
struct GateBatch34 {
    gates: [u8; 102],     // Bit-packed 34-bit wire IDs
    gate_types: u8,       // 8 bits for gate types
}
```

### Wire ID Encoding

Each gate requires 3 × 34 bits = 102 bits for wire IDs:
- **input1**: 34 bits
- **input2**: 34 bits  
- **output**: 34 bits

Eight gates require: 8 × 102 = 816 bits = 102 bytes

### Bit Packing Layout

Wire IDs are tightly packed across byte boundaries. For gate at index `i` (0-7):

```
bit_offset = i * 102
input1_bits = [bit_offset : bit_offset + 34]
input2_bits = [bit_offset + 34 : bit_offset + 68]
output_bits = [bit_offset + 68 : bit_offset + 102]
```

#### Encoding Example

For gate 0 (aligned):
```
Bytes 0-4:  input1 (bits 0-33)
  byte[0] = input1 & 0xFF
  byte[1] = (input1 >> 8) & 0xFF
  byte[2] = (input1 >> 16) & 0xFF
  byte[3] = (input1 >> 24) & 0xFF
  byte[4] = (input1 >> 32) & 0x03  // Only lower 2 bits

Bytes 4-8:  input2 (bits 34-67)
  byte[4] |= (input2 & 0x3F) << 2  // Upper 6 bits of byte[4]
  byte[5] = (input2 >> 6) & 0xFF
  byte[6] = (input2 >> 14) & 0xFF
  byte[7] = (input2 >> 22) & 0xFF
  byte[8] = (input2 >> 30) & 0x0F  // Only lower 4 bits
  
... and so on
```

For unaligned gates, bits span across byte boundaries requiring careful bit shifting.

### Gate Type Encoding

The `gate_types` byte uses one bit per gate:
- Bit `i` (0-7) represents the type of gate `i`
- `0` = XOR gate
- `1` = AND gate

Example: `gate_types = 0b10101010` means gates 0,2,4,6 are XOR and gates 1,3,5,7 are AND.

## Implementation Details

### Reading a Gate

```rust
fn get_34bit_value(buffer: &[u8], bit_offset: usize) -> u64 {
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    
    if bit_shift == 0 {
        // Aligned case - simpler extraction
        let mut value = buffer[byte_offset] as u64;
        value |= (buffer[byte_offset + 1] as u64) << 8;
        value |= (buffer[byte_offset + 2] as u64) << 16;
        value |= (buffer[byte_offset + 3] as u64) << 24;
        value |= ((buffer[byte_offset + 4] & 0x03) as u64) << 32;
        value
    } else {
        // Unaligned case - read extra bytes and shift
        // ... implementation details ...
    }
}
```

### Writing a Gate

```rust
fn set_34bit_value(buffer: &mut [u8], bit_offset: usize, value: u64) {
    debug_assert!(value < (1u64 << 34));
    
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;
    
    if bit_shift == 0 {
        // Aligned case
        buffer[byte_offset] = (value & 0xFF) as u8;
        buffer[byte_offset + 1] = ((value >> 8) & 0xFF) as u8;
        buffer[byte_offset + 2] = ((value >> 16) & 0xFF) as u8;
        buffer[byte_offset + 3] = ((value >> 24) & 0xFF) as u8;
        buffer[byte_offset + 4] = 
            (buffer[byte_offset + 4] & 0xFC) | ((value >> 32) & 0x03) as u8;
    } else {
        // Unaligned case - preserve surrounding bits
        // ... implementation details ...
    }
}
```

## Size Calculations

### Per-Gate Overhead

- **v1 format**: 12 bytes per gate (3 × 32-bit values)
- **v3a format**: 12.75 bytes per gate (102 bytes / 8 gates)
- **Overhead**: 6.25% increase for 34-bit support

### Batch Efficiency

Batching 8 gates together provides:
- **Amortized type storage**: 1 bit per gate instead of 1 byte
- **Better I/O performance**: Fewer system calls
- **Cache efficiency**: Full cache line utilization

### Maximum Circuit Size

With 34-bit wire IDs:
- **Maximum wires**: 2^34 = 17,179,869,184 (~17 billion)
- **Maximum file size**: Limited by filesystem (typically 2^63 bytes)

## Role in Production Pipeline

v3a serves as the intermediate format in the circuit processing pipeline:

1. **Generation**: Synthesis tools output v3a (no optimization required)
2. **Storage**: v3a files are stored and transmitted
3. **Optimization**: Leveller reads v3a and produces v3b
4. **Production**: v3b is used for actual circuit evaluation

## Migration from v1

### Key Differences from v1

1. **Header size**: 50 bytes (v3a) vs 8 bytes (v1)
2. **Version detection**: Explicit version/type bytes
3. **Integrity verification**: BLAKE3 checksum for data integrity
4. **Wire ID range**: 34-bit vs 32-bit
5. **Batch size**: 103 bytes vs 97 bytes
6. **Gate counts**: 64-bit vs 32-bit in header

### Conversion Process

```rust
// Reading v1 and writing v3a
let v1_reader = v1::CircuitReader::new(input)?;
let mut v3a_writer = v3::a::CircuitWriter::new(output)?;

while let Some((batch, count)) = v1_reader.next_batch()? {
    for i in 0..count {
        let (gate, gate_type) = batch.get_gate(i);
        // Convert 32-bit to 34-bit (safe extension)
        let gate34 = CompactGate34::new(
            gate.input1 as u64,
            gate.input2 as u64,
            gate.output as u64,
        );
        v3a_writer.write_gate(gate34, gate_type)?;
    }
}
```

## Performance Characteristics

### Memory Layout

The 103-byte batch size is less cache-line friendly than v1's 97 bytes, but the impact is minimal:
- Modern CPUs have 64-byte cache lines
- 103 bytes spans 2 cache lines (same as v1's 97 bytes)

### Bit Manipulation Overhead

Extracting 34-bit values requires:
- **Aligned gates** (gates 0, 2, 5, 7): Simple byte operations
- **Unaligned gates** (gates 1, 3, 4, 6): Additional bit shifting

The CPU's barrel shifter makes this overhead negligible for most workloads.

### Suggested Buffer Sizes

- **Reading**: 64KB-1MB buffers (640-10,000 batches)
- **Writing**: 64KB buffers with periodic flushes

## Error Handling

### Format Validation

Readers MUST validate:
1. Version byte equals `3`
2. Format type byte equals `0`
3. BLAKE3 checksum matches computed hash of data after checksum
4. File size matches expected batch count:
   ```
   expected_batches = ceil(total_gates / 8)
   expected_size = 50 + (expected_batches * 103)
   ```

### Wire ID Validation

Writers SHOULD validate:
- Wire IDs do not exceed 34-bit maximum (2^34 - 1)
- Output wire IDs are monotonically increasing (optional but recommended)

### Partial Batch Handling

The last batch may contain fewer than 8 gates:
- Unused gate slots should be zeroed
- Reader must use header gate counts to determine valid gates

## Example Circuit

### Circuit Definition

```
XOR(0, 1) -> 2
AND(0, 2) -> 3
XOR(1, 3) -> 4
```

### Encoded Format (Hex)

```
Header (50 bytes):
03 00                    # version=3, type=0
[32 bytes checksum]      # BLAKE3 hash of remaining data
02 00 00 00 00 00 00 00  # xor_gates=2
01 00 00 00 00 00 00 00  # and_gates=1

Batch 0 (103 bytes):
[102 bytes of bit-packed gate data]
02                       # gate_types: 0b00000010 (gate 1 is AND)
```

## Security Considerations

### Input Validation

Implementations MUST:
- Validate header before allocating buffers
- Verify BLAKE3 checksum matches the data
- Check for integer overflow when calculating buffer sizes
- Limit maximum file size to prevent DoS

### Checksum Computation

Writers compute the checksum as follows:
1. Write placeholder header with zero checksum
2. Write all gate batches
3. Compute BLAKE3 hash of bytes from position 34 to end
4. Seek back and update checksum field
5. Flush to disk

Readers verify the checksum by:
1. Read the 50-byte header
2. Extract the checksum field
3. Read remaining file data
4. Compute BLAKE3 hash of data (excluding header first 34 bytes)
5. Compare with stored checksum

### Memory Safety

- Use bounds checking for all buffer accesses
- Validate bit offsets before bit manipulation
- Clear sensitive data from memory after use

## Future Extensions

### Design Philosophy

v3a is intentionally kept simple as an intermediate format. Complex optimizations belong in the leveller transformation to v3b, not in v3a itself. This ensures:

- Circuit generators remain simple
- Format is easy to validate and debug
- Clear separation of concerns

### Potential Extensions

1. **Larger Wire IDs**: 36-bit if needed (108-byte batches)
2. **Metadata**: Circuit annotations for debugging
3. **Checksums**: Per-batch integrity verification

### Reserved Bytes

The format currently uses all bytes efficiently. Future versions requiring additional metadata should increment the version number.
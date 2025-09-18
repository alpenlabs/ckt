# CKT Format v3 Specification Overview

## Introduction

CKT Format v3 represents a significant evolution in Boolean circuit storage, offering two complementary variants for different stages of the circuit processing pipeline:

- **v3a (Type A)**: Intermediate format for unoptimized circuits with 34-bit wire IDs, evolved from v1
- **v3b (Type B)**: Production format for high-performance circuit evaluation with level-based organization, evolved from v2

Both variants share a common version identifier (3) but use different type flags for disambiguation. The typical workflow is: v3a (storage) → leveller → v3b (execution).

## Format Selection Guide

### v3a - Intermediate Storage Format:
- For storing raw, unoptimized circuits from synthesis tools
- Before topological optimization via leveller
- When circuit structure is arbitrary or unknown
- For circuits awaiting processing
- As input to the levelling algorithm
- Simple format for tools to generate

### v3b - Production Execution Format:
- For final, optimized circuits ready for evaluation
- After levelling optimization
- Maximum performance in production systems
- Parallel circuit evaluation
- Minimal memory footprint
- Cache-optimized access patterns

## Shared Components

### Version Detection and Integrity

Both formats start with:
```
byte 0: version (0x03)
byte 1: format_type (0x00 for v3a, 0x01 for v3b)
bytes 2-33: BLAKE3 checksum (32 bytes)
```

This allows readers to detect format version and verify data integrity.

### Gate Types

Both formats support exactly two gate types:
- XOR gates (2-input, 1-output)
- AND gates (2-input, 1-output)

## Format Comparison

| Feature | v3a | v3b |
|---------|-----|-----|
| **Wire ID bits** | 34-bit | Variable (varint) |
| **Max wires** | ~17 billion | ~4.6 quintillion |
| **Output storage** | Explicit | Implicit |
| **Organization** | Batches of 8 | Levels |
| **Header size** | 50 bytes | 58 bytes |
| **Per-gate size** | 12.75 bytes | ~4-6 bytes |
| **Checksum** | BLAKE3 (32 bytes) | BLAKE3 (32 bytes) |
| **Compression** | No | Built-in |
| **Parallelism** | N/A | Per level |
| **Purpose** | Intermediate storage | Production execution |
| **Best for** | Pre-optimization | Post-optimization |

## Common Header Structure

```rust
struct V3Header {
    version: u8,        // Always 3
    format_type: u8,    // 0 for v3a, 1 for v3b
    checksum: [u8; 32], // BLAKE3 hash of all data after checksum
    // Type-specific fields follow...
}
```

### v3a Additional Header Fields
```rust
    xor_gates: u64,   // 8 bytes
    and_gates: u64,   // 8 bytes
    // Total: 50 bytes (2 + 32 + 8 + 8)
```

### v3b Additional Header Fields
```rust
    xor_gates: u64,      // 8 bytes
    and_gates: u64,      // 8 bytes
    primary_inputs: u64, // 8 bytes
    // Total: 58 bytes (2 + 32 + 8 + 8 + 8)
```

## Wire ID Encoding Strategies

### v3a: Fixed-Width Encoding
- Every wire ID is exactly 34 bits
- Packed tightly across byte boundaries
- Simple indexing but constant overhead

### v3b: Level-Based Encoding
- Wire = [level_id, index_in_level]
- Optimized for previous-level references
- Variable size based on locality

## Memory Layout Comparison

### v3a Memory Layout
```
[Header-50B][Batch0-103B][Batch1-103B]...[BatchN-103B]
```
- Fixed-size batches enable random access
- Each batch contains exactly 8 gates
- Predictable memory requirements

### v3b Memory Layout
```
[Header-58B][Level1-Variable][Level2-Variable]...[LevelN-Variable]
```
- Variable-size levels match circuit topology
- Sequential access optimized
- Memory depends on circuit structure

## Performance Characteristics

### v3a Performance
- **Strengths**:
  - Predictable memory access patterns
  - Simple bit manipulation (though crossing boundaries)
  - Good for streaming large circuits
  - Batch-level parallelism

- **Weaknesses**:
  - Higher memory usage
  - No compression benefits
  - Bit unpacking overhead

### v3b Performance
- **Strengths**:
  - Excellent compression ratios
  - Cache-friendly level processing
  - Natural parallelism boundaries
  - Minimal memory footprint

- **Weaknesses**:
  - Complex encoding/decoding logic
  - Variable-length records
  - Requires level tracking state

## Migration Paths

### From v1 to v3a
```rust
// Direct gate-by-gate conversion
while let Some((batch, count)) = v1_reader.next_batch()? {
    for i in 0..count {
        let (gate, gate_type) = batch.get_gate(i);
        // Extend 32-bit to 34-bit
        let gate34 = CompactGate34::new(
            gate.input1 as u64,
            gate.input2 as u64,
            gate.output as u64,
        );
        v3a_writer.write_gate(gate34, gate_type)?;
    }
}
```

### From v2 to v3b
```rust
// Level-preserving conversion
while let Some(level) = v2_reader.read_level()? {
    // Convert gates removing output wire IDs
    let converted_level = Level {
        id: level_counter++,
        xor_gates: level.xor_gates.iter().map(|g|
            Gate::new(
                encode_wire_location(g.input1),
                encode_wire_location(g.input2),
            )
        ).collect(),
        and_gates: // similar conversion
    };
    v3b_writer.write_level(&converted_level)?;
}
```

### From v3a to v3b (Primary Pipeline)
This is the primary production pipeline using the `lvl` crate:
1. Read v3a format (unoptimized circuit)
2. Build dependency graph
3. Topologically sort into levels
4. Optimize for cache locality
5. Write as v3b (production-ready)

This transformation is essential for production deployment.

## Implementation Guidelines

### Buffer Sizes
- **v3a**: Use multiples of 103 bytes (e.g., 103KB for 1000 batches)
- **v3b**: Use 64KB-256KB for general purpose

### Error Handling
Both formats should:
1. Validate version and type bytes
2. Check wire ID bounds
3. Verify file size matches header claims
4. Handle partial/corrupted data gracefully

### Platform Considerations
- Both formats use little-endian byte order
- Both support 64-bit file offsets
- Neither requires specific alignment (beyond byte boundaries)

## Format Evolution

### Why Two Variants?

The dual-variant approach separates concerns in the circuit processing pipeline:

1. **Generation & Storage** (v3a): Synthesis tools produce circuits with arbitrary structure. v3a provides a simple format that's easy to generate and store, without requiring optimization.

2. **Optimization & Execution** (v3b): Production systems need maximum performance. v3b provides a highly optimized format after circuits have been processed through a leveller.

This separation allows:
- Simple tools that generate v3a without complex optimization
- One-time optimization cost when converting to v3b
- Maximum runtime performance with v3b in production
- Clear pipeline: generate → store → optimize → execute

### Future Compatibility

The version/type byte pattern allows for:
- Version 4+ for major breaking changes
- Type 2-255 for additional v3 variants
- Backward-compatible readers via version detection

## Security Considerations

Both formats require:
- BLAKE3 checksum verification before processing
- Input validation before memory allocation
- Bounds checking on all wire IDs
- Protection against malicious file sizes
- Rejection of files with invalid checksums

## Conclusion

CKT v3 provides a complete circuit processing pipeline through two complementary formats:

- **v3a**: Intermediate format for circuit storage and transport
- **v3b**: Production format for high-performance circuit evaluation

The typical workflow:
1. **Generate**: Tools output v3a (simple to implement)
2. **Store/Transfer**: v3a files (self-contained, portable)
3. **Optimize**: Leveller transforms v3a → v3b (one-time cost)
4. **Execute**: Production systems evaluate v3b (maximum performance)

This design ensures both ease of integration and production performance.

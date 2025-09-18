# CKT Format v3b Specification

## Overview

Version 3b (v3b) is the production format for high-performance Boolean circuit evaluation. It represents the final, optimized form of a circuit after topological levelling. This format is specifically designed for maximum evaluation performance in production systems, with features like implicit outputs, cache-optimized level organization, and wire encoding that exploits topological locality.

### Key Innovations for Production Performance
- **Implicit Outputs**: Eliminates output storage overhead for faster evaluation
- **Cache-Optimized Levels**: Ensures maximum cache hit rates during parallel evaluation
- **Previous Level Fast Path**: Optimized encoding for the common dependency pattern
- **Explicit Level 0**: Primary inputs formalized for consistent evaluation semantics
- **Production Ready**: Output of the levelling process, ready for high-throughput evaluation

## Wire ID Philosophy

In v3b, every wire is uniquely identified by:
- **Level ID**: Which level produced this wire (0 = primary inputs)
- **Index**: Position within that level (0-based)

## Varint Specifications

v3b uses the same varint types as v2 but with different semantics:

### StandardVarInt
Standard QUIC varint encoding (unchanged from v2):
- 1 byte: values 0-63
- 2 bytes: values 64-16,383
- 4 bytes: values 16,384-1,073,741,823
- 8 bytes: values 1,073,741,824-4,611,686,018,427,387,903

### FlaggedVarInt for Level IDs

The flag bit has special meaning for level encoding:

```rust
enum LevelEncoding {
    PreviousLevel,     // flag=1, value=index within previous level
    OtherLevel,        // flag=0, followed by level specification
}
```

When `OtherLevel`, the next bit indicates:
- `0`: Relative level ID (backward reference, e.g., relative(2) = current_level - 2)
- `1`: Absolute level ID (direct reference, e.g., absolute(5) = level 5)

## Format Structure

### File Layout

```
[Header (58 bytes)]
[Level 0 (implicit, no data)]
[Level 1 encoded]
[Level 2 encoded]
...
[Level N encoded]
```

### Header Structure (Fixed Size: 58 bytes)

```rust
struct HeaderV3B {
    version: u8,          // 1 byte: Always 0x03
    format_type: u8,      // 1 byte: Always 0x01 for TypeB
    checksum: [u8; 32],   // 32 bytes: BLAKE3 hash of all data after checksum
    xor_gates: u64,       // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,       // 8 bytes: Total AND gates (little-endian)
    primary_inputs: u64,  // 8 bytes: Number of primary inputs (level 0 size)
}
```

## Level Structure

### Level Header

Each level starts with:
1. `num_xor` (FlaggedVarInt):
   - Value: Number of XOR gates
   - Flag: 1 if level contains AND gates, 0 if XOR-only
2. `num_and` (StandardVarInt): Only present if flag=1

### Gate Encoding

Each gate stores only its two inputs (output is implicit):

```rust
struct EncodedGate {
    input1: EncodedWireID,
    input2: EncodedWireID,
    // output is implicit: current wire_counter
}
```

## Wire ID Encoding

### Encoding Algorithm

```rust
fn encode_wire_id(wire_level: u32, wire_index: u32, current_level: u32) -> bytes {
    if wire_level == current_level - 1 {
        // Previous level optimization (most common case)
        return FlaggedVarInt::with_flag(wire_index, true);
    } else {
        // Other level (must be < current_level - no forward references allowed)
        let mut bytes = FlaggedVarInt::with_flag(0, false);
        
        // Choose the more efficient encoding
        let distance = current_level - wire_level;
        if distance < wire_level {
            // Relative encoding is smaller (e.g., level 3000000 referring to 2999999)
            bytes.append(FlaggedVarInt::relative(distance));
        } else {
            // Absolute encoding is smaller (e.g., level 3000000 referring to level 5)
            bytes.append(FlaggedVarInt::absolute(wire_level));
        }
        
        // Always append index for non-previous levels
        bytes.append(StandardVarInt::new(wire_index));
        return bytes;
    }
}
```

### Decoding Algorithm

```rust
fn decode_wire_id(bytes: &[u8], current_level: u32) -> (level, index, bytes_consumed) {
    let (first_varint, consumed) = FlaggedVarInt::decode(bytes);

    if first_varint.is_previous_level() {
        // Previous level - value is the index
        return (current_level - 1, first_varint.value(), consumed);
    } else {
        // Other level - need to read level spec
        let (level_varint, consumed2) = FlaggedVarInt::decode(&bytes[consumed..]);

        let level = if level_varint.is_relative() {
            current_level - level_varint.value()
        } else {
            level_varint.value()  // absolute
        };

        // Read index
        let (index_varint, consumed3) = StandardVarInt::decode(&bytes[consumed + consumed2..]);

        return (level, index_varint.value(), consumed + consumed2 + consumed3);
    }
}
```

## Level Organization

### Level 0: Primary Inputs

Level 0 is implicit and contains exactly `primary_inputs` wires:
- Wire IDs: 0 to primary_inputs-1
- No gates (pure inputs)
- Never serialized to disk

### Level Processing Example

Consider a circuit snippet:
```
Level 0: Primary inputs [0, 1, 2, 3]  # implicit
Level 1: 
  XOR(0, 1) -> 4
  XOR(2, 3) -> 5
Level 2:
  AND(4, 5) -> 6      # Both from previous level
  XOR(0, 4) -> 7      # Mixed: level 0 and level 1
Level 3:
  AND(6, 7) -> 8      # Both from previous level
```

Encoded wire references:
- Level 2, gate 0: `input1 = [flag=1, value=0]` (previous level, index 0 = wire 4)
- Level 2, gate 0: `input2 = [flag=1, value=1]` (previous level, index 1 = wire 5)
- Level 2, gate 1: `input1 = [flag=0][abs=1, value=0][index=0]` (level 0, index 0)
- Level 2, gate 1: `input2 = [flag=0][abs=1, value=1][index=0]` (level 1, index 0 = wire 4)
- Level 3, gate 0: `input1 = [flag=1, value=0]` (previous level, index 0 = wire 6)
- Level 3, gate 0: `input2 = [flag=1, value=1]` (previous level, index 1 = wire 7)

## Wire Counter Management

### Initialization
```
wire_counter = primary_inputs  // Start after primary inputs
```

### Progression
After each gate is processed:
```
gate.output = wire_counter  // Implicit assignment
wire_counter += 1
```

### Level Tracking
Maintain a vector of level sizes for decoding:
```
level_sizes = [primary_inputs, level1_gates, level2_gates, ...]
```

## Size Optimization Benefits

### Performance Benefits for Production

Compared to unoptimized formats:
1. **Memory Efficiency**: ~33% reduction via output elimination
2. **Cache Performance**: Sequential level access maximizes L1/L2 hits
3. **Parallel Evaluation**: Each level can be evaluated independently
4. **Predictable Latency**: Level structure ensures consistent evaluation time

Typical encoding sizes:
- Previous level reference: 1-2 bytes total
- Near level reference (relative): 3-4 bytes total when distance < level_id
- Distant level reference (absolute): 3-4 bytes total when level_id ≤ distance
- Primary input reference: 3-4 bytes total (always absolute level 0)

### Example Circuit Comparison

For a 1M gate circuit with good locality:
- **v2 format**: ~6-8 bytes per gate (3 wire IDs)
- **v3b format**: ~4-5 bytes per gate (2 wire IDs, implicit output)
- **Savings**: 33-40% reduction

## Implementation Requirements

### Reader State

Readers must maintain:
1. Current level ID
2. Current wire counter
3. Vector of level sizes for lookups
4. Mapping of level_id -> starting wire_id

### Writer State

Writers must maintain:
1. Current level ID
2. Wire counter
3. Level sizes vector
4. Buffered level gates before writing

### Memory Management

- Level sizes vector grows linearly with circuit depth
- For circuits with 10K levels: ~80KB overhead
- Consider chunking for extremely deep circuits

## Performance Characteristics

### Production Evaluation Performance

Level-based organization enables:
- **Maximum Throughput**: Gates in a level evaluate in parallel
- **Optimal Cache Usage**: Working set fits in L2 cache per level
- **Hardware Prefetching**: CPU prefetchers optimize for sequential access
- **SIMD Opportunities**: Vectorized evaluation within levels
- **Predictable Performance**: Consistent evaluation time in production

### Parallel Processing

Each level can be processed in parallel:
```rust
fn process_level(level: &Level) -> Result<()> {
    rayon::par_iter(&level.xor_gates).for_each(|gate| {
        // Process XOR gates in parallel
    });
    rayon::par_iter(&level.and_gates).for_each(|gate| {
        // Process AND gates in parallel
    });
}
```

## Error Handling

### Validation Rules

1. **Header Validation**:
   - Version must be 3
   - Format type must be 1
   - BLAKE3 checksum must match computed hash
   - Primary inputs > 0

2. **Level Validation**:
   - Wire IDs must reference existing wires
   - Level ID must be valid (0 <= level_id < current_level)
   - No forward or same-level references allowed (gates in level N can only reference levels 0 through N-1)
   - Index must be within level bounds

3. **Wire Counter Validation**:
   - Output wire IDs must be sequential
   - No gaps in wire numbering

### Recovery Strategies

For corrupted data:
1. Verify BLAKE3 checksum first - if invalid, reject entire file
2. Skip to next level boundary (if detectable)
3. Use checksums per level (optional extension)
4. Maintain backup of level sizes

## Example Circuit

### Circuit Definition
```
Primary inputs: 4 (wires 0-3)
Level 1:
  XOR(0, 1) -> 4
  XOR(2, 3) -> 5
Level 2:
  AND(4, 5) -> 6
```

### Encoded Format

```
Header (58 bytes):
03                       # version = 3
01                       # format_type = TypeB (1)
[32 bytes checksum]      # BLAKE3 hash of remaining data
02 00 00 00 00 00 00 00  # xor_gates = 2
01 00 00 00 00 00 00 00  # and_gates = 1
04 00 00 00 00 00 00 00  # primary_inputs = 4

Level 1:
02                       # num_xor=2, flag=0 (no AND gates)
  Gate 0 (XOR):
    80 00                # input1: level=0, index=0 (wire 0)
    80 00 01             # input2: level=0, index=1 (wire 1)
  Gate 1 (XOR):
    80 00 02             # input1: level=0, index=2 (wire 2)
    80 00 03             # input2: level=0, index=3 (wire 3)

Level 2:
01                       # num_xor=0, flag=1 (has AND gates)
01                       # num_and=1
  Gate 0 (AND):
    20                   # input1: previous level, index=0 (wire 4)
    21                   # input2: previous level, index=1 (wire 5)
```

## Migration from v2

### Key Differences for Production

1. **Output removal**: Reduces memory bandwidth in evaluation hot path
2. **Wire encoding**: Optimized for level-based parallel evaluation
3. **Header**: Format type enables runtime optimization selection
4. **Level 0**: Standardized primary input handling for evaluation
5. **Production focus**: Every design decision prioritizes evaluation speed

### Production Pipeline

```rust
// v3a → v3b transformation for production deployment
// This is typically done once during circuit preparation

// Read intermediate format (v3a)
let v3a_reader = v3::a::CircuitReader::new(input)?;
let leveller = Leveller::new(primary_inputs);

// Optimize circuit topology
while let Some((batch, count)) = v3a_reader.next_batch()? {
    for gate in batch.gates() {
        leveller.add_gate(gate);
    }
}

// Write production format (v3b)
let mut v3b_writer = v3::b::CircuitWriter::new(output, primary_inputs)?;
while let Some(level) = leveller.take_level() {
    v3b_writer.write_level(&level)?;
}

// v3b file is now ready for production evaluation
```

### Checksum Computation and Verification

#### Writer Process
1. Write header with placeholder checksum (zeros)
2. Write all levels to file
3. Compute BLAKE3 hash of all data after position 34 (after checksum field)
4. Seek back to position 2 and write the 32-byte checksum
5. Flush to ensure data is written

#### Reader Process
1. Read the 58-byte header
2. Extract checksum from bytes 2-33
3. Read or memory-map remaining file data
4. Compute BLAKE3 hash of all data after byte 34
5. Verify computed hash matches stored checksum
6. Reject file if checksums don't match

This ensures data integrity for production circuits, detecting any corruption or tampering.

## Future Considerations

### Production Enhancement Opportunities

1. **GPU Evaluation**: Level structure maps directly to GPU warps
2. **AVX-512 Support**: Wide SIMD evaluation per level
3. **Memory Mapping**: Direct mmap for zero-copy evaluation
4. **Distributed Evaluation**: Levels as natural distribution boundaries
5. **JIT Compilation**: Generate specialized evaluators per circuit

### Format Extensibility

Reserved for future use:
- Format type values 2-255
- Version values 4-255
- Additional header fields via version increment

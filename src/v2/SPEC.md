# CKT Format v2 Specification

## Overview

CKT v2 is a high-performance binary format for storing Boolean circuits with significant improvements over v1:

- **Scalable wire IDs**: Support for up to 2^61 wires using variable-length integer encoding
- **Explicit topological levels**: Gates are organized by dependency levels for parallel processing
- **Locality-aware compression**: Modified varint encoding exploits circuit locality patterns
- **Space efficiency**: Dramatic size reduction through relative/absolute wire ID encoding
- **SoA-friendly**: Reader API supports Structure of Arrays pattern for vectorization

## Varint Specifications

### StandardVarInt

Used for level metadata like `num_xor` and `num_and` counts. Standard QUIC varint encoding:

```
Length | Format
-------|--------
1 byte | 0xxxxxxx (0-127)
2 bytes| 01xxxxxx xxxxxxxx (0-16383) 
4 bytes| 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (0-1073741823)
8 bytes| 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (0-4611686018427387903)
```

### FlaggedVarInt

Used for gate wire IDs and level metadata with byte-slice API. Based on QUIC varint but steals 1 bit for a flag:

```
Length | Format                                    | Max Value
-------|-------------------------------------------|----------
1 byte | 00rxxxxx                                 | 31
2 bytes| 01rxxxxx xxxxxxxx                       | 8191  
4 bytes| 10rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx     | 536870911
8 bytes| 11rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx ... | 2^61-1
```

Where the flag bit has context-dependent meaning:
- **For wire IDs**: `0` = Absolute wire ID, `1` = Relative to current counter position  
- **For num_xors**: `0` = No AND gates in level, `1` = AND gates follow

### Varint API

Both varint types use efficient byte-slice operations:

```rust
// Encoding: returns bytes used
pub fn encode(self, buffer: &mut [u8]) -> Result<usize>

// Decoding: returns (varint, bytes_consumed) 
pub fn decode(buffer: &[u8]) -> Result<(Self, usize)>
```

## Format Structure

### File Layout

```
[Header] [Level0] [Level1] ... [LevelN]
```

Where each level contains:
```
[num_xor: FlaggedVarInt] [num_and: StandardVarInt (optional)] [XorGates...] [AndGates...]
```

### Header Structure (Fixed Size: 25 bytes)

```rust
struct HeaderV2 {
    version: u8,                    // Fixed: 2 (1 byte)
    xor_gates: u64,                 // Total number of XOR gates in circuit (8 bytes, little-endian)
    and_gates: u64,                 // Total number of AND gates in circuit (8 bytes, little-endian) 
    primary_inputs: u64,            // Number of primary input wires (8 bytes, little-endian)
}
```

**Header Layout**: 1 + 8 + 8 + 8 = 25 bytes total, always fixed size for efficient updates.

### Level Structure

Each level in the circuit is encoded as:

```rust
struct Level {
    num_xor: FlaggedVarInt,         // Number of XOR gates + AND gate presence flag (1-8 bytes)
    num_and: StandardVarInt,        // Number of AND gates (1-8 bytes, only if flag=1)
    xor_gates: [Gate; num_xor],     // All XOR gates in this level
    and_gates: [Gate; num_and],     // All AND gates in this level (only if flag=1)
}
```

Gates within a level can be processed in parallel since they only depend on:
- Primary inputs (wires 0 to primary_inputs-1)
- Outputs from previous levels

## Gate Structure

```rust
struct Gate {
    input1: FlaggedVarInt,          // First input wire ID (1-8 bytes)
    input2: FlaggedVarInt,          // Second input wire ID (1-8 bytes)
    output: FlaggedVarInt,          // Output wire ID (1-8 bytes, usually 1 byte as relative(0))
}
```

Gate types are implicit based on position within the level:
- All gates in the `xor_gates` array are XOR gates
- All gates in the `and_gates` array are AND gates
- No explicit gate type encoding is needed

## Wire ID Counter & Encoding

### Counter Initialization
```rust
let mut counter = primary_inputs; // Start after primary inputs
```

### Counter Progression
For each gate processed:
1. The gate's output wire ID becomes `counter`
2. Increment `counter` for next gate
3. Encode gate's input/output wire IDs using WireVarInt

### Encoding Logic

For each wire ID to encode:

```rust
fn encode_wire_id(absolute_id: u64, counter: u64) -> FlaggedVarInt {
    let relative_value = counter.saturating_sub(absolute_id);
    
    if absolute_id <= relative_value {
        // Absolute encoding is smaller/equal
        FlaggedVarInt::absolute(absolute_id)
    } else {
        // Relative encoding is smaller  
        FlaggedVarInt::relative(relative_value)
    }
}
```

### Decoding Logic

```rust
fn decode_wire_id(varint: FlaggedVarInt, counter: u64) -> u64 {
    if varint.is_relative() {
        counter.saturating_sub(varint.value())
    } else {
        varint.value()
    }
}

// Built-in method for convenience
varint.decode_to_absolute(counter)
```

### Level Encoding Logic

```rust
fn encode_level(level: &Level) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    
    // Encode num_xor with AND gate presence flag
    let has_and_gates = !level.and_gates.is_empty();
    let num_xor_flagged = FlaggedVarInt::with_flag(level.xor_gates.len() as u64, has_and_gates)?;
    num_xor_flagged.encode(&mut buffer)?;
    
    // Only encode num_and if there are AND gates
    if has_and_gates {
        let num_and_varint = StandardVarInt::new(level.and_gates.len() as u64)?;
        num_and_varint.encode(&mut buffer)?;
    }
    
    // Encode gates...
    Ok(buffer)
}

fn decode_level(data: &[u8]) -> Result<Level> {
    let (num_xor_flagged, mut offset) = FlaggedVarInt::decode(data)?;
    let num_xor = num_xor_flagged.value();
    let has_and_gates = num_xor_flagged.flag();
    
    let num_and = if has_and_gates {
        let (varint, consumed) = StandardVarInt::decode(&data[offset..])?;
        offset += consumed;
        varint.value()
    } else {
        0
    };
    
    // Decode gates...
}
```

## Level Organization

Levels are explicitly encoded in the format:

1. **Level Structure**: Each level contains `num_gates`, followed by all gates, then gate types
2. **Parallel Processing**: All gates within a level can be processed in parallel
3. **Cross-Level Dependencies**: Gates only reference wires from previous levels or primary inputs
4. **Sequential Levels**: Levels must be processed in order, but gates within each level are independent

### Level Processing Example

```
Primary inputs: wires 0-99 (100 total)
Counter starts at: 100

Level 0:
- num_xor=1, num_and=1
- XOR Gate A: inputs(5,7) -> output(100)     [Only uses primary inputs]
- AND Gate B: inputs(12,34) -> output(101)   [Only uses primary inputs] 

Level 1:
- num_xor=1, num_and=0  
- XOR Gate C: inputs(100,45) -> output(102)  [Uses Gate A output(100)]

Level 2:
- num_xor=0, num_and=1
- AND Gate D: inputs(101,102) -> output(103) [Uses Gates B&C outputs]
```

## Size Optimization Benefits

### Typical Encoding Sizes

**Gate Outputs**: Usually `relative(0)` since gates are processed sequentially
- Encoded as: `00100000` (1 byte)

**Recent References**: Gates often reference recent outputs  
- Wire 95 when counter=100: `relative(5)` = `00100101` (1 byte)

**Primary Inputs**: Early in large circuits
- Wire 42: `absolute(42)` = `00001010 00101010` (2 bytes worst case)

**Distant References**: Rare but handled efficiently
- Uses longer varint encodings only when necessary

## Example Circuit

### Circuit Definition
- Primary inputs: 4 wires (0,1,2,3)
- Gates:
  1. XOR(0,1) -> 4
  2. AND(2,3) -> 5  
  3. XOR(4,5) -> 6

### Encoded Format

**Header** (25 bytes total):
```
02                              // version = 2 (1 byte)
02 00 00 00 00 00 00 00        // xor_gates = 2 (8 bytes, little-endian u64)
01 00 00 00 00 00 00 00        // and_gates = 1 (8 bytes, little-endian u64)
04 00 00 00 00 00 00 00        // primary_inputs = 4 (8 bytes, little-endian u64)
```

**Level 0** (2 XOR gates, no AND gates):
```
00000100    // num_xor = 2, flag=0 (no AND gates) - saves 1 byte!
// XOR Gate 1: XOR(0,1) -> 4, counter=4
00000000    // input1: absolute(0) 
00000001    // input2: absolute(1)
00100000    // output: relative(0) = 4-4
// XOR Gate 2: XOR(2,3) -> 5, counter=5  
00000010    // input1: absolute(2)
00000011    // input2: absolute(3) 
00100000    // output: relative(0) = 5-5
```

**Level 1** (0 XOR gates, 1 AND gate):
```
00100000    // num_xor = 0, flag=1 (has AND gates)
01          // num_and = 1 (only present because flag=1)
// AND Gate 3: AND(4,5) -> 6, counter=6
00100010    // input1: relative(2) = 6-4 
00100001    // input2: relative(1) = 6-5  
00100000    // output: relative(0) = 6-6
```

Total size: 25 + 7 + 4 = **36 bytes** vs v1's ~97+ bytes for same circuit.

**Space Savings**: This optimization saves 1 byte per level with no AND gates. In typical circuits with 99% XOR gates, this results in significant space savings across many levels.

## Implementation Notes

### Streaming Requirements
- Gates must be written in topological level order
- Levels are explicitly marked with `num_xor` and `num_and`
- Header written with placeholder values, then updated at end (requires seek for writing)
- No seek operations required for reading

### Memory Efficiency  
- Can read one level at a time for parallel processing
- Minimal state required (just wire counter)
- SoA reader variants enable vectorization

### Reader API Variants

#### High-Performance Monoio Reader
```rust
// AoS (Array of Structures) - traditional approach
async fn read_level(&mut self) -> Result<Option<Level>>

// SoA (Structure of Arrays) - vectorization-friendly  
async fn read_soa_level<const N: usize>(&mut self) -> Result<Option<(XorGates<N>, AndGates<N>)>>

struct XorGates<const N: usize> {
    input1s: [u64; N],     // All XOR input1 wire IDs
    input2s: [u64; N],     // All XOR input2 wire IDs  
    outputs: [u64; N],     // All XOR output wire IDs
    count: usize,          // Actual number of valid XOR gates
}

struct AndGates<const N: usize> {
    input1s: [u64; N],     // All AND input1 wire IDs
    input2s: [u64; N],     // All AND input2 wire IDs  
    outputs: [u64; N],     // All AND output wire IDs
    count: usize,          // Actual number of valid AND gates
}
```

#### Writer API
```rust
// High-performance async writer with monoio
async fn write_level(&mut self, level: &Level) -> Result<()>
async fn write_levels(&mut self, levels: &[Level]) -> Result<()>
async fn finish(self) -> Result<(File, CircuitStats)>
```

### Performance Characteristics

#### Space Efficiency
- **Gate outputs**: Usually 1 byte each (relative(0) encoding)
- **Recent references**: 1-2 bytes for recently computed wires  
- **Primary inputs**: 1-2 bytes for small wire IDs
- **Typical compression**: 60-80% smaller than v1 format

#### Computational Efficiency
- **Zero-copy I/O**: Direct byte slice operations, no intermediate allocations
- **Vectorization ready**: SoA layout enables SIMD operations on 8-32 gates simultaneously
- **Cache friendly**: Level-by-level processing with good locality
- **Async I/O**: Non-blocking file operations with monoio

#### Parallel Processing
- **Level parallelism**: All gates within a level can execute in parallel
- **Gate type separation**: XOR and AND gates processed separately for optimal vectorization
- **Streaming**: Can process circuits larger than memory

## Error Handling and Validation

### Format Validation
Writers and readers MUST validate:

1. **Version Compatibility**: First byte must be `2`
2. **Header Integrity**: Header must be exactly 25 bytes
3. **Wire ID Constraints**: 
   - All wire IDs must be < 2^61
   - Input wire IDs must reference existing wires (< current counter)
   - Output wire IDs must equal current counter
4. **Level Consistency**: 
   - `num_xor + num_and` must match actual gates in level
   - Gates must not reference wires from future levels
5. **Circuit Completeness**: Total gates read must match header counts

### Error Conditions

#### Writer Errors
- `InvalidData`: Gate references unavailable wire IDs
- `InvalidData`: Output wire ID doesn't match counter  
- `InvalidData`: Varint value exceeds maximum (2^61 - 1)
- `WriteZero`: Buffer too small for varint encoding

#### Reader Errors
- `InvalidData`: Unsupported version byte
- `UnexpectedEof`: Incomplete header or truncated data
- `InvalidData`: Malformed varint encoding
- `UnexpectedEof`: Level declares more gates than available data

### Recovery Strategies
- **Partial reads**: Readers should return successfully read levels on EOF
- **Buffer management**: Writers should flush on large buffers to prevent memory exhaustion
- **Validation**: Early validation prevents corrupted files

## Implementation Requirements

### Memory Management
- **Buffer sizes**: Recommended 64KB-1MB read buffers for optimal performance
- **Streaming**: Implementations MUST support circuits larger than available RAM
- **Zero-copy**: Preferred implementations should minimize allocations

### Threading and Async
- **Level parallelism**: Readers should enable parallel processing of levels
- **Async I/O**: High-performance implementations should use async I/O (monoio)
- **Backpressure**: Writers should implement flow control for large circuits

### Platform Requirements
- **Endianness**: All multi-byte values use little-endian encoding
- **Alignment**: No special alignment requirements (packed format)
- **File systems**: Must support seek operations for writers (header updates)

## Security Considerations

### Input Validation
- **Bounds checking**: All varint decoding must validate value ranges
- **Buffer overflow protection**: Never read beyond available buffer data
- **Memory exhaustion**: Validate level sizes before allocation

### Malicious Input Protection
- **Denial of Service**: Limit maximum level sizes and circuit sizes
- **Integer overflow**: Use saturating arithmetic for wire counter operations
- **Resource exhaustion**: Implement timeouts and memory limits

## Performance Characteristics

### Expected Performance
- **Encoding speed**: 500MB/s - 2GB/s depending on circuit complexity
- **Decoding speed**: 1GB/s - 4GB/s with zero-copy readers
- **Compression ratio**: 60-90% smaller than v1, depending on circuit locality
- **Memory usage**: O(buffer_size) for streaming, O(level_size) for level processing

### Optimization Guidelines
- **Vectorization**: Use SoA readers for SIMD processing of 8-32 gates
- **Cache efficiency**: Process levels sequentially, gates within levels in parallel
- **I/O patterns**: Large sequential reads/writes preferred over many small operations
- **Buffer tuning**: 64KB-1MB buffers balance memory usage and I/O efficiency

## Format Validation Rules

### Structural Validation
1. **File starts with version byte `2`**
2. **Header is exactly 25 bytes**
3. **Each level starts with valid StandardVarInts for counts**
4. **Gate counts match declared level sizes**
5. **File ends after declared number of gates**

### Semantic Validation
1. **Wire IDs form valid dependency graph**
2. **No forward references within levels**
3. **Output IDs are strictly increasing**
4. **Primary input range [0, primary_inputs) is respected**

### Implementation Validation
```rust
// Example validation in reader
if wire_id >= wire_counter {
    return Err(Error::new(ErrorKind::InvalidData, 
        format!("Forward reference: wire {} >= counter {}", wire_id, wire_counter)));
}

if gate.output != wire_counter {
    return Err(Error::new(ErrorKind::InvalidData,
        format!("Output {} != expected counter {}", gate.output, wire_counter)));
}
```

## Edge Cases and Limitations

### Supported Scenarios
- **Empty circuits**: Zero gates, only primary inputs
- **Single-level circuits**: All gates depend only on primary inputs  
- **Large circuits**: Up to 2^61 wires, 2^64 gates
- **Deep circuits**: Unlimited levels

### Limitations
- **Gate types**: Only XOR and AND gates supported
- **Fan-in**: Exactly 2 inputs per gate
- **Fan-out**: Unlimited (wire can be used by multiple gates)
- **Wire reuse**: Wires can be referenced multiple times

### Corner Cases
- **Counter overflow**: Implementations should detect and error on overflow
- **Empty levels**: Levels with 0 gates are valid but discouraged
- **Maximum varints**: 8-byte varints at format limits must be handled correctly
- **Buffer boundaries**: Varint reads spanning buffer boundaries must work correctly

## Backward Compatibility
- Version byte (2) distinguishes v2 from v1 format  
- Completely different encoding, no compatibility with v1 readers
- New format optimized for modern CPU architectures and parallel processing
- Migration tools should be provided to convert between formats
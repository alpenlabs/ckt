# CKT Format v4a Specification

## Overview

Version 4a (v4a) is a **debug and research format** designed for analyzing memory usage patterns in Boolean circuits through an explicit credits system. This format is **NOT used in the production pipeline** - production systems pass credits directly from source to leveller without intermediate serialization. Instead, v4a serves as a standardized format for:

- Debugging credit calculation algorithms from source generators
- Researching memory usage patterns in circuits
- Validating that source formats correctly compute credits
- Academic analysis of circuit structure and wire lifetimes
- Building memory profiling tools
- Cross-checking different circuit synthesis implementations

### Key Features
- **Explicit Credits**: Each gate output includes its usage count computed by source
- **Wire-Based Encoding**: Traditional wire IDs with credit annotations
- **Batch Organization**: Gates packed in batches of 8 for efficient I/O
- **Research Focus**: Optimized for analysis rather than execution
- **Debug Visibility**: Credits visible for validation and profiling

## Credits System Philosophy

Credits represent a fundamental insight: **wire lifetime is known at circuit synthesis time**. The source that generates the circuit knows exactly how many times each wire will be consumed, enabling:

1. **Source Computation**: During synthesis, track wire usage counts
2. **Leveller Optimization**: Free wire_id → (level, index) mappings when credits exhausted
3. **Memory Preallocation**: Slab allocator knows when to free memory
4. **Zero Runtime Allocation**: All memory decisions made at compile time

## Format Structure

### File Layout

```
[Header (66 bytes)]
[Output Wire IDs (variable)]
[GateBatch 0 (variable)]
[GateBatch 1 (variable)]
...
[GateBatch N (variable)]
```

### Header Structure (Fixed Size: 66 bytes)

```rust
struct HeaderV4A {
    version: u8,         // 1 byte: Always 0x04 for v4
    format_type: u8,     // 1 byte: Always 0x00 for TypeA
    checksum: [u8; 32],  // 32 bytes: BLAKE3 hash of all data after checksum
    xor_gates: u64,      // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,      // 8 bytes: Total AND gates (little-endian)
    primary_inputs: u64, // 8 bytes: Number of primary input wires (little-endian)
    num_outputs: u64,    // 8 bytes: Number of output wires (little-endian)
}
```

#### Header Fields

- **version**: Must be `4` to identify v4 format
- **format_type**: Must be `0` to identify TypeA variant (debug/research)
- **checksum**: BLAKE3 hash of all bytes after position 34 (everything after checksum)
- **xor_gates**: Total number of XOR gates in the circuit
- **and_gates**: Total number of AND gates in the circuit
- **primary_inputs**: Number of primary input wires (wires 2 to 2+primary_inputs-1)
- **num_outputs**: Number of circuit outputs

### Output Wire IDs

Immediately following the header, output wire IDs are encoded as StandardVarInts:

```rust
outputs: [StandardVarInt; num_outputs]
```

These identify which wires are circuit outputs and should have credits = 0 (never freed).

## Wire ID Model

### Reserved Wire IDs

```
Wire 0: False constant (credits = MAX, never freed)
Wire 1: True constant (credits = MAX, never freed)  
Wire 2+: User-defined (primary inputs have credits = MAX, gates have computed credits)
```

### Wire Counter

The wire counter tracks the next available wire ID:
- Initialized to `2 + primary_inputs`
- Incremented after each gate output
- Used for relative encoding optimization

## Gate Encoding

### Gate Structure

Each gate is encoded as a sequence of variable-length integers:

```rust
struct EncodedGate {
    in1: FlaggedVarInt,     // Input 1 wire ID
    in2: FlaggedVarInt,     // Input 2 wire ID
    out: FlaggedVarInt,     // Output wire ID
    credits: StandardVarInt, // Usage count computed by source
}
```

### Credits Semantics

Credits MUST be computed by the source during circuit synthesis:

- **credits = 0**: Wire is a final output, never freed
- **credits = 1**: Wire used by exactly one gate, freed after use
- **credits = n**: Wire used by n gates, freed after nth use
- **credits = u32::MAX**: Constants and primary inputs (never freed)

### How Sources Compute Credits

```rust
// During circuit generation, sources must:
fn compute_credits(circuit: &Circuit) -> HashMap<WireId, u32> {
    let mut usage_count = HashMap::new();
    
    // Count how many times each wire is used as input
    for gate in &circuit.gates {
        *usage_count.entry(gate.in1).or_insert(0) += 1;
        *usage_count.entry(gate.in2).or_insert(0) += 1;
    }
    
    // Outputs have credits = 0 (never freed)
    for &output in &circuit.outputs {
        usage_count.insert(output, 0);
    }
    
    // Constants and primary inputs have credits = MAX
    usage_count.insert(0, u32::MAX); // false
    usage_count.insert(1, u32::MAX); // true
    for i in 0..circuit.primary_inputs {
        usage_count.insert(2 + i, u32::MAX);
    }
    
    usage_count
}
```

### FlaggedVarInt Wire Encoding

Wire IDs use FlaggedVarInt with optimized encoding:

- **Flag = 1**: Absolute wire ID
- **Flag = 0**: Relative to current wire counter

This optimizes for common patterns:
- Sequential outputs use relative encoding (small values)
- References to early wires use absolute encoding
- Primary inputs always use absolute encoding

## Batch Structure

### Batch Layout

Gates are grouped into batches of up to 8 gates:

```rust
struct GateBatch {
    gates: Vec<u8>,  // Variable-length encoded gates
    gate_types: u8,  // Bit-packed gate types (8 bits)
}
```

### Gate Type Encoding

The `gate_types` byte uses one bit per gate:
- Bit `i` (0-7) represents the type of gate `i`
- `0` = XOR gate
- `1` = AND gate

Example: `gate_types = 0b10101010` means gates 0,2,4,6 are XOR and gates 1,3,5,7 are AND.

### Partial Batches

The last batch may contain fewer than 8 gates:
- Only bits 0 to (n-1) are valid in gate_types
- Remaining bits should be zero
- Reader uses header gate counts to determine valid gates

## Variable-Length Integer Encoding

### StandardVarInt (for credits and counts)

Standard QUIC varint encoding:

```
Length | Prefix | Data Bits | Range
-------|--------|-----------|-------
1 byte | 00     | 6         | 0-63
2 bytes| 01     | 14        | 64-16,383
4 bytes| 10     | 30        | 16,384-1,073,741,823
8 bytes| 11     | 62        | 1,073,741,824+
```

### FlaggedVarInt (for wire IDs)

Modified QUIC varint with flag bit:

```
Length | Prefix | Flag | Data Bits | Range
-------|--------|------|-----------|-------
1 byte | 00     | f    | 5         | 0-31
2 bytes| 01     | f    | 13        | 32-8,191
4 bytes| 10     | f    | 29        | 8,192-536,870,911
8 bytes| 11     | f    | 61        | 536,870,912+
```

Where `f` is the flag bit (1=absolute, 0=relative).

## Production Pipeline (Why v4a is Bypassed)

The production pipeline passes credits directly from source to leveller:

```
[Source with Credits] → [Leveller] → [Memory Prealloc] → [v4b]
         ↓                    ↓              ↓
   (compute credits)   (use to free     (use for slab
                       wire mappings)     allocation)
```

v4a is bypassed because:
1. **Efficiency**: Avoids serialization/deserialization overhead
2. **Memory**: Leveller can free mappings immediately as credits expire
3. **Speed**: Direct streaming from source to leveller
4. **Integration**: Credits flow naturally through the pipeline

### How Leveller Uses Credits

The leveller maintains a large mapping table:
```rust
// Maps original wire IDs to their level location  
wire_map: HashMap<u64, (level_id, index_in_level)>

// When consuming a wire:
fn consume_wire(wire_id: u64, credits_remaining: &mut HashMap<u64, u32>) {
    let credits = credits_remaining.get_mut(&wire_id).unwrap();
    *credits -= 1;
    
    if *credits == 0 {
        // Critical: free the mapping to save memory
        wire_map.remove(&wire_id);
        credits_remaining.remove(&wire_id);
    }
}
```

For large circuits (billions of gates), this mapping table would consume gigabytes of RAM without credits-based freeing.

## Use Cases for v4a

Despite being bypassed in production, v4a serves important purposes:

### 1. Source Validation
```rust
// Verify source correctly computes credits
let source_credits = source.generate_with_credits();
let validated_credits = recompute_credits(&circuit);
assert_eq!(source_credits, validated_credits);
```

### 2. Memory Profiling
```rust
// Analyze memory usage patterns
let mut peak_memory = 0;
let mut current_memory = 0;

for gate in circuit.gates() {
    // Allocate output
    current_memory += 1;
    peak_memory = peak_memory.max(current_memory);
    
    // Free inputs when credits exhausted
    for input in [gate.in1, gate.in2] {
        if decrement_credits(input) == 0 {
            current_memory -= 1;
        }
    }
}

println!("Peak memory: {} wires", peak_memory);
```

### 3. Research Applications
- Study wire lifetime distributions
- Compare different credit computation strategies
- Analyze circuit depth vs memory usage tradeoffs
- Benchmark memory allocation algorithms

### 4. Debugging Tools
- Visualize credit flow through circuit
- Identify wires with unexpectedly high credits
- Verify outputs have credits = 0
- Cross-check different source implementations

## Implementation Notes

### Writing v4a (Research Tools Only)

```rust
// v4a writer is only for research/debug tools
// Production sources pass credits directly to leveller
let mut writer = v4a::CircuitWriter::new(output, primary_inputs, outputs)?;

// Source must provide credits
for (gate, credits) in source.gates_with_credits() {
    writer.write_gate(Gate {
        in1: gate.input1,
        in2: gate.input2,
        out: gate.output,
        credits, // From source computation
    }, gate.gate_type)?;
}

writer.finish()?;
```

### Reading v4a (Analysis Only)

```rust
// v4a reader is for analysis, not execution
let reader = v4a::CircuitReader::new(input)?;
let mut credit_validator = CreditValidator::new();

while let Some((gate, gate_type)) = reader.next_gate()? {
    // Validate credits match expected usage
    credit_validator.validate_gate(&gate);
    
    // Profile memory patterns
    if gate.credits > 100 {
        println!("High-usage wire: {} with {} consumers", gate.out, gate.credits);
    }
}

credit_validator.report();
```

## Error Handling

### Format Validation

Readers MUST validate:
1. Version byte equals `4`
2. Format type byte equals `0`
3. BLAKE3 checksum matches computed hash
4. Wire IDs are monotonically increasing (recommended)
5. Credits are reasonable (0 ≤ credits ≤ total_gates or MAX for constants)

### Common Issues

1. **Incorrect credits from source**: Off-by-one errors in usage counting
   - Solution: Validate against reference implementation

2. **Missing output marking**: Outputs not marked with credits = 0
   - Solution: Check all outputs in header have credits = 0

3. **Constants without MAX credits**: Constants/inputs freed incorrectly
   - Solution: Ensure wires 0, 1, and primary inputs have MAX credits

## Security Considerations

### Input Validation

Even though v4a is not for production, validate inputs:
- Check for integer overflow in credit values
- Verify wire IDs don't exceed reasonable bounds
- Validate outputs have credits = 0
- Check constants have credits = MAX
- Validate checksum before processing

## Example Circuit

### Circuit Definition

```
Primary inputs: 2 (wires 2, 3)
Gate 0: XOR(2, 3) -> 4 (used by gates 1 and 2, credits = 2)
Gate 1: AND(2, 4) -> 5 (used by gate 2, credits = 1)  
Gate 2: XOR(4, 5) -> 6 (output, credits = 0)
Output: wire 6
```

### Credits Computation by Source

```
Wire 0 (false): credits = MAX (constant)
Wire 1 (true): credits = MAX (constant)
Wire 2 (input): credits = MAX (primary input)
Wire 3 (input): credits = MAX (primary input)
Wire 4: credits = 2 (used by gates 1 and 2)
Wire 5: credits = 1 (used by gate 2)
Wire 6: credits = 0 (output, never freed)
```

### Encoded Format (Conceptual)

```
Header:
  version: 4
  format_type: 0
  checksum: [32 bytes]
  xor_gates: 2
  and_gates: 1
  primary_inputs: 2
  num_outputs: 1

Outputs:
  StandardVarInt(6)

Batch 0:
  Gate 0: FlaggedVarInt(2,absolute), FlaggedVarInt(3,absolute), 
          FlaggedVarInt(4,relative), StandardVarInt(2)
  Gate 1: FlaggedVarInt(2,absolute), FlaggedVarInt(4,relative),
          FlaggedVarInt(5,relative), StandardVarInt(1)
  Gate 2: FlaggedVarInt(4,absolute), FlaggedVarInt(5,relative),
          FlaggedVarInt(6,relative), StandardVarInt(0)
  gate_types: 0b00000010 (bit 1 set for AND gate)
```

## Conclusion

v4a serves as a research and debugging format for understanding credit-based memory management in Boolean circuits. The key insight is that **credits are computed by the source during circuit synthesis** and flow through the pipeline:

1. **Source computes credits** during circuit generation
2. **Credits passed to leveller** (v4a bypassed in production)
3. **Leveller uses credits** to free wire_id → level_location mappings
4. **Slab allocator uses credits** for memory address assignment
5. **v4b contains addresses**, not credits

While production systems bypass v4a entirely, it provides a standardized format for validating credit computation, researching memory patterns, and debugging the sophisticated memory management that enables zero-allocation circuit evaluation.
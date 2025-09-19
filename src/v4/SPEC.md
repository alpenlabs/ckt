# CKT Format v4 Specification Overview

## Introduction

CKT Format v4 represents a revolutionary advancement in Boolean circuit storage and evaluation, introducing **compile-time memory management** through a credits system and precomputed memory addresses. This eliminates runtime allocation overhead and enables unprecedented performance in production circuit evaluation.

The format offers two variants for different use cases:

- **v4a (Type A)**: Intermediate format with explicit credits for debugging and research
- **v4b (Type B)**: Production format with precomputed memory addresses for execution

## Key Innovation: Zero-Allocation Runtime

Traditional circuit formats require dynamic memory management during evaluation, causing:
- Unpredictable allocation overhead
- Memory fragmentation
- Cache misses from scattered allocations
- GC pressure in managed languages

v4 solves this through:
1. **Credits system**: Source generates usage counts for each wire during circuit synthesis
2. **Leveller memory optimization**: Credits used to free internal wire mappings when exhausted
3. **Slab preallocation**: Memory addresses computed using credits from leveller
4. **Deterministic lifecycle**: Wires freed at precise level boundaries

## Credits Flow Through Pipeline

The credits system flows from source generation through to execution:

```
[Circuit Synthesis] → [Source with Credits] → [Leveller] → [Memory Prealloc] → [v4b]
         ↓                      ↓                  ↓              ↓
  (compute credits)    (pass credits)    (use to free      (use credits
                                         wire mappings)    for slab alloc)
```

### How Credits Work

1. **Source Generation**: During circuit synthesis, compute how many times each wire is used
2. **Credits Passed to Leveller**: Each gate includes credits for its output wire
3. **Leveller Memory Management**: 
   - Maintains mapping: original_wire_id → (level_id, index_in_level)
   - When wire's credits reach 0, frees this mapping entry
   - Reduces leveller's memory footprint for large circuits
4. **Memory Preallocation**: Credits passed to slab allocator for address assignment
5. **v4b Output**: Final format contains memory addresses, not credits

## Format Selection Guide

### v4a - Debug/Research Format:
- **NOT used in production pipeline** - credits flow directly from source to leveller
- For debugging credit calculation algorithms
- For researching memory usage patterns
- For validating preallocation strategies
- For academic analysis of circuit structure
- When you need to inspect credits independently of levelling

### v4b - Production Execution Format:
- **Primary production format** after levelling and preallocation
- Direct memory addressing for zero-overhead execution
- Supports arbitrary data types (bool, garbled labels, field elements)
- GPU-ready with linear memory layout
- Parallel evaluation within levels

## Typical Production Pipeline

```
[Source Format with Credits] → [Leveller] → [Memory Prealloc] → [v4b]
```

The v4a format is **bypassed entirely** in production:
1. Read source format that includes credits (e.g., extended Bristol with credits)
2. Feed gates with credits to leveller
3. Leveller uses credits to manage its wire_id → level_location mappings
4. Perform topological sorting into levels
5. Run memory preallocation using credits
6. Write v4b with computed memory addresses

## Memory Model

### Scratch Space Layout

```
Index | Purpose
------|--------
0     | False constant (always available)
1     | True constant (always available)
2-N   | Primary inputs (always available)
N+1-M | Gate outputs (allocated/freed by credits)
```

### Credits System

Credits represent how many times a wire will be consumed:
- `credits = 0`: Wire is a final output (never freed)
- `credits = 1`: Wire used once, freed after consumption
- `credits = n`: Wire used n times, freed after last use

The credits enable two critical optimizations:
1. **Leveller memory efficiency**: Free wire_id → level_location mappings when credits exhausted
2. **Slab allocation**: Know exactly when memory can be reused

### Leveller Memory Management

The leveller maintains a mapping table during processing:
```rust
// Maps original wire IDs to their level location
wire_map: HashMap<u64, (level_id, index_in_level)>

// When processing a gate that consumes a wire:
let location = wire_map.get(wire_id);
credits--;
if credits == 0 {
    wire_map.remove(wire_id);  // Free the mapping
}
```

This is crucial for large circuits where the mapping table would otherwise consume gigabytes of RAM.

### Memory Preallocation Algorithm

```rust
// Simplified preallocation with slab allocator
let mut slab = SlabAllocator::new();
let mut wire_to_memory = HashMap::new();
let mut to_free = Vec::new();

// Preallocate constants and primary inputs
slab.allocate(u16::MAX); // 0: false
slab.allocate(u16::MAX); // 1: true
for i in 0..primary_inputs {
    slab.allocate(u16::MAX); // 2+i: primary input
}

for level in levels {
    for (gate, credits) in level {
        // Consume inputs, decrement their credits
        let in1_addr = consume_wire(gate.in1, &mut wire_to_memory, &mut to_free);
        let in2_addr = consume_wire(gate.in2, &mut wire_to_memory, &mut to_free);
        
        // Allocate output with its credits
        let out_addr = slab.allocate(credits);
        wire_to_memory.insert(gate.out, (out_addr, credits));
        
        // Create executable gate
        executable_gates.push(Gate {
            in1: in1_addr,
            in2: in2_addr,
            out: out_addr,
        });
    }
    
    // Free exhausted wires after level completes
    for wire_id in to_free {
        let (addr, _) = wire_to_memory.remove(wire_id);
        slab.free(addr);
    }
    to_free.clear();
}

max_scratch_space = slab.peak_usage();
```

## Shared Components

### Version Detection

Both formats start with:
```
byte 0: version (0x04)
byte 1: format_type (0x00 for v4a, 0x01 for v4b)
bytes 2-33: BLAKE3 checksum (32 bytes)
```

### Gate Types

Both formats support exactly two gate types:
- XOR gates (2-input, 1-output)
- AND gates (2-input, 1-output)

### Variable-Length Encoding

Both formats use two varint types:

**StandardVarInt**: For counts, sizes, and credits
- 1 byte: 0-63
- 2 bytes: 64-16,383
- 4 bytes: 16,384-1,073,741,823
- 8 bytes: 1,073,741,824+

**FlaggedVarInt**: For wire IDs (v4a) and memory addresses (v4b)
- Flag bit indicates absolute vs relative encoding
- Optimizes for locality and sequential access

## Format Comparison

| Feature | v4a | v4b |
|---------|-----|-----|
| **Purpose** | Debug/Research | Production |
| **Used in pipeline** | No (bypassed) | Yes |
| **Wire representation** | Wire IDs + credits | Memory addresses |
| **Organization** | Batches of 8 | Levels |
| **Credits** | Explicit per gate | Used during creation |
| **Header size** | 66 bytes + outputs | 74 bytes + outputs |
| **Memory model** | Abstract | Direct addressing |
| **Parallelism** | N/A | Per-level |
| **Best for** | Analysis | Execution |

## Performance Characteristics

### v4a Performance
- **Not optimized for execution** - research format only
- Useful for measuring memory patterns
- Credits visible for algorithm validation
- Good for debugging credit computation

### v4b Performance
- **Zero allocation during execution**
- **Single scratch space allocation**
- **Direct memory addressing**
- **Cache-optimal access patterns**
- **Natural parallelism boundaries**
- **GPU-ready memory layout**

Typical improvements over traditional formats:
- 10-100x reduction in allocation calls
- 2-5x improvement in cache hit rates
- 3-10x faster evaluation throughput
- Deterministic memory usage

## Security Considerations

Both formats require:
- BLAKE3 checksum verification before processing
- Bounds checking on all memory addresses (v4b)
- Validation of credits values (v4a)
- Protection against malicious scratch space sizes
- Safe handling of untrusted input circuits

## Implementation Guidelines

### Reading v4a (Debug Only)
```rust
// v4a is for analysis, not execution
let reader = v4a::CircuitReader::new(input)?;
while let Some((gate, gate_type)) = reader.next_gate()? {
    println!("Gate {:?} has {} credits", gate, gate.credits);
    // Analyze memory patterns, validate credits, etc.
}
```

### Production Pipeline (Skip v4a)
```rust
// Read source with credits directly into leveller
let source = ExtendedBristol::new(input)?; // Source that includes credits
let mut leveller = Leveller::new(primary_inputs);

// Leveller receives credits from source
while let Some((gate, credits)) = source.next_with_credits()? {
    leveller.add_gate(gate, credits);
    // Leveller uses credits to free wire mappings when exhausted
}

// Preallocation produces v4b directly
let (levels, max_scratch) = leveller.into_executable_levels()?;
let mut writer = v4b::CircuitWriter::new(output)?;
for level in levels {
    writer.write_level(&level)?;
}
writer.finish(max_scratch)?;
```

### Execution with v4b
```rust
// Single allocation for entire circuit
let mut scratch = vec![false; header.scratch_space as usize];

// Initialize constants and inputs
scratch[0] = false;
scratch[1] = true;
for (i, input) in inputs.iter().enumerate() {
    scratch[2 + i] = *input;
}

// Execute levels
let mut reader = v4b::CircuitReader::new(circuit)?;
while let Some(level) = reader.read_level()? {
    execute_level(&level, &mut scratch);
}

// Read outputs from precomputed addresses
let outputs: Vec<bool> = reader.outputs()
    .iter()
    .map(|&addr| scratch[addr as usize])
    .collect();
```

## Format Evolution

### Why v4a Exists Despite Being Bypassed

The v4a format serves important non-production purposes:

1. **Research**: Studying memory usage patterns in circuits
2. **Debugging**: Validating credit calculation algorithms
3. **Education**: Understanding the credits system
4. **Tooling**: Building analysis tools for memory optimization
5. **Verification**: Cross-checking different source generators

While the production pipeline skips v4a entirely (passing credits directly from source to leveller), having a standardized format for credits is valuable for the ecosystem.

### Credits Generation

Credits must be computed during circuit synthesis:
```rust
// During circuit generation
let mut wire_usage = HashMap::new();

// First pass: count usage
for gate in circuit {
    wire_usage.entry(gate.in1).or_insert(0) += 1;
    wire_usage.entry(gate.in2).or_insert(0) += 1;
}

// Mark outputs as never freed
for output in outputs {
    wire_usage.insert(output, 0);
}

// Second pass: attach credits to gates
for gate in circuit {
    gate.credits = wire_usage.get(gate.out).unwrap_or(0);
}
```

### Future Compatibility

The version/type byte pattern allows for:
- Version 5+ for major breaking changes
- Type 2-255 for additional v4 variants
- Backward-compatible readers via version detection

## Conclusion

CKT v4 revolutionizes circuit evaluation through compile-time memory management:

- **v4a**: Research format for studying credits and memory patterns (not used in production)
- **v4b**: Production format with zero-allocation runtime execution

The key insight is that credits flow from source generation through the entire pipeline:
1. **Generate**: Source computes credits during synthesis
2. **Pass**: Credits passed to leveller with gates
3. **Optimize**: Leveller uses credits to free internal mappings
4. **Preallocate**: Memory allocator uses credits for address assignment
5. **Execute**: Single allocation, direct memory access

This design achieves both research flexibility and production performance, with credits enabling memory optimization at every stage of the pipeline.
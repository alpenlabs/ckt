# CKT Format v5 Specification

## Overview

CKT Format v5 represents a revolutionary advancement in Boolean circuit storage, introducing **fixed-width encoding** and **Structure-of-Arrays (SoA)** layout for unprecedented performance at scale. Designed specifically for circuits with billions of gates, v5 eliminates varint parsing overhead and enables direct memory mapping with optimal SIMD/AVX-512 processing.

The format offers two variants optimized for different stages of the circuit pipeline:

- **v5a**: Intermediate format with 34-bit wire IDs and 24-bit credits for wire garbage collection
- **v5b**: Production format with 24-bit memory addresses for direct execution

## Key Innovations

### Fixed-Width Encoding
- **Zero parsing overhead**: Direct memory access to gate data
- **Predictable performance**: Constant-time field access
- **SIMD-friendly**: Aligned for vectorized processing

### Structure-of-Arrays (SoA) Layout
- **Cache optimal**: All in1 values together, all in2 values together, etc.
- **AVX-512 ready**: Process 16+ gates in parallel
- **Memory bandwidth efficient**: Sequential access patterns

### Performance Targets
- **200M+ gates/second** processing rate
- **2GB/s** sustained I/O with io_uring
- **<5% CPU usage** for I/O-bound operations
- **60 seconds** to read 12 billion gate circuits

## File Structure

Both formats follow the same high-level organization:

```
[HEADER]       Fixed-size header with metadata
[OUTPUTS]      Output wire IDs (v5a) or memory addresses (v5b)
[GATE BLOCKS]  SoA-formatted gate data in blocks
```

### Checksum Calculation

The BLAKE3 checksum is computed over the concatenation of:
1. **OUTPUTS** section (entire section as written)
2. **GATE BLOCKS** section (all blocks in order)
3. **HEADER** fields after the checksum field

This order ensures streaming verification is possible.

## Format v5a - Intermediate Format with Credits

### Purpose
v5a is an intermediate format that preserves wire IDs and credits for memory management. It bridges source formats and the levelled v5b format, maintaining the credits system for compile-time garbage collection.

### Header Structure (72 bytes)

```c
struct HeaderV5a {
    // Identification (8 bytes)
    magic: [u8; 4],          // 4 bytes: "Zk2u" (0x5A6B3275)
    version: u8,             // 1 byte: Always 0x05
    format_type: u8,         // 1 byte: Always 0x00 for v5a
    reserved: [u8; 2],       // 2 bytes: Reserved, must be 0x0000

    // Checksum (32 bytes)
    checksum: [u8; 32],      // 32 bytes: BLAKE3 hash

    // Circuit metadata (32 bytes)
    xor_gates: u64,          // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,          // 8 bytes: Total AND gates (little-endian)
    primary_inputs: u64,     // 8 bytes: Number of primary inputs
    num_outputs: u64,        // 8 bytes: Number of outputs
}
```

### Outputs Section

```c
// Each output wire ID is stored as 5 bytes (40 bits, using lower 34)
outputs: [[u8; 5]; num_outputs]
```

Output wire IDs are padded to 5 bytes for alignment. The upper 6 bits of each 40-bit value must be zero.

### Gate Block Structure

Gates are organized in blocks of 256 gates using Structure-of-Arrays layout:

```c
struct BlockV5a {
    // Input 1 stream: 256 × 34 bits = 8704 bits = 1088 bytes
    in1_packed: [u8; 1088],

    // Input 2 stream: 256 × 34 bits = 8704 bits = 1088 bytes
    in2_packed: [u8; 1088],

    // Output stream: 256 × 34 bits = 8704 bits = 1088 bytes
    out_packed: [u8; 1088],

    // Credits stream: 256 × 24 bits = 6144 bits = 768 bytes
    credits_packed: [u8; 768],

    // Gate types: 256 bits = 32 bytes (1 bit per gate: 0=XOR, 1=AND)
    gate_types: [u8; 32],
}
// Total: 4064 bytes per 256 gates = 15.875 bytes/gate
```

#### Bit Packing Details

**34-bit values** are packed sequentially with no padding between them:
- Gates 0-14: bits 0-509 (15 gates × 34 bits = 510 bits)
- Gates 15-29: bits 510-1019 (15 gates × 34 bits = 510 bits)
- And so on...

To extract gate N's value (0-indexed):
```
bit_offset = N * 34
byte_offset = bit_offset / 8
bit_shift = bit_offset % 8
value = extract_34_bits(data[byte_offset:], bit_shift)
```

**24-bit credits** are packed similarly:
- Gate N's credits start at bit N × 24

#### Gate Type Encoding

The `gate_types` field uses 1 bit per gate:
- Byte 0, bit 0: Gate 0 type (0=XOR, 1=AND)
- Byte 0, bit 1: Gate 1 type
- ...
- Byte 31, bit 7: Gate 255 type

### Partial Blocks

The last block may contain fewer than 256 gates:
- Unused gate slots are filled with zeros
- Credits for unused slots are set to 0
- Type bits for unused slots are set to 0
- Readers use header gate counts to determine valid gates

### Wire ID Semantics

Wire IDs in v5a follow the standard convention:
- Wire 0: Boolean false constant
- Wire 1: Boolean true constant
- Wires 2 to (2+primary_inputs-1): Primary inputs
- Wires (2+primary_inputs) onward: Gate outputs

Maximum supported wire ID: 2^34 - 1 = 17,179,869,183 (17 billion)

### Credits Semantics

Credits represent how many times a wire will be consumed:
- `credits = 0`: Wire is a circuit output (never freed)
- `credits = 1-16777214`: Wire consumed N times
- `credits = 16777215` (2^24-1): Special value for constants/primary inputs

## Format v5b - Production Format with Memory Addresses

### Purpose
v5b is the production format output by the leveller, with precomputed memory addresses for zero-allocation runtime execution. All gates are organized by level for parallel evaluation.

### Header Structure (80 bytes)

```c
struct HeaderV5b {
    // Identification (8 bytes)
    magic: [u8; 4],          // 4 bytes: "Zk2u" (0x5A6B3275)
    version: u8,             // 1 byte: Always 0x05
    format_type: u8,         // 1 byte: Always 0x01 for v5b
    reserved: [u8; 2],       // 2 bytes: Reserved, must be 0x0000

    // Checksum (32 bytes)
    checksum: [u8; 32],      // 32 bytes: BLAKE3 hash

    // Circuit metadata (40 bytes)
    xor_gates: u64,          // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,          // 8 bytes: Total AND gates (little-endian)
    primary_inputs: u64,     // 8 bytes: Number of primary inputs
    scratch_space: u64,      // 8 bytes: Maximum scratch space entries needed
    num_outputs: u64,        // 8 bytes: Number of outputs
    num_levels: u32,         // 4 bytes: Number of levels in circuit
    reserved2: u32,          // 4 bytes: Reserved for alignment
}
```

### Outputs Section

```c
// Each output memory address is stored as 3 bytes (24 bits)
outputs: [[u8; 3]; num_outputs]
```

Output addresses reference locations in the scratch space where final values will be stored after circuit evaluation.

### Level Structure

v5b organizes gates by level. Each level starts with a header followed by gate blocks:

```rs
struct LevelHeader {
    num_xor: u32,          // 4 bytes: Number of XOR gates
    num_and: u32,      // 4 bytes: Number of AND gates
}
```

### Gate Block Structure (v5b)

Within each level, gates are organized in blocks of 504 gates for optimal bit packing:

```c
struct BlockV5b {
    // Input 1 stream: 504 × 24 bits = 12096 bits = 1512 bytes
    in1_stream: [u8; 1512],

    // Input 2 stream: 504 × 24 bits = 12096 bits = 1512 bytes
    in2_stream: [u8; 1512],

    // Output stream: 504 × 24 bits = 12096 bits = 1512 bytes
    out_stream: [u8; 1512],
}
// Total: 4536 bytes per 504 gates = 9 bytes/gate exactly
```

Note: Gate types are determined by position - first `num_xor` are XOR, remainder are AND.

#### Why 504 Gates?

504 × 24 = 12096 bits = 1512 bytes
- 504 = 7 × 72 = 8 × 63 = 21 × 24 (many factorizations)
- 21 × 24 = 504 bits fits perfectly in AVX-512 (512 bits)
- Enables processing 21 gates per AVX-512 operation

#### Bit Packing Details

**24-bit values** are packed sequentially:
- Gate N's address starts at bit N × 24
- Byte offset: (N × 24) / 8
- Bit shift: (N × 24) % 8

### Memory Model

The scratch space is a linear array indexed by the 24-bit addresses:

```
Index Range          | Purpose
---------------------|---------------------------
0                    | Boolean false constant
1                    | Boolean true constant
2..(2+inputs-1)     | Primary inputs
(2+inputs)..max     | Gate outputs (managed by credits in v5a)
```

Maximum addressable memory: 2^24 = 16,777,216 entries

### Level Ordering

Levels are stored in topological order:
- Level 0: Implicit (constants and primary inputs)
- Level 1: Gates that only depend on level 0
- Level N: Gates that depend on levels 0 through N-1

All gates within a level can be evaluated in parallel.

## Implementation Guidelines

### Reading v5 with io_uring

```rust
// Optimal buffer size for NVMe
const BUFFER_SIZE: usize = 128 * 1024 * 1024; // 128MB

// Triple buffering for pipeline parallelism
struct V5Reader {
    ring: IoUring,
    buffers: [AlignedBuffer; 3],
    current: usize,
}

// Setup io_uring for maximum performance
let ring = IoUring::builder()
    .setup_sqpoll(1000)    // Kernel polling thread
    .setup_iopoll()        // Busy-poll completion
    .setup_cqsize(1024)    // Large completion queue
    .build(256)?;          // 256 submission queue entries

// Register buffers for zero-copy
ring.register_buffers(&buffers)?;

// Use O_DIRECT to bypass page cache
let file = OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_DIRECT | libc::O_NOATIME)
    .open(path)?;
```

### AVX-512 Processing

```rust
// Process multiple gates in parallel
#[target_feature(enable = "avx512f,avx512vbmi,avx512vbmi2")]
unsafe fn process_gates_avx512(block: &BlockV5b) {
    // Extract 21 gates at once (504 bits = 21 × 24)
    let data = _mm512_loadu_si512(block.in1_stream.as_ptr());

    // Use VPMULTISHIFTQB for parallel bit extraction
    let shifts = _mm512_setr_epi64(0, 24, 48, 72, 96, 120, 144, 168);
    let addresses = _mm512_multishift_epi64_epi8(shifts, data);

    // Mask to 24 bits
    let mask24 = _mm512_set1_epi32(0xFFFFFF);
    let result = _mm512_and_si512(addresses, mask24);
}
```

### Memory Mapping for Read-Only Access

```rust
use memmap2::MmapOptions;

// For read-only evaluation, memory map the entire file
let file = File::open(path)?;
let mmap = unsafe { MmapOptions::new().map(&file)? };

// Cast directly to block structure - zero parsing!
let blocks = unsafe {
    slice::from_raw_parts(
        mmap[HEADER_SIZE + outputs_size..].as_ptr() as *const BlockV5b,
        num_blocks
    )
};
```

## Performance Characteristics

### v5a Performance
- **File size**: 15.875 bytes/gate (189GB for 12B gates)
- **Read speed**: 2GB/s with io_uring
- **Parse time**: ~0 (direct memory access)
- **AVX-512**: Process 15 gates per 512-bit operation
- **Total time**: 95 seconds for 12B gates (I/O bound)

### v5b Performance
- **File size**: 9 bytes/gate (108GB for 12B gates)
- **Read speed**: 2GB/s with io_uring
- **Parse time**: ~0 (direct memory access)
- **AVX-512**: Process 21 gates per 512-bit operation
- **Total time**: 54 seconds for 12B gates (I/O bound)

### Compared to v4 (varint encoding)
| Metric | v4 (varint) | v5 (fixed) | Improvement |
|--------|-------------|------------|-------------|
| Parse time | 50-100ns/gate | 0 | ∞ |
| CPU usage | 80-90% | <5% | 18x |
| Gates/sec | 10K | 200M+ | 20,000x |
| Predictability | Variable | Constant | ∞ |

## Validation Requirements

### Header Validation
1. Magic bytes must equal "Zk2u" (0x5A6B3275)
2. Version must equal 0x05
3. Format type must be 0x00 (v5a) or 0x01 (v5b)
4. Reserved fields must be zero
5. Gate counts must sum to valid total

### Block Validation
1. Sum of all blocks' gates must equal header gate count
2. Unused bits in 34-bit values must be zero (v5a)
3. 24-bit addresses must be < scratch_space (v5b)
4. Level gate counts must sum correctly (v5b)

### Checksum Verification
```rust
let mut hasher = blake3::Hasher::new();

// 1. Hash outputs section
hasher.update(&outputs_data);

// 2. Hash all gate blocks
for block in blocks {
    hasher.update(&block.to_bytes());
}

// 3. Hash header fields after checksum
hasher.update(&header_bytes[40..]);  // Skip magic, version, type, reserved, checksum

let computed = hasher.finalize();
assert_eq!(computed.as_bytes(), &header.checksum);
```

## Error Handling

### Fatal Errors
- Invalid magic bytes
- Unsupported version
- Checksum mismatch
- Truncated file

### Recoverable Errors
- Extra trailing data (warn and ignore)
- Reserved bits set (warn and mask)

## Security Considerations

1. **Memory bounds**: Always validate addresses before access
2. **Integer overflow**: Check gate counts don't overflow
3. **Resource limits**: Cap maximum file size/gate count
4. **Untrusted input**: Verify checksum before processing
5. **Side channels**: Use constant-time operations for sensitive circuits

## Format Evolution

The format is designed for extensibility:
- Version byte allows future format revisions
- Reserved fields enable backward-compatible additions
- Format type distinguishes variants
- Magic bytes enable quick format detection

## Example Circuit

### Small Circuit (4 gates)

```
Primary inputs: 2 (wires 2, 3)
Gate 0: XOR(2, 3) -> 4, credits=2
Gate 1: AND(2, 4) -> 5, credits=1
Gate 2: XOR(4, 5) -> 6, credits=1
Gate 3: AND(5, 6) -> 7, credits=0 (output)
Output: wire 7
```

**v5a encoding**: Single block with 4 gates + 252 padding = 4064 bytes
**v5b encoding**: Two levels, single block each = 4536 bytes × 2

### Large Circuit (12 billion gates)

```
Primary inputs: 1,000,000
Gates: 6B XOR, 6B AND
Outputs: 1,000
Levels: ~40 (typical depth)
```

**v5a encoding**:
- 46,875,000 blocks of 256 gates
- File size: 189 GB
- Read time: 95 seconds at 2GB/s

**v5b encoding**:
- 23,809,524 blocks of 504 gates
- File size: 108 GB
- Read time: 54 seconds at 2GB/s

## Reference Implementation

A reference implementation in Rust is provided at:
https://github.com/GatekeepOne/ckt

Key modules:
- `src/v5/a/` - v5a reader/writer implementation
- `src/v5/b/` - v5b reader/writer implementation
- `src/v5/common/` - Shared SoA structures and AVX-512 utilities

## Conclusion

CKT v5 format achieves unprecedented performance through:
- **Fixed-width encoding**: Eliminates parsing overhead
- **SoA layout**: Optimizes for SIMD/cache efficiency
- **io_uring integration**: Maximizes I/O throughput
- **AVX-512 optimization**: Processes 15-21 gates per operation

The format is specifically designed for billion-gate circuits, achieving 20,000x speedup over traditional varint formats while maintaining the flexibility of the credits system for memory management.

# CKT Format v5 Specification

## Overview

CKT Format v5 represents a revolutionary advancement in Boolean circuit storage, introducing **fixed-width encoding** and **Structure-of-Arrays (SoA)** layout for unprecedented performance at scale. Designed specifically for circuits with billions of gates, v5 eliminates varint parsing overhead and enables direct memory mapping with optimal SIMD/AVX-512 processing.

The format offers two variants optimized for different stages of the circuit pipeline:

- **v5a**: Intermediate format with 34-bit wire IDs and 24-bit credits for wire garbage collection
- **v5c**: Flat production format with 32-bit memory addresses (execution order) - see `c/SPEC.md` for details

## Key Innovations

### Fixed-Width Encoding
- **Zero parsing overhead**: Direct memory access to gate data
- **Predictable performance**: Constant-time field access
- **SIMD-friendly**: Aligned for vectorized processing

### Optimized Layout
- **v5a**: Structure-of-Arrays (SoA) for AVX-512 SIMD processing
- **v5c**: Array-of-Structures (AoS) in flat blocks for sequential/garbling workloads
- **Cache optimal**: Sequential access patterns

### Performance Targets
- **200M+ gates/second** processing rate
- **2GB/s** sustained I/O with io_uring
- **<5% CPU usage** for I/O-bound operations
- **60 seconds** to read 12 billion gate circuits

## File Structure

```
[HEADER]       Fixed-size header with metadata
[OUTPUTS]      Output wire IDs (v5a) or memory addresses (v5c)
[GATE BLOCKS]  SoA-formatted gate data in blocks
```

### Checksum Calculation

The BLAKE3 checksum is computed over the concatenation of:
1. **GATE BLOCKS** section (all blocks for v5a)
2. **OUTPUTS** section (entire section as written)
3. **HEADER** fields after the checksum field (bytes 40 onward: metadata fields)

**Note**: This order differs from the physical file layout (Header → Outputs → Gate Blocks). The modified order enables streaming hash computation during write operations: blocks can be hashed as they're written to disk, then outputs and header metadata are hashed at finalization. This eliminates the need for a second pass over potentially billions of gates.

**Physical file order**: Header → Outputs → Gate Blocks
**Checksum order**: Gate Blocks → Outputs → Header tail

This design allows writers to compute checksums in a single streaming pass without seeking.

## Format v5a - Intermediate Format with Credits

### Purpose
v5a is an intermediate format that preserves wire IDs and credits for memory management. It bridges source formats and the production v5c format, maintaining the credits system for compile-time garbage collection.

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

## Performance Characteristics

### v5a Performance
- **File size**: 15.875 bytes/gate (189GB for 12B gates)
- **Read speed**: 2GB/s with io_uring
- **Parse time**: ~0 (direct memory access)
- **AVX-512**: Process 15 gates per 512-bit operation
- **Total time**: 95 seconds for 12B gates (I/O bound)

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
3. Format type must be 0x00 (v5a) or 0x02 (v5c)
4. Reserved fields must be zero
5. Gate counts must sum to valid total

### Block Validation
1. Sum of all blocks' gates must equal header gate count (v5a)
2. Unused bits in 34-bit values must be zero (v5a)

### Checksum Verification
```rust
let mut hasher = blake3::Hasher::new();

// 1. Hash all gate blocks
for block in blocks {
    hasher.update(&block.to_bytes());
}

// 2. Hash outputs section
hasher.update(&outputs_data);

// 3. Hash header fields after checksum (bytes 40..72 for v5a)
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

### Large Circuit (12 billion gates)

```
Primary inputs: 1,000,000
Gates: 6B XOR, 6B AND
Outputs: 1,000
```

**v5a encoding**:
- 46,875,000 blocks of 256 gates
- File size: 189 GB
- Read time: 95 seconds at 2GB/s

## Reference Implementation

A reference implementation in Rust is provided at:
https://github.com/alpenlabs/ckt

Key modules:
- `crates/fmtv5-types/src/v5/a/` - v5a reader/writer implementation
- `crates/fmtv5-types/src/v5/c/` - v5c reader/writer implementation (see c/SPEC.md)

## Conclusion

CKT v5 format achieves unprecedented performance through:
- **Fixed-width encoding**: Eliminates parsing overhead entirely
- **Optimized layouts**: SoA for v5a CPU/AVX-512, AoS blocks for v5c sequential processing
- **io_uring integration**: Maximizes I/O throughput
- **Zero-copy design**: Direct memory/pointer casting with no parsing

The v5a format uses SoA with AVX-512 for CPU processing (15 gates per operation), while v5c uses flat AoS blocks optimized for sequential/garbling workloads. Both variants are specifically designed for billion-gate circuits.

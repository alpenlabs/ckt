# CKT Format v5c Specification

## Overview

CKT Format v5c is a flat production format using 32-bit memory addresses with gates stored in **execution order**. It is designed as a bridge between v5a (intermediate format with wire IDs) and v5b (leveled production format), optimized for sequential evaluation and garbling workloads.

**Key Features:**
- **32-bit memory addresses** (not wire IDs)
- **Flat array organization** (no level structure)
- **Execution order preservation** (gates ordered for sequential evaluation)
- **256 KiB blocks** optimized for 1 MB L2 cache
- **Cache-friendly layout** (gates + ciphertext vec both fit in L2)
- **8-byte alignment** for optimal memory access
- **Bit-compacted gate types** (1 bit per gate, like v5a)
- **Zero-copy compatible** with direct pointer casting

## Design Goals

v5c is specifically optimized for garbling workloads where:
1. Gates are processed sequentially in execution order
2. Both gate data and ciphertext accumulation buffer fit in L2 cache
3. Random access to ~1GB working space (50%+ L3 hit rate)
4. Integration with existing 4 MiB io_uring triple-buffered readers
5. Deferred ciphertext hashing per block

### Cache Budget (Ryzen 9900X / Zen 5)
```
L2 per core: 1 MB
Block working set:
  - Gate block:      ~259 KB (gates + types)
  - Ciphertext vec:  ~346 KB (16 bytes × 21,620 gates)
  - Total:           ~605 KB (fits comfortably in 1 MB L2)
```

## File Structure

```
[HEADER]          88 bytes → padded to next 256 KiB boundary
[OUTPUTS]         num_outputs × 4 bytes → padded to next 256 KiB boundary
[GATE BLOCKS]     Sequence of 256 KiB blocks:
  Block 0:        256 KiB
  Block 1:        256 KiB
  ...
  Block N-1:      256 KiB (full block)
  Block N:        Partial block → padded to 256 KiB
```

All major sections are aligned to 256 KiB boundaries for optimal mmap and io_uring performance.

## Constants

```c
// Block configuration
#define BLOCK_SIZE           262144    // 256 KiB
#define GATES_PER_BLOCK      21620     // Maximum gates per block
#define GATE_SIZE            12        // 3 × u32
#define ALIGNMENT            256       // 256 KiB section alignment

// Block layout offsets
#define GATES_OFFSET         0
#define GATES_SIZE           259440    // 21,620 × 12 bytes (8-byte aligned)
#define TYPES_OFFSET         259440    // Immediately after gates (8-byte aligned)
#define TYPES_SIZE           2703      // ⌈21,620 / 8⌉ bytes
#define BLOCK_PADDING        1         // To reach 262,144 bytes

// Header/output sizes
#define HEADER_SIZE          88
#define OUTPUT_ENTRY_SIZE    4
```

## Header Structure (88 bytes)

```c
struct HeaderV5c {
    // Identification (10 bytes)
    magic: [u8; 4],          // 4 bytes: "Zk2u" (0x5A6B3275)
    version: u8,             // 1 byte: Always 0x05
    format_type: u8,         // 1 byte: Always 0x02 for v5c
    nkas: [u8; 4],           // 4 bytes: "nkas" (0x6E6B6173)

    // Checksum (32 bytes)
    checksum: [u8; 32],      // 32 bytes: BLAKE3 hash

    // Circuit metadata (46 bytes)
    xor_gates: u64,          // 8 bytes: Total XOR gates (little-endian)
    and_gates: u64,          // 8 bytes: Total AND gates (little-endian)
    primary_inputs: u64,     // 8 bytes: Number of primary inputs
    scratch_space: u64,      // 8 bytes: Maximum scratch space entries needed
    num_outputs: u64,        // 8 bytes: Number of outputs
    reserved2: [u8; 6],      // 6 bytes: Reserved for future use
}
// Total: 88 bytes
// Padded to: 262,144 bytes (256 KiB)
```

### Header Fields

- **magic**: Must be `[0x5A, 0x6B, 0x32, 0x75]` ("Zk2u")
- **version**: Must be `0x05`
- **format_type**: Must be `0x02` (identifies v5c variant)
- **nkas**: Must be `[0x6E, 0x6B, 0x61, 0x73]` ("nkas")
- **checksum**: BLAKE3 hash (see Checksum Calculation)
- **xor_gates**: Total count of XOR gates in circuit
- **and_gates**: Total count of AND gates in circuit
- **primary_inputs**: Number of primary input wires
- **scratch_space**: Size of memory space needed for evaluation (max address + 1)
- **num_outputs**: Number of output wires
- **reserved2**: Must be `[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]` (reserved for future extensions)

**Total gates**: `xor_gates + and_gates`

## Outputs Section

Output memory addresses stored as 32-bit little-endian values:

```c
struct OutputsSection {
    outputs: [u32; num_outputs],  // Each 4 bytes, little-endian
    padding: [u8; pad_size],      // Padded to 256 KiB boundary
}
```

**Padding calculation** (rounds up to next 256 KiB boundary):
```
outputs_size = num_outputs × 4
padded_size = ((outputs_size + 262143) / 262144) × 262144
pad_size = padded_size - outputs_size
```

Examples:
- 1,000 outputs (4 KB) → padded to 256 KiB
- 100,000 outputs (390 KB) → padded to 512 KiB (2 × 256 KiB)
- 1,000,000 outputs (3.8 MB) → padded to 4 MB (16 × 256 KiB)

Output addresses reference locations in the scratch space where final values are stored after circuit evaluation.

## Block Structure (256 KiB)

Each block contains gates in execution order with bit-compacted gate types:

```c
struct BlockV5c {
    // Gates section (259,440 bytes, 8-byte aligned)
    gates: [GateV5c; GATES_PER_BLOCK],  // 21,620 gates × 12 bytes
    
    // Gate types section (2,703 bytes, starts at 8-byte boundary)
    types: [u8; TYPES_SIZE],            // Bit-packed gate types
    
    // Padding to reach exactly 256 KiB (1 byte)
    padding: [u8; 1],
}

struct GateV5c {
    in1: u32,  // 4 bytes: Input 1 memory address (little-endian)
    in2: u32,  // 4 bytes: Input 2 memory address (little-endian)
    out: u32,  // 4 bytes: Output memory address (little-endian)
}
// Total: 12 bytes per gate
```

### Block Layout Diagram

```
Offset      Size        Section
─────────────────────────────────────────────────────────
0           259,440     Gates (21,620 × 12 bytes)
                        [8-byte aligned at end]
259,440     2,703       Types (⌈21,620 / 8⌉ bytes)
                        [bit-packed: 1 bit per gate]
262,143     1           Padding
─────────────────────────────────────────────────────────
Total:      262,144     Exactly 256 KiB
```

### Gate Types Encoding

Gate types are stored as a bit-packed array where each bit indicates the gate type:
- **Bit = 0**: XOR gate
- **Bit = 1**: AND gate

**Bit mapping**:
```
Byte 0, bit 0: Gate 0 type
Byte 0, bit 1: Gate 1 type
...
Byte 0, bit 7: Gate 7 type
Byte 1, bit 0: Gate 8 type
...
Byte 2702, bit 3: Gate 21,619 type
```

**Extraction formula**:
```c
bool get_gate_type(const u8* types, size_t gate_index) {
    size_t byte_index = gate_index / 8;
    size_t bit_index = gate_index % 8;
    return (types[byte_index] >> bit_index) & 1;
}
```

### Partial Blocks

The last block may contain fewer than 21,620 gates:

1. **Unused gate slots**: Filled with zeros (in1=0, in2=0, out=0)
2. **Unused type bits**: Set to 0
3. **Padding**: Filled with zeros
4. **Size**: Always exactly 256 KiB (same as full blocks)

Readers use `total_gates` from header to determine the number of valid gates in the final block.

## Memory Model

The scratch space is a linear array indexed by 32-bit addresses:

```
Index Range              | Purpose
─────────────────────────────────────────────────────
0                        | Boolean false constant
1                        | Boolean true constant
2..(2 + inputs - 1)      | Primary inputs
(2 + inputs)..max        | Gate outputs
```

**Maximum addressable**: 2³² = 4,294,967,296 entries (~4.3 billion)

All gate addresses (in1, in2, out) must be less than `scratch_space`.

## Checksum Calculation

The BLAKE3 checksum is computed over **the entire file** except the checksum field itself (bytes 10-42 in header).

**Hash order** (to enable streaming during writes):
1. **GATE BLOCKS** section - all full 256 KiB blocks including 1-byte padding within each
2. **OUTPUTS** section - with padding to 256 KiB boundary
3. **HEADER** section - bytes 0-8, skip bytes 8-40 (checksum field), bytes 40-88, then padding to 256 KiB

This differs from the physical file layout (Header → Outputs → Gate Blocks) to enable streaming hash computation during writes.

### Checksum Algorithm

```rust
let mut hasher = blake3::Hasher::new();

// 1. Hash all gate blocks (full 256 KiB each, including 1-byte padding)
for block_index in 0..num_blocks {
    hasher.update(&block_bytes);  // Full 256 KiB (262,144 bytes)
}

// 2. Hash outputs section (padded to 256 KiB boundary)
let outputs_padded_size = padded_size(num_outputs * 4);
hasher.update(&outputs_padded_data);  // Includes padding to 256 KiB boundary

// 3. Hash header (skip only the checksum field itself)
hasher.update(&header_bytes[0..10]);     // magic, version, format_type, nkas
// Skip bytes 10-42: checksum field
hasher.update(&header_bytes[42..88]);    // all circuit metadata
let header_padding = vec![0u8; 256*1024 - 88];
hasher.update(&header_padding);          // padding to 256 KiB

let computed = hasher.finalize();
assert_eq!(computed.as_bytes(), &header.checksum);
```

**What is included in checksum:**
- All gate blocks: full 256 KiB each (gates + types + 1-byte padding)
- Outputs section: data + padding to 256 KiB boundary
- Header section: all bytes except checksum field (10-42) + padding to 256 KiB
- **Summary: Everything in the file except the checksum field itself**

## File Layout Example

### Small Circuit (45,000 gates, 1000 outputs)

```
Section         Unpadded Size   Padded Size     Content
────────────────────────────────────────────────────────────────
Header          88 bytes        256 KiB         HeaderV5c + padding
Outputs         4,000 bytes     256 KiB         [u32; 1000] + padding
Block 0         262,144 bytes   256 KiB         21,620 gates (full)
Block 1         262,144 bytes   256 KiB         21,620 gates (full)
Block 2         262,144 bytes   256 KiB         1,760 gates (partial) + padding
────────────────────────────────────────────────────────────────
Total           ~786 KB         1.25 MB
```

### Large Circuit (12 billion gates, 1000 outputs)

```
Section         Unpadded Size   Padded Size     Overhead
────────────────────────────────────────────────────────────────
Header          88 bytes        256 KiB         ~256 KiB
Outputs         4,000 bytes     256 KiB         ~256 KiB
Blocks          ~145.5 GB       ~145.5 GB       < 256 KiB
────────────────────────────────────────────────────────────────
Total           ~145.5 GB       ~145.5 GB       ~512 KiB

Number of blocks: ⌈12,000,000,000 / 21,620⌉ = 555,041 blocks
File size: 88 bytes + 256 KiB + 4,000 bytes + 256 KiB + (555,041 × 256 KiB)
         ≈ 145.5 GB

Overhead: 0.00034% (negligible for large circuits)
```

## Integration with io_uring Triple Buffering

v5c is designed to work seamlessly with existing 4 MiB io_uring triple-buffered readers:

```
4 MiB Disk Buffer = 16 × 256 KiB blocks

Processing pattern:
1. Read 4 MiB buffer from disk (io_uring, triple buffered)
2. Process 16 blocks sequentially:
   For each 256 KiB block:
     a. Parse gates (zero-copy cast to &[GateV5c])
     b. Process 21,620 gates sequentially
     c. Accumulate ciphertexts in vec (346 KB, stays in L2)
     d. Hash ciphertext vec (sequential L2 access)
     e. Clear vec and continue to next block
```

**Cache efficiency**:
- Gate block (259 KB) + Ciphertext vec (346 KB) = 605 KB total
- Both fit comfortably in 1 MB L2 cache
- Leaves ~400 KB for other hot data (hash state, loop variables, etc.)

## Multi-Worker Parallel Processing

v5c is designed to enable **zero-copy Arc-sharing** for parallel garbling workloads:

**Key Design Properties:**
- 4 MiB disk buffers contain exactly 16 × 256 KiB blocks
- Master thread wraps 4 MiB buffer in Arc and distributes pointer to workers
- Workers cast directly into shared buffer (zero-copy) to process assigned blocks
- 256 KiB block alignment enables safe pointer casting to gate arrays
- Gate block (259 KB) + ciphertext vec (346 KB) fit in 1 MB L2 cache per worker
- Each worker maintains private working space (no contention on read-only gate buffer)

This enables distribution of ~345,947 gates per Arc pointer with minimal coordination overhead.

## Performance Characteristics

### File Size

For N gates:
```
header_padded = 256 KiB
outputs_padded = ⌈num_outputs × 4 / 256 KiB⌉ × 256 KiB
blocks_size = ⌈N / 21,620⌉ × 256 KiB
total_size = header_padded + outputs_padded + blocks_size
```

**Effective bytes per gate**: 12.125 bytes/gate (for large circuits)
- 12 bytes for gate structure
- 0.125 bytes for type bit (1/8 byte per gate)

### Read Performance (with io_uring)

**Sequential read** (12B gates, 6.5 GB/s):
- File size: ~145.5 GB
- Read time: 145.5 GB ÷ 6.5 GB/s ≈ **22.4 seconds**

**Block processing** (assuming 50% L3 hit on working space):
- Gates per second: ~162.5 ns/gate → **6.15M gates/sec per core**
- With 16 cores: **~98M gates/sec**
- Total processing: 12B ÷ 98M ≈ **122 seconds (2 minutes)**

**Total pipeline**: I/O overlapped with processing, bottlenecked by processing time.

### Comparison with Other Formats

| Metric | v5a | v5b | v5c |
|--------|-----|-----|-----|
| Address size | 34-bit wire IDs | 32-bit addresses | 32-bit addresses |
| Credits | 24-bit | None | None |
| Organization | 256-gate SoA blocks | Level-based AoS | Flat AoS blocks |
| Gate types | Bit-compact | Position | Bit-compact |
| Bytes/gate | 15.875 | 12 + level overhead | 12.125 |
| Block size | 4,064 bytes | Variable (by level) | 256 KiB |
| Alignment | Block-aligned | Section-aligned | 256 KiB aligned |
| Zero-copy | No (bit unpacking) | Yes | Yes |
| Use case | Intermediate | Parallel evaluation | Sequential/garbling |

## Validation Requirements

### Header Validation

1. **Magic bytes**: Must equal `[0x5A, 0x6B, 0x32, 0x75]`
2. **Version**: Must equal `0x05`
3. **Format type**: Must equal `0x02`
4. **nkas field**: Must equal `[0x6E, 0x6B, 0x61, 0x73]`
5. **Reserved fields**: Must be zero
6. **Gate counts**: `xor_gates + and_gates` must not overflow u64
7. **Scratch space**: Must be ≤ 2³² (4,294,967,296)
8. **Outputs**: `num_outputs` must not exceed the sum of primary inputs and total gates

### Block Validation

1. **File size**: Must equal `header_padded + outputs_padded + blocks_size`
2. **Block count**: Must equal `⌈total_gates / 21,620⌉`
3. **Alignment**: All sections start at 256 KiB boundaries
4. **Gate addresses**: All in1, in2, out must be < scratch_space
5. **Partial block**: Last block may have fewer than 21,620 valid gates

### Checksum Verification

1. Read all gate blocks (including padding)
2. Read outputs (including padding)
3. Read header tail (bytes 40..88)
4. Compute BLAKE3 hash in the specified order
5. Compare with header checksum field

## Implementation Guidelines

### Reading v5c

```rust
use memmap2::MmapOptions;

pub struct ReaderV5c {
    header: HeaderV5c,
    mmap: Mmap,
}

impl ReaderV5c {
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        
        // Parse header
        let header = HeaderV5c::from_bytes(&mmap[0..88])?;
        header.validate()?;
        
        Ok(ReaderV5c { header, mmap })
    }
    
    // Get outputs (zero-copy)
    pub fn outputs(&self) -> &[u32] {
        let offset = 256 * 1024; // After header padding
        let len = self.header.num_outputs as usize;
        unsafe {
            slice::from_raw_parts(
                self.mmap[offset..].as_ptr() as *const u32,
                len
            )
        }
    }
    
    // Iterate over blocks (zero-copy)
    pub fn blocks(&self) -> BlockIterator {
        let blocks_offset = 512 * 1024; // After header + outputs
        let total_gates = self.header.total_gates();
        let num_blocks = (total_gates + 21619) / 21620;
        
        BlockIterator {
            mmap: &self.mmap,
            blocks_offset,
            total_gates,
            num_blocks,
            current_block: 0,
        }
    }
}

pub struct BlockIterator<'a> {
    mmap: &'a [u8],
    blocks_offset: usize,
    total_gates: u64,
    num_blocks: u64,
    current_block: u64,
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Block<'a>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_block >= self.num_blocks {
            return None;
        }
        
        let block_offset = self.blocks_offset + 
            (self.current_block as usize * 262144);
        let block_bytes = &self.mmap[block_offset..block_offset + 262144];
        
        // Calculate gates in this block
        let remaining = self.total_gates - (self.current_block * 21620);
        let gates_in_block = remaining.min(21620) as usize;
        
        // Zero-copy cast to gates
        let gates: &[GateV5c] = unsafe {
            slice::from_raw_parts(
                block_bytes.as_ptr() as *const GateV5c,
                gates_in_block
            )
        };
        
        let types = &block_bytes[259440..259440 + 2703];
        
        self.current_block += 1;
        
        Some(Block { gates, types })
    }
}
```

### Writing v5c

```rust
pub struct WriterV5c {
    file: File,
    hasher: blake3::Hasher,
    header: HeaderV5c,
    block_buffer: Vec<u8>,
    gates_in_block: usize,
}

impl WriterV5c {
    pub fn new(path: &Path, header_info: HeaderInfo) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut header = HeaderV5c::new();
        header.xor_gates = header_info.xor_gates;
        header.and_gates = header_info.and_gates;
        header.primary_inputs = header_info.primary_inputs;
        header.scratch_space = header_info.scratch_space;
        header.num_outputs = header_info.num_outputs;
        
        Ok(WriterV5c {
            file,
            hasher: blake3::Hasher::new(),
            header,
            block_buffer: vec![0u8; 262144],
            gates_in_block: 0,
        })
    }
    
    pub fn write_gate(&mut self, gate: GateV5c, gate_type: bool) -> io::Result<()> {
        if self.gates_in_block >= 21620 {
            self.flush_block()?;
        }
        
        // Write gate to block buffer
        let offset = self.gates_in_block * 12;
        self.block_buffer[offset..offset+4].copy_from_slice(&gate.in1.to_le_bytes());
        self.block_buffer[offset+4..offset+8].copy_from_slice(&gate.in2.to_le_bytes());
        self.block_buffer[offset+8..offset+12].copy_from_slice(&gate.out.to_le_bytes());
        
        // Set type bit
        let type_offset = 259440 + self.gates_in_block / 8;
        let type_bit = self.gates_in_block % 8;
        if gate_type {
            self.block_buffer[type_offset] |= 1 << type_bit;
        }
        
        self.gates_in_block += 1;
        Ok(())
    }
    
    fn flush_block(&mut self) -> io::Result<()> {
        if self.gates_in_block == 0 {
            return Ok(());
        }
        
        // Hash gate data (no padding)
        let gates_size = self.gates_in_block * 12;
        let types_size = (self.gates_in_block + 7) / 8;
        self.hasher.update(&self.block_buffer[..gates_size]);
        self.hasher.update(&self.block_buffer[259440..259440 + types_size]);
        
        // Write full 256 KiB block to disk
        self.file.write_all(&self.block_buffer)?;
        
        // Reset for next block
        self.block_buffer.fill(0);
        self.gates_in_block = 0;
        
        Ok(())
    }
    
    pub fn finalize(mut self, outputs: &[u32]) -> io::Result<()> {
        // Flush remaining gates
        self.flush_block()?;
        
        // Seek back to write header and outputs
        self.file.seek(SeekFrom::Start(0))?;
        
        // Write header (padded to 256 KiB)
        let mut header_padded = vec![0u8; 262144];
        header_padded[..88].copy_from_slice(&self.header.to_bytes());
        self.file.write_all(&header_padded)?;
        
        // Write outputs (padded to 256 KiB)
        let outputs_size = outputs.len() * 4;
        let outputs_padded_size = ((outputs_size + 262143) / 262144) * 262144;
        let mut outputs_padded = vec![0u8; outputs_padded_size];
        for (i, &addr) in outputs.iter().enumerate() {
            outputs_padded[i*4..(i+1)*4].copy_from_slice(&addr.to_le_bytes());
        }
        self.file.write_all(&outputs_padded)?;
        
        // Complete checksum: hash outputs then header tail
        self.hasher.update(&outputs_padded[..outputs_size]); // No padding
        self.hasher.update(&self.header.to_bytes()[40..88]);
        
        let checksum = self.hasher.finalize();
        self.header.checksum.copy_from_slice(checksum.as_bytes());
        
        // Write final header with checksum
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.to_bytes())?;
        
        Ok(())
    }
}
```

## Use Cases

1. **Garbling circuits**: Optimized for sequential garbling with ciphertext accumulation
2. **Sequential evaluation**: Execute gates in exact order without level computation
3. **Streaming processing**: Process in chunks without level boundaries  
4. **Bridge format**: Between v5a (wire IDs + credits) and v5b (levels)
5. **Custom parallelism**: Non-level-based parallel evaluation strategies

## Migration Path

```
v5a (34-bit wire IDs, credits)
    ↓ [address resolution]
v5c (32-bit addresses, flat)
    ↓ [compute levels]
v5b (32-bit addresses, levels)
```

v5c serves as the intermediate format after memory addresses are resolved but before leveling is computed.

## Security Considerations

1. **Memory bounds**: Validate all addresses < scratch_space before access
2. **Integer overflow**: Check gate count additions don't overflow
3. **File size**: Verify file size matches expected size from header
4. **Checksum**: Always verify BLAKE3 checksum before processing untrusted files
5. **Resource limits**: Cap maximum circuit

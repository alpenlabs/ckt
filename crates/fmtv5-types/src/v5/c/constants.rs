/// Block size for v5c format (256 KiB)
pub const BLOCK_SIZE: usize = 256 * 1024; // 262,144 bytes

/// Maximum gates per block (calculated to fit in BLOCK_SIZE with alignment)
pub const GATES_PER_BLOCK: usize = 21_620;

/// Block layout offsets and sizes
pub const GATES_OFFSET: usize = 0;
pub const GATES_SIZE: usize = GATES_PER_BLOCK * GATE_SIZE; // 259,440 bytes
pub const TYPES_OFFSET: usize = GATES_SIZE; // 259,440
pub const TYPES_SIZE: usize = GATES_PER_BLOCK.div_ceil(8); // 2,703 bytes
pub const BLOCK_PADDING: usize = BLOCK_SIZE - GATES_SIZE - TYPES_SIZE; // 1 byte

/// Size of a single gate (3 × u32 LE)
pub const GATE_SIZE: usize = 12;

/// Header size
pub const HEADER_SIZE: usize = 88;

/// Output entry size (u32 LE)
pub const OUTPUT_ENTRY_SIZE: usize = 4;

/// Section alignment (256 KiB)
pub const ALIGNMENT: usize = 256 * 1024;

/// Magic bytes for v5 format: "Zk2u"
pub const MAGIC: [u8; 4] = crate::v5::MAGIC;

/// Version number
pub const VERSION: u8 = crate::v5::VERSION;

/// Format type for v5c
pub const FORMAT_TYPE: u8 = 0x02;

/// Secondary magic bytes: "nkas"
pub const NKAS: [u8; 4] = [0x6E, 0x6B, 0x61, 0x73];

/// Maximum addressable memory (2^32)
pub const MAX_MEMORY_ADDRESS: u64 = 4_294_967_296;

/// Disk I/O buffer size (for integration with io_uring triple buffering)
pub const DISK_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Number of processing blocks per disk buffer
pub const BLOCKS_PER_DISK_BUFFER: usize = DISK_BUFFER_SIZE / BLOCK_SIZE; // 16

/// Expected ciphertext vector capacity per block (for garbling)
pub const CIPHERTEXTS_PER_BLOCK: usize = GATES_PER_BLOCK;

/// Expected ciphertext vector size in bytes (16 bytes per ciphertext)
pub const CIPHERTEXT_VEC_SIZE: usize = CIPHERTEXTS_PER_BLOCK * 16; // 346,320 bytes

// Compile-time assertions
const _: () = assert!(GATES_SIZE + TYPES_SIZE + BLOCK_PADDING == BLOCK_SIZE);
const _: () = assert!(
    GATES_SIZE.is_multiple_of(8),
    "Gates size must be 8-byte aligned"
);
const _: () = assert!(
    TYPES_OFFSET.is_multiple_of(8),
    "Types must start at 8-byte boundary"
);
const _: () = assert!(BLOCKS_PER_DISK_BUFFER == 16);
const _: () = assert!(
    CIPHERTEXT_VEC_SIZE < 512 * 1024,
    "Ciphertext vec should be < 512 KB"
);
const _: () = assert!(
    GATES_SIZE + CIPHERTEXT_VEC_SIZE < 1024 * 1024,
    "Gate block + ciphertext vec must fit in 1 MB L2"
);

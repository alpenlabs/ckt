use std::cmp::Ordering;
/// A compact 34-bit wire identifier stored in 5 bytes.
///
/// Wire IDs are used throughout the levelling algorithm to identify circuit wires.
/// The 34-bit representation (2^34 = ~17 billion wires) is sufficient for large circuits
/// while saving memory compared to 64-bit IDs.
///
/// # Bit Layout
/// - Bytes 0-3: Lower 32 bits
/// - Byte 4 (bits 0-1): Upper 2 bits (total 34 bits)
/// - Byte 4 (bits 2-7): Unused (always zero)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactWireId([u8; 5]);

impl CompactWireId {
    /// Creates a CompactWireId from a u64, masking to 34 bits.
    ///
    /// Values exceeding 34 bits (> 0x3_FFFF_FFFF) are truncated.
    pub fn from_u64(value: u64) -> Self {
        // Mask to ensure we only use 34 bits (0x3_FFFF_FFFF)
        let masked_value = value & 0x3_FFFF_FFFF;

        let bytes = [
            (masked_value & 0xFF) as u8,
            ((masked_value >> 8) & 0xFF) as u8,
            ((masked_value >> 16) & 0xFF) as u8,
            ((masked_value >> 24) & 0xFF) as u8,
            ((masked_value >> 32) & 0x3) as u8, // Only 2 bits for the 5th byte
        ];

        Self(bytes)
    }

    /// Converts the CompactWireId back to a u64.
    ///
    /// The result is always in the range [0, 0x3_FFFF_FFFF] (34 bits).
    pub fn to_u64(&self) -> u64 {
        (self.0[0] as u64)
            | ((self.0[1] as u64) << 8)
            | ((self.0[2] as u64) << 16)
            | ((self.0[3] as u64) << 24)
            | (((self.0[4] as u64) & 0x3) << 32) // ensure only 2 bits contribute
    }

    /// Returns a reference to the raw 5-byte representation.
    ///
    /// # Layout
    /// - Bytes 0-3: Lower 32 bits of the wire ID
    /// - Byte 4: Upper 2 bits (bits 0-1), with bits 2-7 always zero
    ///
    /// # Invariant
    /// The 5th byte (index 4) is always in the range 0-3 (only lower 2 bits set).
    pub fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }
}

impl Ord for CompactWireId {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        use core::cmp::Ordering::*;
        for i in (0..5).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Equal => continue,
                non_eq => return non_eq,
            }
        }
        Equal
    }
}

impl PartialOrd for CompactWireId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for CompactWireId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WireId({})", self.to_u64())
    }
}

//! Gate type enum shared across format variants.

/// Gate type with direct conversions between single bits.
///
/// The discriminant values match the bit encoding used in the v5c format:
/// - XOR = 0 (bit unset)
/// - AND = 1 (bit set)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GateType {
    XOR = 0,
    AND = 1,
}

impl GateType {
    /// Create a `GateType` from a bit value.
    ///
    /// This is a zero-cost conversion that directly transmutes the bit.
    #[inline]
    pub const fn from_bit(bit: bool) -> Self {
        // SAFETY: bool is guaranteed to be 0 or 1, which matches our repr(u8) discriminants
        unsafe { std::mem::transmute(bit as u8) }
    }

    /// Convert to a bit value.
    ///
    /// Returns `false` for XOR, `true` for AND.
    #[inline]
    pub const fn to_bit(self) -> bool {
        self as u8 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_type_bit_conversions() {
        assert_eq!(GateType::from_bit(false), GateType::XOR);
        assert_eq!(GateType::from_bit(true), GateType::AND);

        assert!(!GateType::XOR.to_bit());
        assert!(GateType::AND.to_bit());
    }
}

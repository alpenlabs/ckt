//! Variable-length integer encoding for CKT v4a format
//!
//! Implements two varint types with optimized branchless decoding:
//! - StandardVarInt: Standard QUIC varint encoding for credits and counts
//! - FlaggedVarInt: Modified QUIC varint for wire IDs
//!   - Flag=1: Absolute wire ID
//!   - Flag=0: Relative to current wire counter

use cynosure::hints::{likely, unlikely};
use std::io::{Error, ErrorKind, Result};

/// Standard QUIC-style varint for credits and header fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardVarInt(u64);

impl StandardVarInt {
    /// Maximum value that can be encoded (2^62 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 62) - 1;

    /// Create a new StandardVarInt
    #[inline]
    pub fn new(value: u64) -> Result<Self> {
        if unlikely(value > Self::MAX_VALUE) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(StandardVarInt(value))
    }

    /// Get the raw value
    #[inline(always)]
    pub fn value(self) -> u64 {
        self.0
    }

    /// Encode to byte slice and return number of bytes used
    #[inline]
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.0;

        if likely(value < (1u64 << 6)) {
            // 1 byte: 00xxxxxx
            if unlikely(buffer.is_empty()) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = value as u8;
            Ok(1)
        } else if likely(value < (1u64 << 14)) {
            // 2 bytes: 01xxxxxx xxxxxxxx
            if unlikely(buffer.len() < 2) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x40 | ((value >> 8) as u8);
            buffer[1] = value as u8;
            Ok(2)
        } else if likely(value < (1u64 << 30)) {
            // 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 4) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x80 | ((value >> 24) as u8);
            buffer[1] = (value >> 16) as u8;
            buffer[2] = (value >> 8) as u8;
            buffer[3] = value as u8;
            Ok(4)
        } else {
            // 8 bytes: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 8) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0xC0 | ((value >> 56) as u8);
            buffer[1] = (value >> 48) as u8;
            buffer[2] = (value >> 40) as u8;
            buffer[3] = (value >> 32) as u8;
            buffer[4] = (value >> 24) as u8;
            buffer[5] = (value >> 16) as u8;
            buffer[6] = (value >> 8) as u8;
            buffer[7] = value as u8;
            Ok(8)
        }
    }

    /// Decode from byte slice and return (varint, bytes_consumed)
    /// Uses branchless length computation for optimal performance
    #[inline]
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize)> {
        if unlikely(buffer.is_empty()) {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Empty buffer"));
        }

        let first = buffer[0];

        // Branchless length computation: 00->1, 01->2, 10->4, 11->8
        let length = 1 << (first >> 6);

        // Branchless mask computation: 0xxxxxxx->0x7F, others->0x3F
        // Note: StandardVarInt always uses 6 value bits in first byte for 2/4/8 byte encodings
        let mask = 0x3F;

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let mut value = (first & mask) as u64;

        // Unroll small loops for better performance
        unsafe {
            match length {
                1 => {
                    // value already set correctly from (first & mask)
                }
                2 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                }
                4 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(2) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(3) as u64);
                }
                8 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(2) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(3) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(4) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(5) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(6) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(7) as u64);
                }
                _ => unreachable!(),
            }
        }

        Ok((StandardVarInt(value), length))
    }

    /// Get the encoded size in bytes for a given value
    #[inline(always)]
    pub fn encoded_size(value: u64) -> usize {
        if value < (1u64 << 6) {
            1
        } else if value < (1u64 << 14) {
            2
        } else if value < (1u64 << 30) {
            4
        } else {
            8
        }
    }
}

/// Flagged varint for wire ID encoding
/// In v4a context:
/// - Flag=1 means absolute wire ID
/// - Flag=0 means relative to current wire counter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggedVarInt {
    value: u64,
    flag: bool,
}

impl FlaggedVarInt {
    /// Maximum value that can be encoded (2^61 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 61) - 1;

    /// Create a FlaggedVarInt with absolute wire ID
    #[inline]
    pub fn absolute(wire_id: u64) -> Result<Self> {
        if unlikely(wire_id > Self::MAX_VALUE) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Wire ID {} exceeds maximum {}", wire_id, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: wire_id,
            flag: true, // Flag=1 for absolute
        })
    }

    /// Create a FlaggedVarInt with relative offset from wire counter
    #[inline]
    pub fn relative(offset: u64) -> Result<Self> {
        if unlikely(offset > Self::MAX_VALUE) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Offset {} exceeds maximum {}", offset, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: offset,
            flag: false, // Flag=0 for relative
        })
    }

    /// Create a new FlaggedVarInt with specified flag
    #[inline]
    pub fn with_flag(value: u64, flag: bool) -> Result<Self> {
        if unlikely(value > Self::MAX_VALUE) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt { value, flag })
    }

    /// Get the flag value
    #[inline(always)]
    pub fn flag(self) -> bool {
        self.flag
    }

    /// Get the raw value
    #[inline(always)]
    pub fn value(self) -> u64 {
        self.value
    }

    /// Check if this is an absolute wire ID
    #[inline(always)]
    pub fn is_absolute(self) -> bool {
        self.flag
    }

    /// Check if this is relative to wire counter
    #[inline(always)]
    pub fn is_relative(self) -> bool {
        !self.flag
    }

    /// Encode to byte slice and return number of bytes used
    #[inline]
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.value;
        let flag_bit = if self.flag { 0x20u8 } else { 0u8 }; // Pre-compute shifted flag

        if likely(value < (1u64 << 5)) {
            // 1 byte: 00fxxxxx (f = flag bit)
            if unlikely(buffer.is_empty()) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = (value as u8) | flag_bit;
            Ok(1)
        } else if likely(value < (1u64 << 13)) {
            // 2 bytes: 01fxxxxx xxxxxxxx
            if unlikely(buffer.len() < 2) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x40 | flag_bit | ((value >> 8) as u8);
            buffer[1] = value as u8;
            Ok(2)
        } else if likely(value < (1u64 << 29)) {
            // 4 bytes: 10fxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 4) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x80 | flag_bit | ((value >> 24) as u8);
            buffer[1] = (value >> 16) as u8;
            buffer[2] = (value >> 8) as u8;
            buffer[3] = value as u8;
            Ok(4)
        } else {
            // 8 bytes: 11fxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 8) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0xC0 | flag_bit | ((value >> 56) as u8);
            buffer[1] = (value >> 48) as u8;
            buffer[2] = (value >> 40) as u8;
            buffer[3] = (value >> 32) as u8;
            buffer[4] = (value >> 24) as u8;
            buffer[5] = (value >> 16) as u8;
            buffer[6] = (value >> 8) as u8;
            buffer[7] = value as u8;
            Ok(8)
        }
    }

    /// Decode from byte slice and return (varint, bytes_consumed)
    /// Uses branchless decoding for optimal performance
    #[inline]
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize)> {
        if unlikely(buffer.is_empty()) {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Empty buffer"));
        }

        let first = buffer[0];

        // Branchless length computation: 00->1, 01->2, 10->4, 11->8
        let length = 1 << (first >> 6);

        // Extract flag bit (bit 5)
        let flag = (first & 0x20) != 0;

        // Value mask is always 0x1F (5 bits) for FlaggedVarInt
        const VALUE_MASK: u8 = 0x1F;

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let mut value = (first & VALUE_MASK) as u64;

        // Unroll loops for better performance
        unsafe {
            match length {
                1 => {
                    // value already set from first byte
                }
                2 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                }
                4 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(2) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(3) as u64);
                }
                8 => {
                    value = (value << 8) | (*buffer.get_unchecked(1) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(2) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(3) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(4) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(5) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(6) as u64);
                    value = (value << 8) | (*buffer.get_unchecked(7) as u64);
                }
                _ => unreachable!(),
            }
        }

        Ok((FlaggedVarInt { value, flag }, length))
    }

    /// Get the encoded size in bytes for a given value
    #[inline(always)]
    pub fn encoded_size(value: u64) -> usize {
        if value < (1u64 << 5) {
            1
        } else if value < (1u64 << 13) {
            2
        } else if value < (1u64 << 29) {
            4
        } else {
            8
        }
    }

    /// Encode a wire ID relative to the current wire counter
    /// Chooses optimal encoding (absolute vs relative) based on value sizes
    #[inline]
    pub fn encode_wire_id(wire_id: u64, wire_counter: u64, buffer: &mut [u8]) -> Result<usize> {
        // Choose the most efficient encoding
        // Use relative if the offset is smaller than the absolute value
        if wire_id <= wire_counter {
            let offset = wire_counter - wire_id;
            if offset < wire_id {
                // Relative encoding is more efficient
                let varint = FlaggedVarInt::relative(offset)?;
                return varint.encode(buffer);
            }
        }

        // Absolute encoding
        let varint = FlaggedVarInt::absolute(wire_id)?;
        varint.encode(buffer)
    }

    /// Decode a wire ID given the current wire counter
    #[inline]
    pub fn decode_wire_id(buffer: &[u8], wire_counter: u64) -> Result<(u64, usize)> {
        let (varint, consumed) = FlaggedVarInt::decode(buffer)?;

        let wire_id = if varint.is_absolute() {
            varint.value
        } else {
            // Relative offset from wire counter
            if unlikely(varint.value > wire_counter) {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Relative offset {} exceeds wire counter {}",
                        varint.value, wire_counter
                    ),
                ));
            }
            wire_counter - varint.value
        };

        Ok((wire_id, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_varint_encode_decode() -> Result<()> {
        let test_values = vec![
            0,
            63,         // 1 byte boundary
            64,         // 2 bytes
            16383,      // 2 byte boundary
            16384,      // 4 bytes
            1073741823, // 4 byte boundary
            1073741824, // 8 bytes
            StandardVarInt::MAX_VALUE,
        ];

        for value in test_values {
            let varint = StandardVarInt::new(value)?;
            let mut buffer = [0u8; 8];
            let encoded_size = varint.encode(&mut buffer)?;
            assert_eq!(encoded_size, StandardVarInt::encoded_size(value));

            let (decoded, consumed) = StandardVarInt::decode(&buffer)?;
            assert_eq!(decoded.value(), value);
            assert_eq!(consumed, encoded_size);
        }

        Ok(())
    }

    #[test]
    fn test_flagged_varint_encode_decode() -> Result<()> {
        // Test absolute encoding
        let absolute = FlaggedVarInt::absolute(12345)?;
        assert!(absolute.is_absolute());
        assert!(!absolute.is_relative());

        let mut buffer = [0u8; 8];
        let size = absolute.encode(&mut buffer)?;
        let (decoded, consumed) = FlaggedVarInt::decode(&buffer)?;
        assert_eq!(consumed, size);
        assert_eq!(decoded.value, 12345);
        assert!(decoded.is_absolute());

        // Test relative encoding
        let relative = FlaggedVarInt::relative(100)?;
        assert!(relative.is_relative());
        assert!(!relative.is_absolute());

        let size = relative.encode(&mut buffer)?;
        let (decoded, consumed) = FlaggedVarInt::decode(&buffer)?;
        assert_eq!(consumed, size);
        assert_eq!(decoded.value, 100);
        assert!(decoded.is_relative());

        Ok(())
    }

    #[test]
    fn test_wire_id_encoding() -> Result<()> {
        let wire_counter = 1000u64;
        let mut buffer = [0u8; 16];

        // Test absolute encoding (wire ID is large)
        let wire_id = 999999;
        let encoded = FlaggedVarInt::encode_wire_id(wire_id, wire_counter, &mut buffer)?;
        let (decoded_id, consumed) = FlaggedVarInt::decode_wire_id(&buffer, wire_counter)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_id, wire_id);

        // Test relative encoding (wire ID is close to counter)
        let wire_id = 995;
        let encoded = FlaggedVarInt::encode_wire_id(wire_id, wire_counter, &mut buffer)?;
        let (decoded_id, consumed) = FlaggedVarInt::decode_wire_id(&buffer, wire_counter)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_id, wire_id);

        // Test edge case: wire_id equals wire_counter
        let wire_id = wire_counter;
        let encoded = FlaggedVarInt::encode_wire_id(wire_id, wire_counter, &mut buffer)?;
        let (decoded_id, consumed) = FlaggedVarInt::decode_wire_id(&buffer, wire_counter)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_id, wire_id);

        Ok(())
    }

    #[test]
    fn test_max_values() -> Result<()> {
        // Test StandardVarInt max value
        let max_standard = StandardVarInt::new(StandardVarInt::MAX_VALUE)?;
        let mut buffer = [0u8; 8];
        let size = max_standard.encode(&mut buffer)?;
        assert_eq!(size, 8);

        // Test exceeding max value
        assert!(StandardVarInt::new(StandardVarInt::MAX_VALUE + 1).is_err());

        // Test FlaggedVarInt max value
        let max_flagged = FlaggedVarInt::absolute(FlaggedVarInt::MAX_VALUE)?;
        let size = max_flagged.encode(&mut buffer)?;
        assert_eq!(size, 8);

        // Test exceeding max value
        assert!(FlaggedVarInt::absolute(FlaggedVarInt::MAX_VALUE + 1).is_err());

        Ok(())
    }

    #[test]
    fn test_performance_critical_path() -> Result<()> {
        // Test that the most common cases (small values) are fast
        let mut buffer = [0u8; 8];

        // Small values should encode to 1 byte
        for i in 0..32u64 {
            let varint = FlaggedVarInt::relative(i)?;
            let size = varint.encode(&mut buffer)?;
            assert_eq!(size, 1);

            let (decoded, consumed) = FlaggedVarInt::decode(&buffer)?;
            assert_eq!(consumed, 1);
            assert_eq!(decoded.value(), i);
        }

        // Medium values should be efficient too
        for i in [100, 500, 1000, 5000].iter() {
            let varint = StandardVarInt::new(*i)?;
            let size = varint.encode(&mut buffer)?;
            assert!(size <= 2);
        }

        Ok(())
    }
}

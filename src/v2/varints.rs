//! Variable-length integer encoding for CKT v2 format
//!
//! Implements two varint types:
//! - StandardVarInt: Standard QUIC varint encoding
//! - FlaggedVarInt: Modified QUIC varint with context-dependent flag bit

use cynosure::hints::{likely, unlikely};
use std::io::{Error, ErrorKind, Result};

/// Standard QUIC-style varint for header fields and counts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardVarInt(u64);

impl StandardVarInt {
    /// Maximum value that can be encoded (2^62 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 62) - 1;

    /// Create a new StandardVarInt
    pub fn new(value: u64) -> Result<Self> {
        if value > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(StandardVarInt(value))
    }

    /// Get the raw value
    pub fn value(self) -> u64 {
        self.0
    }

    /// Encode to byte slice and return number of bytes used
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.0;

        if likely(value < (1u64 << 6)) {
            // 1 byte: 0xxxxxxx
            if unlikely(buffer.len() < 1) {
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
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize)> {
        if unlikely(buffer.is_empty()) {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Empty buffer"));
        }

        let first = buffer[0];

        // Branchless length computation: 00->1, 01->2, 10->4, 11->8
        let length = 1 << (first >> 6);

        // Branchless mask computation: 0xxxxxxx->0x7F, others->0x3F
        let mask = 0x3F + ((first >> 6 == 0) as u8) * 0x40;

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let mut value = (first & mask) as u64;

        for i in 1..length {
            value = (value << 8) | (buffer[i] as u64);
        }

        Ok((StandardVarInt(value), length))
    }

    /// Get the encoded size in bytes for a given value
    pub fn encoded_size(value: u64) -> usize {
        if likely(value < (1u64 << 6)) {
            1
        } else if likely(value < (1u64 << 14)) {
            2
        } else if likely(value < (1u64 << 30)) {
            4
        } else {
            8
        }
    }
}

/// Flagged varint with context-dependent flag bit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggedVarInt {
    value: u64,
    is_relative: bool,
}

impl FlaggedVarInt {
    /// Maximum value that can be encoded (2^61 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 61) - 1;

    /// Create a new absolute FlaggedVarInt
    pub fn absolute(value: u64) -> Result<Self> {
        if value > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value,
            is_relative: false,
        })
    }

    /// Create a new relative FlaggedVarInt
    pub fn relative(value: u64) -> Result<Self> {
        if value > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value,
            is_relative: true,
        })
    }

    /// Create a new FlaggedVarInt with arbitrary flag meaning
    pub fn with_flag(value: u64, flag: bool) -> Result<Self> {
        if value > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value,
            is_relative: flag,
        })
    }

    /// Get the flag value (context-dependent meaning)
    pub fn flag(self) -> bool {
        self.is_relative
    }

    /// Get the raw value
    pub fn value(self) -> u64 {
        self.value
    }

    /// Check if this is a relative encoding
    pub fn is_relative(self) -> bool {
        self.is_relative
    }

    /// Check if this is an absolute encoding
    pub fn is_absolute(self) -> bool {
        !self.is_relative
    }

    /// Encode to byte slice and return number of bytes used
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.value;
        let rel_bit = if self.is_relative { 1u8 } else { 0u8 };

        if likely(value < (1u64 << 5)) {
            // 1 byte: 00rxxxxx
            if unlikely(buffer.len() < 1) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = (rel_bit << 5) | (value as u8);
            Ok(1)
        } else if likely(value < (1u64 << 13)) {
            // 2 bytes: 01rxxxxx xxxxxxxx
            if unlikely(buffer.len() < 2) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x40 | (rel_bit << 5) | ((value >> 8) as u8);
            buffer[1] = value as u8;
            Ok(2)
        } else if likely(value < (1u64 << 29)) {
            // 4 bytes: 10rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 4) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x80 | (rel_bit << 5) | ((value >> 24) as u8);
            buffer[1] = (value >> 16) as u8;
            buffer[2] = (value >> 8) as u8;
            buffer[3] = value as u8;
            Ok(4)
        } else {
            // 8 bytes: 11rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 8) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0xC0 | (rel_bit << 5) | ((value >> 56) as u8);
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
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize)> {
        if unlikely(buffer.is_empty()) {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Empty buffer"));
        }

        let first = buffer[0];

        let length = 1 << (first >> 6);
        let rel_bit = (first >> 5) & 1;
        let mask = 0x1F; // Always 5 bits for FlaggedVarInt

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let is_relative = rel_bit == 1;
        let mut value = (first & mask) as u64;

        for i in 1..length {
            value = (value << 8) | (buffer[i] as u64);
        }

        Ok((FlaggedVarInt { value, is_relative }, length))
    }

    /// Get the encoded size in bytes for a given value
    pub fn encoded_size(value: u64) -> usize {
        if likely(value < (1u64 << 5)) {
            1
        } else if likely(value < (1u64 << 13)) {
            2
        } else if likely(value < (1u64 << 29)) {
            4
        } else {
            8
        }
    }

    /// Decode wire ID to absolute value given current counter
    pub fn decode_to_absolute(self, counter: u64) -> u64 {
        if self.is_relative {
            counter.saturating_sub(self.value)
        } else {
            self.value
        }
    }

    /// Choose optimal encoding (absolute vs relative) and create FlaggedVarInt
    pub fn optimal_encoding(absolute_id: u64, counter: u64) -> Result<Self> {
        let relative_value = counter.saturating_sub(absolute_id);

        // Choose encoding that results in smaller serialized size
        let abs_size = Self::encoded_size(absolute_id);
        let rel_size = Self::encoded_size(relative_value);

        if unlikely(abs_size <= rel_size) {
            Self::absolute(absolute_id)
        } else {
            // Relative encoding is more common for circuit locality
            Self::relative(relative_value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_varint_encode_decode() {
        let test_values = [
            0u64,
            1,
            63,         // Max 1-byte
            64,         // Min 2-byte
            16383,      // Max 2-byte
            16384,      // Min 4-byte
            1073741823, // Max 4-byte
            1073741824, // Min 8-byte
            StandardVarInt::MAX_VALUE,
        ];

        for &value in &test_values {
            let varint = StandardVarInt::new(value).unwrap();
            let mut buffer = vec![0u8; 16]; // Max size
            let encoded_size = varint.encode(&mut buffer).unwrap();

            assert_eq!(encoded_size, StandardVarInt::encoded_size(value));

            let (decoded, bytes_consumed) = StandardVarInt::decode(&buffer).unwrap();
            assert_eq!(decoded.value(), value);
            assert_eq!(bytes_consumed, encoded_size);
        }
    }

    #[test]
    fn test_flagged_varint_encode_decode() {
        let test_values = [
            (0u64, false),
            (0u64, true),
            (31, false),        // Max 1-byte
            (32, false),        // Min 2-byte
            (8191, true),       // Max 2-byte
            (8192, true),       // Min 4-byte
            (536870911, false), // Max 4-byte
            (536870912, false), // Min 8-byte
        ];

        for &(value, is_relative) in &test_values {
            let varint = if is_relative {
                FlaggedVarInt::relative(value).unwrap()
            } else {
                FlaggedVarInt::absolute(value).unwrap()
            };

            let mut buffer = vec![0u8; 16]; // Max size
            let encoded_size = varint.encode(&mut buffer).unwrap();

            assert_eq!(encoded_size, FlaggedVarInt::encoded_size(value));

            let (decoded, bytes_consumed) = FlaggedVarInt::decode(&buffer).unwrap();
            assert_eq!(decoded.value(), value);
            assert_eq!(decoded.is_relative(), is_relative);
            assert_eq!(bytes_consumed, encoded_size);
        }
    }

    #[test]
    fn test_with_flag() {
        let varint = FlaggedVarInt::with_flag(42, true).unwrap();
        assert_eq!(varint.value(), 42);
        assert_eq!(varint.flag(), true);
        assert_eq!(varint.is_relative(), true);

        let varint = FlaggedVarInt::with_flag(100, false).unwrap();
        assert_eq!(varint.value(), 100);
        assert_eq!(varint.flag(), false);
        assert_eq!(varint.is_absolute(), true);
    }

    #[test]
    fn test_flagged_varint_decode_to_absolute() {
        let counter = 1000u64;

        // Test absolute encoding
        let abs_varint = FlaggedVarInt::absolute(500).unwrap();
        assert_eq!(abs_varint.decode_to_absolute(counter), 500);

        // Test relative encoding
        let rel_varint = FlaggedVarInt::relative(50).unwrap();
        assert_eq!(rel_varint.decode_to_absolute(counter), 950); // 1000 - 50
    }

    #[test]
    fn test_optimal_encoding() {
        let counter = 1000u64;

        // Absolute should be chosen for small absolute values
        let varint = FlaggedVarInt::optimal_encoding(5, counter).unwrap();
        assert!(varint.is_absolute());
        assert_eq!(varint.value(), 5);

        // Relative should be chosen for recent references
        let varint = FlaggedVarInt::optimal_encoding(995, counter).unwrap();
        assert!(varint.is_relative());
        assert_eq!(varint.value(), 5); // 1000 - 995
    }

    #[test]
    fn test_size_calculations() {
        assert_eq!(StandardVarInt::encoded_size(0), 1);
        assert_eq!(StandardVarInt::encoded_size(63), 1);
        assert_eq!(StandardVarInt::encoded_size(64), 2);
        assert_eq!(StandardVarInt::encoded_size(16383), 2);
        assert_eq!(StandardVarInt::encoded_size(16384), 4);

        assert_eq!(FlaggedVarInt::encoded_size(0), 1);
        assert_eq!(FlaggedVarInt::encoded_size(31), 1);
        assert_eq!(FlaggedVarInt::encoded_size(32), 2);
        assert_eq!(FlaggedVarInt::encoded_size(8191), 2);
        assert_eq!(FlaggedVarInt::encoded_size(8192), 4);
    }

    #[test]
    fn test_max_value_limits() {
        // Should succeed at max value
        assert!(StandardVarInt::new(StandardVarInt::MAX_VALUE).is_ok());
        assert!(FlaggedVarInt::absolute(FlaggedVarInt::MAX_VALUE).is_ok());
        assert!(FlaggedVarInt::relative(FlaggedVarInt::MAX_VALUE).is_ok());

        // Should fail above max value
        assert!(StandardVarInt::new(StandardVarInt::MAX_VALUE + 1).is_err());
        assert!(FlaggedVarInt::absolute(FlaggedVarInt::MAX_VALUE + 1).is_err());
        assert!(FlaggedVarInt::relative(FlaggedVarInt::MAX_VALUE + 1).is_err());
    }
}

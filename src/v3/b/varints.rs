//! Variable-length integer encoding for CKT v3b format
//!
//! Implements two varint types:
//! - StandardVarInt: Standard QUIC varint encoding for indices and counts
//! - FlaggedVarInt: Modified QUIC varint with level-encoding semantics
//!   - Flag=1: Previous level reference (value is index)
//!   - Flag=0: Other level (followed by level spec and index)

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

        for byte in buffer.iter().take(length).skip(1) {
            value = (value << 8) | (*byte as u64);
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

/// Flagged varint for level-based wire encoding
/// In v3b context:
/// - Flag=1 means "previous level", value is the index
/// - Flag=0 means "other level", requires additional level spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggedVarInt {
    value: u64,
    flag: bool,
}

impl FlaggedVarInt {
    /// Maximum value that can be encoded (2^61 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 61) - 1;

    /// Create a FlaggedVarInt for previous level reference
    pub fn previous_level(index: u64) -> Result<Self> {
        if index > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Index {} exceeds maximum {}", index, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: index,
            flag: true, // Flag=1 for previous level
        })
    }

    /// Create a FlaggedVarInt for other level (not previous)
    pub fn other_level() -> Result<Self> {
        Ok(FlaggedVarInt {
            value: 0,    // Value unused for other level marker
            flag: false, // Flag=0 for other level
        })
    }

    /// Create an absolute level ID FlaggedVarInt
    pub fn absolute(level_id: u64) -> Result<Self> {
        if level_id > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Level ID {} exceeds maximum {}", level_id, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: level_id,
            flag: false, // Absolute uses flag=0
        })
    }

    /// Create a relative level ID FlaggedVarInt (backward reference)
    pub fn relative(distance: u64) -> Result<Self> {
        if distance > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Distance {} exceeds maximum {}", distance, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: distance,
            flag: true, // Relative uses flag=1
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
        Ok(FlaggedVarInt { value, flag })
    }

    /// Get the flag value (context-dependent meaning)
    pub fn flag(self) -> bool {
        self.flag
    }

    /// Get the raw value
    pub fn value(self) -> u64 {
        self.value
    }

    /// Check if this is a previous level reference
    pub fn is_previous_level(self) -> bool {
        self.flag
    }

    /// Check if this is an other level reference
    pub fn is_other_level(self) -> bool {
        !self.flag
    }

    /// Check if this represents a relative level ID (for level specs)
    pub fn is_relative(self) -> bool {
        self.flag
    }

    /// Check if this represents an absolute level ID (for level specs)
    pub fn is_absolute(self) -> bool {
        !self.flag
    }

    /// Encode to byte slice and return number of bytes used
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.value;
        let flag_bit = if self.flag { 1u8 } else { 0u8 };

        if likely(value < (1u64 << 5)) {
            // 1 byte: 00rxxxxx
            if unlikely(buffer.is_empty()) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = (flag_bit << 5) | (value as u8);
            Ok(1)
        } else if likely(value < (1u64 << 13)) {
            // 2 bytes: 01rxxxxx xxxxxxxx
            if unlikely(buffer.len() < 2) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x40 | (flag_bit << 5) | ((value >> 8) as u8);
            buffer[1] = value as u8;
            Ok(2)
        } else if likely(value < (1u64 << 29)) {
            // 4 bytes: 10rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 4) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x80 | (flag_bit << 5) | ((value >> 24) as u8);
            buffer[1] = (value >> 16) as u8;
            buffer[2] = (value >> 8) as u8;
            buffer[3] = value as u8;
            Ok(4)
        } else {
            // 8 bytes: 11rxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 8) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0xC0 | (flag_bit << 5) | ((value >> 56) as u8);
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
        let flag_bit = (first >> 5) & 1;
        let mask = 0x1F; // Always 5 bits for FlaggedVarInt

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let flag = flag_bit == 1;
        let mut value = (first & mask) as u64;

        for byte in buffer.iter().take(length).skip(1) {
            value = (value << 8) | (*byte as u64);
        }

        Ok((FlaggedVarInt { value, flag }, length))
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

    /// Encode a wire location for v3b format
    /// Returns the encoded bytes and number of bytes used
    pub fn encode_wire_location(
        level: u32,
        index: u32,
        current_level: u32,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let mut offset = 0;

        // Check if it's previous level
        if level == current_level.saturating_sub(1) && level != current_level {
            // Previous level optimization
            let varint = Self::previous_level(index as u64)?;
            offset += varint.encode(buffer)?;
        } else {
            // Other level - need level spec + index
            let other_marker = Self::other_level()?;
            offset += other_marker.encode(&mut buffer[offset..])?;

            // Encode level ID (relative or absolute)
            // We can only reference previous levels or earlier gates in the same level
            if level > current_level {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "Cannot reference level {} from level {} (can only reference previous levels)",
                        level, current_level
                    ),
                ));
            }

            // Choose the more efficient encoding
            let distance = current_level - level;
            if distance < level {
                // Relative encoding is smaller
                let level_varint = Self::relative(distance as u64)?;
                offset += level_varint.encode(&mut buffer[offset..])?;
            } else {
                // Absolute encoding is smaller (or equal, prefer absolute for simplicity)
                let level_varint = Self::absolute(level as u64)?;
                offset += level_varint.encode(&mut buffer[offset..])?;
            }

            // Always encode index for other levels
            let index_varint = StandardVarInt::new(index as u64)?;
            offset += index_varint.encode(&mut buffer[offset..])?;
        }

        Ok(offset)
    }

    /// Decode a wire location from v3b format
    /// Returns (level, index, bytes_consumed)
    pub fn decode_wire_location(buffer: &[u8], current_level: u32) -> Result<(u32, u32, usize)> {
        let (first_varint, consumed) = Self::decode(buffer)?;

        if first_varint.is_previous_level() {
            // Previous level - value is the index
            let level = current_level.saturating_sub(1);
            let index = first_varint.value() as u32;
            Ok((level, index, consumed))
        } else {
            // Other level - read level spec and index
            let (level_varint, consumed2) = Self::decode(&buffer[consumed..])?;

            let level = if level_varint.is_relative() {
                // Relative backward reference
                let distance = level_varint.value() as u32;
                if distance > current_level {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Invalid relative distance {} from level {}",
                            distance, current_level
                        ),
                    ));
                }
                current_level - distance
            } else {
                // Absolute level ID
                let level = level_varint.value() as u32;
                if level >= current_level {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Invalid level reference {} from level {} (can only reference previous levels)",
                            level, current_level
                        ),
                    ));
                }
                level
            };

            // Read index
            let (index_varint, consumed3) =
                StandardVarInt::decode(&buffer[consumed + consumed2..])?;

            Ok((
                level,
                index_varint.value() as u32,
                consumed + consumed2 + consumed3,
            ))
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
    fn test_wire_location_encoding() {
        let mut buffer = [0u8; 32];

        // Test previous level encoding (optimized case)
        let bytes = FlaggedVarInt::encode_wire_location(5, 10, 6, &mut buffer).unwrap();
        assert!(bytes <= 2); // Should be compact

        let (level, index, consumed) = FlaggedVarInt::decode_wire_location(&buffer, 6).unwrap();
        assert_eq!(level, 5);
        assert_eq!(index, 10);
        assert_eq!(consumed, bytes);

        // Test absolute level encoding
        let bytes = FlaggedVarInt::encode_wire_location(2, 15, 10, &mut buffer).unwrap();
        let (level, index, consumed) = FlaggedVarInt::decode_wire_location(&buffer, 10).unwrap();
        assert_eq!(level, 2);
        assert_eq!(index, 15);
        assert_eq!(consumed, bytes);
    }

    #[test]
    fn test_relative_absolute_optimization() {
        let mut buffer = [0u8; 32];

        // Test case 1: distance < level, should use relative (but NOT previous level)
        // Level 3000000 referring to level 2999998 (distance=2, level=2999998)
        // distance(2) < level(2999998), so should use relative
        let bytes =
            FlaggedVarInt::encode_wire_location(2999998, 100, 3000000, &mut buffer).unwrap();
        let (level, index, consumed) =
            FlaggedVarInt::decode_wire_location(&buffer, 3000000).unwrap();
        assert_eq!(level, 2999998);
        assert_eq!(index, 100);
        assert_eq!(consumed, bytes);

        // The relative encoding of distance=2 should be smaller than absolute encoding of 2999998
        // Verify by checking the first varint after the other_level marker
        let (first_varint, first_consumed) = FlaggedVarInt::decode(&buffer).unwrap();
        assert!(!first_varint.is_previous_level()); // Should be other level
        let (level_varint, _) = FlaggedVarInt::decode(&buffer[first_consumed..]).unwrap();
        assert!(level_varint.is_relative()); // Should have chosen relative
        assert_eq!(level_varint.value(), 2); // Distance should be 2

        // Test case 2: level <= distance, should use absolute
        // Level 3000000 referring to level 5 (distance=2999995, level=5)
        // level(5) < distance(2999995), so should use absolute
        let bytes = FlaggedVarInt::encode_wire_location(5, 200, 3000000, &mut buffer).unwrap();
        let (level, index, consumed) =
            FlaggedVarInt::decode_wire_location(&buffer, 3000000).unwrap();
        assert_eq!(level, 5);
        assert_eq!(index, 200);
        assert_eq!(consumed, bytes);

        // Verify it chose absolute encoding
        let (first_varint, first_consumed) = FlaggedVarInt::decode(&buffer).unwrap();
        assert!(!first_varint.is_previous_level()); // Should be other level
        let (level_varint, _) = FlaggedVarInt::decode(&buffer[first_consumed..]).unwrap();
        assert!(level_varint.is_absolute()); // Should have chosen absolute
        assert_eq!(level_varint.value(), 5); // Level should be 5

        // Test case 3: Cannot reference future levels
        let result = FlaggedVarInt::encode_wire_location(10, 0, 5, &mut buffer);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("can only reference previous levels"),
            "Error message should mention 'can only reference previous levels', got: {}",
            err_msg
        );

        // Test case 4: Previous level optimization (should use flag=1)
        // Level 100 referring to level 99
        let _bytes = FlaggedVarInt::encode_wire_location(99, 42, 100, &mut buffer).unwrap();
        let (level, index, consumed) = FlaggedVarInt::decode_wire_location(&buffer, 100).unwrap();
        assert_eq!(level, 99);
        assert_eq!(index, 42);

        // Should be encoded as a single varint with flag=1
        let (first_varint, first_consumed) = FlaggedVarInt::decode(&buffer).unwrap();
        assert!(first_varint.is_previous_level()); // Should be previous level optimization
        assert_eq!(first_varint.value(), 42); // Value should be the index
        assert_eq!(first_consumed, consumed); // Should be just one varint
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

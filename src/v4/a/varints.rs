//! Variable-length integer encoding for CKT v4a format
//!
//! Implements two varint types:
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
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize)> {
        if unlikely(buffer.is_empty()) {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Empty buffer"));
        }

        let first = buffer[0];

        // Determine length based on first two bits
        let (length, mask) = match first >> 6 {
            0b00 => (1, 0x3F),
            0b01 => (2, 0x3F),
            0b10 => (4, 0x3F),
            0b11 => (8, 0x3F),
            _ => unreachable!(),
        };

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
    pub fn absolute(wire_id: u64) -> Result<Self> {
        if wire_id > Self::MAX_VALUE {
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
    pub fn relative(offset: u64) -> Result<Self> {
        if offset > Self::MAX_VALUE {
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
    pub fn with_flag(value: u64, flag: bool) -> Result<Self> {
        if value > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Value {} exceeds maximum {}", value, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt { value, flag })
    }

    /// Get the flag value
    pub fn flag(self) -> bool {
        self.flag
    }

    /// Get the raw value
    pub fn value(self) -> u64 {
        self.value
    }

    /// Check if this is an absolute wire ID
    pub fn is_absolute(self) -> bool {
        self.flag
    }

    /// Check if this is relative to wire counter
    pub fn is_relative(self) -> bool {
        !self.flag
    }

    /// Encode to byte slice and return number of bytes used
    pub fn encode(self, buffer: &mut [u8]) -> Result<usize> {
        let value = self.value;

        // Encode with flag bit in the reserved bit position
        if likely(value < (1u64 << 5)) {
            // 1 byte: 00fxxxxx (f = flag bit)
            if unlikely(buffer.is_empty()) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = (value as u8) | ((self.flag as u8) << 5);
            Ok(1)
        } else if likely(value < (1u64 << 13)) {
            // 2 bytes: 01fxxxxx xxxxxxxx
            if unlikely(buffer.len() < 2) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x40 | ((self.flag as u8) << 5) | ((value >> 8) as u8);
            buffer[1] = value as u8;
            Ok(2)
        } else if likely(value < (1u64 << 29)) {
            // 4 bytes: 10fxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 4) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0x80 | ((self.flag as u8) << 5) | ((value >> 24) as u8);
            buffer[1] = (value >> 16) as u8;
            buffer[2] = (value >> 8) as u8;
            buffer[3] = value as u8;
            Ok(4)
        } else {
            // 8 bytes: 11fxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if unlikely(buffer.len() < 8) {
                return Err(Error::new(ErrorKind::WriteZero, "Buffer too small"));
            }
            buffer[0] = 0xC0 | ((self.flag as u8) << 5) | ((value >> 56) as u8);
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
        let length_bits = first >> 6;

        // Determine length and extract flag bit
        let (length, flag, value_mask) = match length_bits {
            0b00 => (1, (first >> 5) & 1 == 1, 0x1F), // 5 value bits
            0b01 => (2, (first >> 5) & 1 == 1, 0x1F), // 13 value bits total
            0b10 => (4, (first >> 5) & 1 == 1, 0x1F), // 29 value bits total
            0b11 => (8, (first >> 5) & 1 == 1, 0x1F), // 61 value bits total
            _ => unreachable!(),
        };

        if unlikely(buffer.len() < length) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("Need {} bytes but only {} available", length, buffer.len()),
            ));
        }

        let mut value = (first & value_mask) as u64;

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

    /// Encode a wire ID relative to the current wire counter
    pub fn encode_wire_id(wire_id: u64, wire_counter: u64, buffer: &mut [u8]) -> Result<usize> {
        // Choose the most efficient encoding
        if wire_id <= wire_counter && (wire_counter - wire_id) < wire_id {
            // Relative encoding is more efficient
            let offset = wire_counter - wire_id;
            let varint = FlaggedVarInt::relative(offset)?;
            varint.encode(buffer)
        } else {
            // Absolute encoding
            let varint = FlaggedVarInt::absolute(wire_id)?;
            varint.encode(buffer)
        }
    }

    /// Decode a wire ID given the current wire counter
    pub fn decode_wire_id(buffer: &[u8], wire_counter: u64) -> Result<(u64, usize)> {
        let (varint, consumed) = FlaggedVarInt::decode(buffer)?;

        let wire_id = if varint.is_absolute() {
            varint.value
        } else {
            // Relative offset from wire counter
            if varint.value > wire_counter {
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
}

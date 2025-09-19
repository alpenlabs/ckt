//! Variable-length integer encoding for CKT v4b format
//!
//! Implements two varint types:
//! - StandardVarInt: Standard QUIC varint encoding for counts and sizes
//! - FlaggedVarInt: Modified QUIC varint for memory addresses
//!   - Flag=1: Absolute scratch space index
//!   - Flag=0: Relative to previous gate's output address

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

/// Flagged varint for memory address encoding
/// In v4b context:
/// - Flag=1 means absolute scratch space index
/// - Flag=0 means relative to previous gate's output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggedVarInt {
    value: u64,
    flag: bool,
}

impl FlaggedVarInt {
    /// Maximum value that can be encoded (2^61 - 1)
    pub const MAX_VALUE: u64 = (1u64 << 61) - 1;

    /// Create a FlaggedVarInt with absolute memory address
    pub fn absolute(address: u64) -> Result<Self> {
        if address > Self::MAX_VALUE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Address {} exceeds maximum {}", address, Self::MAX_VALUE),
            ));
        }
        Ok(FlaggedVarInt {
            value: address,
            flag: true, // Flag=1 for absolute
        })
    }

    /// Create a FlaggedVarInt with relative offset from previous output
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

    /// Check if this is an absolute address
    pub fn is_absolute(self) -> bool {
        self.flag
    }

    /// Check if this is relative to previous output
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

    /// Encode a memory address relative to the previous output
    pub fn encode_memory_address(
        address: u64,
        previous_output: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        // Choose the most efficient encoding
        if address <= previous_output && (previous_output - address) < address {
            // Relative encoding is more efficient
            let offset = previous_output - address;
            let varint = FlaggedVarInt::relative(offset)?;
            varint.encode(buffer)
        } else {
            // Absolute encoding
            let varint = FlaggedVarInt::absolute(address)?;
            varint.encode(buffer)
        }
    }

    /// Decode a memory address given the previous output
    pub fn decode_memory_address(buffer: &[u8], previous_output: u64) -> Result<(u64, usize)> {
        let (varint, consumed) = FlaggedVarInt::decode(buffer)?;

        let address = if varint.is_absolute() {
            varint.value
        } else {
            // Relative offset from previous output
            if varint.value > previous_output {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Relative offset {} exceeds previous output {}",
                        varint.value, previous_output
                    ),
                ));
            }
            previous_output - varint.value
        };

        Ok((address, consumed))
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
    fn test_memory_address_encoding() -> Result<()> {
        let previous_output = 1000u64;
        let mut buffer = [0u8; 16];

        // Test absolute encoding (address is large)
        let address = 999999;
        let encoded = FlaggedVarInt::encode_memory_address(address, previous_output, &mut buffer)?;
        let (decoded_addr, consumed) =
            FlaggedVarInt::decode_memory_address(&buffer, previous_output)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_addr, address);

        // Test relative encoding (address is close to previous output)
        let address = 995;
        let encoded = FlaggedVarInt::encode_memory_address(address, previous_output, &mut buffer)?;
        let (decoded_addr, consumed) =
            FlaggedVarInt::decode_memory_address(&buffer, previous_output)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_addr, address);

        // Test edge case: address equals previous output
        let address = previous_output;
        let encoded = FlaggedVarInt::encode_memory_address(address, previous_output, &mut buffer)?;
        let (decoded_addr, consumed) =
            FlaggedVarInt::decode_memory_address(&buffer, previous_output)?;
        assert_eq!(consumed, encoded);
        assert_eq!(decoded_addr, address);

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
    fn test_scratch_space_indices() -> Result<()> {
        // Test typical scratch space indices
        let test_cases = vec![
            (0, true),     // False constant
            (1, true),     // True constant
            (2, true),     // First primary input
            (100, true),   // Typical gate output
            (1000, false), // Relative encoding might be better
        ];

        let previous = 1005u64;
        let mut buffer = [0u8; 8];

        for (addr, expect_absolute) in test_cases {
            let encoded = FlaggedVarInt::encode_memory_address(addr, previous, &mut buffer)?;
            let (varint, _) = FlaggedVarInt::decode(&buffer)?;

            if expect_absolute {
                assert!(
                    varint.is_absolute() || addr > previous,
                    "Address {} should use absolute encoding with previous {}",
                    addr,
                    previous
                );
            }

            let (decoded, consumed) = FlaggedVarInt::decode_memory_address(&buffer, previous)?;
            assert_eq!(consumed, encoded);
            assert_eq!(decoded, addr);
        }

        Ok(())
    }
}

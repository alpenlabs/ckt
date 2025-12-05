//! A [`Write`] wrapper that hashes all bytes passing through it.

use std::io::{Result, Write};

/// A [`Write`] implementation that hashes all bytes and forwards them to an
/// inner writer.
///
/// This is useful when you want to compute a hash of data being written
/// while also writing it to another destination (file, buffer, etc.).
///
/// # Example
///
/// ```
/// use std::io::Write;
/// use ckt_runner_exec::HashWriter;
///
/// let mut buffer = Vec::new();
/// let mut writer = HashWriter::new(&mut buffer);
///
/// writer.write_all(b"hello world").unwrap();
/// writer.flush().unwrap();
///
/// let hash = writer.finalize();
/// assert_eq!(buffer, b"hello world");
/// ```
pub struct HashWriter<W> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W> HashWriter<W> {
    /// Create a new `HashWriter` wrapping the given writer.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Consume this writer and return the final hash.
    pub fn finalize(self) -> blake3::Hash {
        self.hasher.finalize()
    }

    /// Get a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Get a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume this writer and return the inner writer and hash.
    pub fn into_parts(self) -> (W, blake3::Hash) {
        (self.inner, self.hasher.finalize())
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_writer_forwards_and_hashes() {
        let mut buffer = Vec::new();
        let mut writer = HashWriter::new(&mut buffer);

        writer.write_all(b"hello ").unwrap();
        writer.write_all(b"world").unwrap();
        writer.flush().unwrap();

        let hash = writer.finalize();

        // Verify data was forwarded
        assert_eq!(buffer, b"hello world");

        // Verify hash matches direct hashing
        let expected = blake3::hash(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_into_parts() {
        let buffer = Vec::new();
        let mut writer = HashWriter::new(buffer);

        writer.write_all(b"test data").unwrap();

        let (buffer, hash) = writer.into_parts();

        assert_eq!(buffer, b"test data");
        assert_eq!(hash, blake3::hash(b"test data"));
    }
}

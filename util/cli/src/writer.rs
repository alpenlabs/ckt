use std::io::{Seek, Write};

use kanal::Sender;

/// A writer that sends data chunks to a remote writer via a channel.
///
/// # Assumptions and Safety Requirements:
///
/// 1. **File size**: The initial file size must be provided. If appending to an
///    existing file, pass its current size. For new files, pass 0. The file_size
///    is tracked based on writes from the initial size.
///
/// 2. **Ordering**: The channel receiver MUST handle potentially out-of-order writes.
///    Seeks can cause writes to earlier positions after writes to later positions.
///
/// 3. **Overlapping writes**: The receiver MUST handle overlapping writes correctly.
///    Later writes should overwrite earlier writes at the same positions.
///
/// 4. **File size tracking**: Assumes this is the ONLY writer to the file.
///    External modifications will make SeekFrom::End incorrect.
///
/// 5. **Data persistence**: Assumes the receiver will actually write all data.
///    There's no acknowledgment mechanism for successful writes.
pub struct RemoteWriter {
    /// Current position in the virtual file
    pos: u64,
    /// Buffered data waiting to be sent
    buffer: Vec<u8>,
    /// File position where the current buffer data should be written
    buffer_start_pos: u64,
    /// Maximum size of data kept in file (for SeekFrom::End support)
    file_size: u64,
    /// sends (start_pos_to_write_to, data)
    send_to_remote: Sender<(u64, Vec<u8>)>,
}

impl RemoteWriter {
    /// Maximum buffer size before auto-flush.
    /// This prevents unbounded memory growth but is arbitrary - tune based on:
    /// - Available memory
    /// - Channel throughput
    /// - Desired write granularity
    const MAX_BUFFER_SIZE: usize = 1024 * 1024; // 1MB max buffer before auto-flush

    pub fn new(send_to_remote: Sender<(u64, Vec<u8>)>, initial_file_size: u64) -> Self {
        Self {
            pos: 0,
            buffer: Vec::with_capacity(8192), // 8KB initial capacity
            buffer_start_pos: 0,
            file_size: initial_file_size,
            send_to_remote,
        }
    }
}

impl Write for RemoteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // If buffer is empty, this is the first write after seek/flush
        if self.buffer.is_empty() {
            self.buffer_start_pos = self.pos;
        }

        self.buffer.extend_from_slice(buf);
        self.pos += buf.len() as u64;

        // Update file size if we've written past the end
        if self.pos > self.file_size {
            self.file_size = self.pos;
        }

        // Auto-flush if buffer gets too large
        if self.buffer.len() > Self::MAX_BUFFER_SIZE {
            self.flush()?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            // Note: We clone the buffer here. For large buffers, this could be expensive.
            // Alternative: Use Arc<Vec<u8>> or a pool of buffers to avoid cloning.
            self.send_to_remote
                .send((self.buffer_start_pos, self.buffer.clone()))
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed")
                })?;
            self.buffer.clear();
            // Don't update buffer_start_pos here - it will be set on next write
        }
        Ok(())
    }
}

impl Seek for RemoteWriter {
    fn seek(&mut self, seek_from: std::io::SeekFrom) -> std::io::Result<u64> {
        // Flush any buffered data before seeking
        self.flush()?;

        let new_pos = match seek_from {
            std::io::SeekFrom::Start(offset) => offset,
            std::io::SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.pos.saturating_add(offset as u64)
                } else {
                    self.pos.saturating_sub((-offset) as u64)
                }
            }
            std::io::SeekFrom::End(offset) => {
                // ASSUMPTION: file_size accurately reflects the actual file size.
                // This requires no external writes and all writes through this writer
                // to complete successfully.
                if offset >= 0 {
                    self.file_size.saturating_add(offset as u64)
                } else {
                    self.file_size.saturating_sub((-offset) as u64)
                }
            }
        };

        self.pos = new_pos;
        // buffer_start_pos will be set on next write
        Ok(new_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanal::unbounded;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn test_seek_from_start() {
        let (tx, rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        // Write at position 0
        writer.write(b"hello").unwrap();
        writer.flush().unwrap();

        // Seek to position 10
        assert_eq!(writer.seek(SeekFrom::Start(10)).unwrap(), 10);
        writer.write(b"world").unwrap();
        writer.flush().unwrap();

        // Check both writes
        let (pos1, data1) = rx.recv().unwrap();
        assert_eq!(pos1, 0);
        assert_eq!(data1, b"hello");

        let (pos2, data2) = rx.recv().unwrap();
        assert_eq!(pos2, 10);
        assert_eq!(data2, b"world");
    }

    #[test]
    fn test_seek_from_current() {
        let (tx, _rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        writer.write(b"hello").unwrap(); // pos = 5
        assert_eq!(writer.seek(SeekFrom::Current(5)).unwrap(), 10);
        assert_eq!(writer.pos, 10);

        assert_eq!(writer.seek(SeekFrom::Current(-3)).unwrap(), 7);
        assert_eq!(writer.pos, 7);
    }

    #[test]
    fn test_seek_from_end() {
        let (tx, _rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 100); // Initial file size 100

        assert_eq!(writer.seek(SeekFrom::End(0)).unwrap(), 100);
        assert_eq!(writer.seek(SeekFrom::End(-10)).unwrap(), 90);
        assert_eq!(writer.seek(SeekFrom::End(10)).unwrap(), 110);
    }

    #[test]
    fn test_file_size_tracking() {
        let (tx, _rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 50);

        // Write within existing file
        writer.write(b"hello").unwrap();
        assert_eq!(writer.file_size, 50);

        // Write past end of file
        writer.seek(SeekFrom::Start(60)).unwrap();
        writer.write(b"world").unwrap();
        assert_eq!(writer.file_size, 65);

        // Seek from end should use updated size
        assert_eq!(writer.seek(SeekFrom::End(0)).unwrap(), 65);
    }

    #[test]
    fn test_auto_flush_on_large_buffer() {
        let (tx, rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        // Write data larger than MAX_BUFFER_SIZE
        let large_data = vec![b'x'; RemoteWriter::MAX_BUFFER_SIZE + 1];
        writer.write(&large_data).unwrap();

        // Should have auto-flushed
        let (pos, data) = rx.recv().unwrap();
        assert_eq!(pos, 0);
        assert_eq!(data.len(), RemoteWriter::MAX_BUFFER_SIZE + 1);
        assert!(writer.buffer.is_empty());
    }

    #[test]
    fn test_out_of_order_writes() {
        let (tx, rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        // Write at position 100
        writer.seek(SeekFrom::Start(100)).unwrap();
        writer.write(b"later").unwrap();
        writer.flush().unwrap();

        // Write at position 0
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write(b"earlier").unwrap();
        writer.flush().unwrap();

        // Check writes arrived in correct order
        let (pos1, data1) = rx.recv().unwrap();
        assert_eq!(pos1, 100);
        assert_eq!(data1, b"later");

        let (pos2, data2) = rx.recv().unwrap();
        assert_eq!(pos2, 0);
        assert_eq!(data2, b"earlier");
    }

    #[test]
    fn test_seek_flushes_buffer() {
        let (tx, rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        writer.write(b"hello").unwrap();

        // Seek should flush the buffer
        writer.seek(SeekFrom::Start(10)).unwrap();

        let (pos, data) = rx.recv().unwrap();
        assert_eq!(pos, 0);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_closed_channel() {
        let (tx, rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        writer.write(b"hello").unwrap();

        // Close receiver
        drop(rx);

        // Flush should return error
        let result = writer.flush();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_saturating_arithmetic() {
        let (tx, _rx) = unbounded();
        let mut writer = RemoteWriter::new(tx, 0);

        // Test saturating subtraction
        assert_eq!(writer.seek(SeekFrom::Current(-100)).unwrap(), 0);

        writer.seek(SeekFrom::Start(u64::MAX - 10)).unwrap();
        // Test saturating addition
        assert_eq!(writer.seek(SeekFrom::Current(100)).unwrap(), u64::MAX);
    }
}

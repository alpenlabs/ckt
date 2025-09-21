//! Lock-free triple buffering system for high-performance streaming I/O
//!
//! This implementation uses cache-line padding to prevent false sharing
//! between reader and writer threads, ensuring maximum throughput.

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

/// 4MiB buffer size optimized for NVMe and O_DIRECT
pub const BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Aligned buffer type for O_DIRECT I/O
pub type AlignedBuffer = Box<[u8]>;

/// Create a new aligned buffer for O_DIRECT
pub fn create_aligned_buffer() -> AlignedBuffer {
    let layout =
        std::alloc::Layout::from_size_align(BUFFER_SIZE, 4096).expect("Failed to create layout");

    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout);
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Vec::from_raw_parts(ptr, BUFFER_SIZE, BUFFER_SIZE).into_boxed_slice()
    }
}

/// Cache-line aligned wrapper to prevent false sharing
#[repr(C, align(64))]
struct CacheAligned<T> {
    value: T,
}

impl<T> CacheAligned<T> {
    const fn new(value: T) -> Self {
        Self { value }
    }
}

/// Lock-free triple buffer
///
/// Uses three buffers that circulate between writer, reader, and a shared middle slot.
/// Writer fills buffers and publishes them to middle.
/// Reader takes buffers from middle when new data is available.
pub struct TripleBuffer {
    // Three buffer pointers - at most one can be null (when reader/writer has it)
    buffers: [AtomicPtr<u8>; 3],

    // === Writer's cache line ===
    writer_idx: CacheAligned<AtomicUsize>,

    // === Reader's cache line ===
    reader_idx: CacheAligned<AtomicUsize>,

    // === Shared cache line ===
    shared_state: CacheAligned<SharedState>,
}

struct SharedState {
    middle_idx: AtomicUsize,
    generation: AtomicUsize,
    last_read_gen: AtomicUsize, // Track last generation read by reader
}

impl TripleBuffer {
    /// Create a new triple buffer
    /// Returns the buffer and the initial buffer for the writer to use
    pub fn new() -> (Self, AlignedBuffer) {
        let b0 = create_aligned_buffer();
        let b1 = create_aligned_buffer();
        let b2 = create_aligned_buffer();

        // Writer starts with buffer 0
        let writer_buffer = b0;

        let buffer = Self {
            buffers: [
                AtomicPtr::new(std::ptr::null_mut()), // Writer has this
                AtomicPtr::new(Box::into_raw(b1) as *mut u8),
                AtomicPtr::new(Box::into_raw(b2) as *mut u8),
            ],
            writer_idx: CacheAligned::new(AtomicUsize::new(0)),
            reader_idx: CacheAligned::new(AtomicUsize::new(1)),
            shared_state: CacheAligned::new(SharedState {
                middle_idx: AtomicUsize::new(2),
                generation: AtomicUsize::new(0),
                last_read_gen: AtomicUsize::new(0),
            }),
        };

        (buffer, writer_buffer)
    }

    /// Writer swaps its completed buffer with the middle buffer
    pub fn writer_swap(&self, completed: AlignedBuffer) -> AlignedBuffer {
        let completed_ptr = Box::into_raw(completed) as *mut u8;

        // Load current indices
        let writer_idx = self.writer_idx.value.load(Ordering::Acquire);
        let middle_idx = self.shared_state.value.middle_idx.load(Ordering::Acquire);

        // Put completed buffer in writer's slot (was empty)
        self.buffers[writer_idx].store(completed_ptr, Ordering::Release);

        // Swap indices
        self.writer_idx.value.store(middle_idx, Ordering::Release);
        self.shared_state
            .value
            .middle_idx
            .store(writer_idx, Ordering::Release);

        // Increment generation
        self.shared_state
            .value
            .generation
            .fetch_add(1, Ordering::Release);

        // Take buffer from what was middle (now writer's)
        let ptr = self.buffers[middle_idx].swap(std::ptr::null_mut(), Ordering::AcqRel);
        unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, BUFFER_SIZE)) }
    }

    /// Reader attempts to take the latest buffer
    pub fn reader_take(&self, previous: Option<AlignedBuffer>) -> Option<AlignedBuffer> {
        // Check for new data
        let generation = self.shared_state.value.generation.load(Ordering::Acquire);
        let last_read = self
            .shared_state
            .value
            .last_read_gen
            .load(Ordering::Acquire);

        if generation == 0 || generation == last_read {
            return previous; // No new data
        }

        // Update last read generation
        self.shared_state
            .value
            .last_read_gen
            .store(generation, Ordering::Release);

        // Get current indices
        let reader_idx = self.reader_idx.value.load(Ordering::Acquire);
        let middle_idx = self.shared_state.value.middle_idx.load(Ordering::Acquire);

        // Put back previous buffer if we have one
        if let Some(prev) = previous {
            let prev_ptr = Box::into_raw(prev) as *mut u8;
            self.buffers[reader_idx].store(prev_ptr, Ordering::Release);
        }

        // Swap indices
        self.reader_idx.value.store(middle_idx, Ordering::Release);
        self.shared_state
            .value
            .middle_idx
            .store(reader_idx, Ordering::Release);

        // Take buffer from what was middle (now reader's)
        let ptr = self.buffers[middle_idx].swap(std::ptr::null_mut(), Ordering::AcqRel);

        if ptr.is_null() {
            None // Middle was empty (shouldn't happen in normal flow)
        } else {
            Some(unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, BUFFER_SIZE)) })
        }
    }

    /// Get buffer statistics for debugging
    pub fn stats(&self) -> BufferStats {
        BufferStats {
            writer_idx: self.writer_idx.value.load(Ordering::Relaxed),
            reader_idx: self.reader_idx.value.load(Ordering::Relaxed),
            middle_idx: self.shared_state.value.middle_idx.load(Ordering::Relaxed),
            generation: self.shared_state.value.generation.load(Ordering::Relaxed),
        }
    }
}

/// Statistics about the triple buffer state
#[derive(Debug, Clone, Copy)]
pub struct BufferStats {
    pub writer_idx: usize,
    pub reader_idx: usize,
    pub middle_idx: usize,
    pub generation: usize,
}

impl Drop for TripleBuffer {
    fn drop(&mut self) {
        unsafe {
            // Free any remaining buffers
            for i in 0..3 {
                let ptr = self.buffers[i].load(Ordering::Relaxed);
                if !ptr.is_null() {
                    let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, BUFFER_SIZE));
                }
            }
        }
    }
}

unsafe impl Send for TripleBuffer {}
unsafe impl Sync for TripleBuffer {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_triple_buffer_basic() {
        let (triple_buffer, mut write_buf) = TripleBuffer::new();
        let buffer = Arc::new(triple_buffer);

        // Reader initially gets None (no data written yet)
        assert!(buffer.reader_take(None).is_none());

        // Writer fills buffer and swaps
        write_buf[0] = 42;
        let returned = buffer.writer_swap(write_buf);
        assert_eq!(returned.len(), BUFFER_SIZE);

        // Reader should now get a buffer with the data
        let read = buffer.reader_take(None);
        assert!(read.is_some());
        let read_buf = read.unwrap();
        assert_eq!(read_buf.len(), BUFFER_SIZE);
        assert_eq!(read_buf[0], 42);

        // Reader returns buffer and gets it back (no new data)
        let returned = buffer.reader_take(Some(read_buf));
        assert!(returned.is_some());
        assert_eq!(returned.unwrap()[0], 42); // Should be the same buffer
    }

    #[test]
    fn test_concurrent_access() {
        let (triple_buffer, writer_initial_buf) = TripleBuffer::new();
        let buffer = Arc::new(triple_buffer);
        let buffer_writer = Arc::clone(&buffer);
        let buffer_reader = Arc::clone(&buffer);

        // Writer thread
        let writer = thread::spawn(move || {
            let mut buf = writer_initial_buf;
            for i in 0..100 {
                // Write incrementing values
                buf[0] = i as u8;
                buf[1] = (i >> 8) as u8;
                buf = buffer_writer.writer_swap(buf);
                thread::sleep(Duration::from_micros(10));
            }
        });

        // Reader thread
        let reader = thread::spawn(move || {
            let mut current = None;
            let mut count = 0;
            let mut last_value = 0u16;

            for _ in 0..1000 {
                current = buffer_reader.reader_take(current);
                if let Some(ref buf) = current {
                    let value = buf[0] as u16 | ((buf[1] as u16) << 8);
                    // Values should never go backwards
                    assert!(
                        value >= last_value,
                        "Value went backwards: {} -> {}",
                        last_value,
                        value
                    );
                    if value > last_value {
                        count += 1;
                        last_value = value;
                    }
                }
                thread::sleep(Duration::from_micros(5));
            }

            assert!(count > 0, "Reader should have received some new buffers");
            count
        });

        writer.join().unwrap();
        let read_count = reader.join().unwrap();
        println!("Reader got {} unique values", read_count);
    }

    #[test]
    fn test_cache_alignment() {
        const CACHE_LINE_SIZE: usize = 64;

        // Verify cache-line alignment
        assert_eq!(
            std::mem::align_of::<CacheAligned<AtomicUsize>>(),
            CACHE_LINE_SIZE
        );

        // Verify fields are on separate cache lines
        let (buffer, _) = TripleBuffer::new();

        let writer_addr = &buffer.writer_idx as *const _ as usize;
        let reader_addr = &buffer.reader_idx as *const _ as usize;
        let shared_addr = &buffer.shared_state as *const _ as usize;

        // All should be cache-line aligned
        assert_eq!(writer_addr % CACHE_LINE_SIZE, 0);
        assert_eq!(reader_addr % CACHE_LINE_SIZE, 0);
        assert_eq!(shared_addr % CACHE_LINE_SIZE, 0);

        // Should be on different cache lines
        assert!(reader_addr.abs_diff(writer_addr) >= CACHE_LINE_SIZE);
        assert!(shared_addr.abs_diff(writer_addr) >= CACHE_LINE_SIZE);
        assert!(shared_addr.abs_diff(reader_addr) >= CACHE_LINE_SIZE);
    }
}

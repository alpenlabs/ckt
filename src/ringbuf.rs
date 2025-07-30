//! An optimized lock-free single-producer single-consumer ring buffer
//! supporting both synchronous and asynchronous operations.
//!
//! # Performance Optimizations
//! - Cached indices to minimize atomic operations
//! - Cache-line padding to prevent false sharing
//! - Lock-free design using atomic operations
//! - Zero-copy operations where possible

use std::alloc::{Layout, alloc, dealloc};
use std::cell::UnsafeCell;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Padding to prevent false sharing between atomic variables
#[repr(align(64))]
struct CachePadded<T> {
    value: T,
}

impl<T> CachePadded<T> {
    fn new(value: T) -> Self {
        Self { value }
    }
}

/// Shared ring buffer state
struct RingBufferShared<T> {
    /// Buffer capacity (must be power of 2)
    capacity: usize,
    /// Mask for wrapping indices (capacity - 1)
    mask: usize,
    /// Pointer to the buffer
    buffer: *mut MaybeUninit<T>,
    /// Layout for deallocation
    layout: Layout,

    /// Write index (updated by producer)
    write_index: CachePadded<AtomicUsize>,
    /// Read index (updated by consumer)
    read_index: CachePadded<AtomicUsize>,

    /// Producer waker for async operations
    producer_waker: CachePadded<UnsafeCell<Option<Waker>>>,
    /// Consumer waker for async operations
    consumer_waker: CachePadded<UnsafeCell<Option<Waker>>>,
    /// Flag to protect waker access
    producer_waker_set: AtomicBool,
    consumer_waker_set: AtomicBool,
}

unsafe impl<T: Send> Send for RingBufferShared<T> {}
unsafe impl<T: Send> Sync for RingBufferShared<T> {}

impl<T> Drop for RingBufferShared<T> {
    fn drop(&mut self) {
        unsafe {
            // Drop any remaining items
            let write = self.write_index.value.load(Ordering::Acquire);
            let read = self.read_index.value.load(Ordering::Acquire);

            let mut current = read;
            while current != write {
                let slot = self.buffer.add(current & self.mask);
                ptr::drop_in_place((*slot).as_mut_ptr());
                current = current.wrapping_add(1);
            }

            // Deallocate buffer
            dealloc(self.buffer as *mut u8, self.layout);
        }
    }
}

/// A heap-allocated ring buffer that can be split into producer/consumer pairs
pub struct RingBuffer<T> {
    shared: Arc<RingBufferShared<T>>,
}

impl<T> RingBuffer<T> {
    /// Create a new ring buffer with the specified capacity
    ///
    /// # Panics
    /// Panics if capacity is 0 or not a power of 2
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than 0");
        assert!(capacity.is_power_of_two(), "capacity must be a power of 2");

        // Allocate buffer
        let layout = Layout::array::<MaybeUninit<T>>(capacity).expect("capacity overflow");

        let buffer = unsafe {
            let ptr = alloc(layout) as *mut MaybeUninit<T>;
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            ptr
        };

        let shared = Arc::new(RingBufferShared {
            capacity,
            mask: capacity - 1,
            buffer,
            layout,
            write_index: CachePadded::new(AtomicUsize::new(0)),
            read_index: CachePadded::new(AtomicUsize::new(0)),
            producer_waker: CachePadded::new(UnsafeCell::new(None)),
            consumer_waker: CachePadded::new(UnsafeCell::new(None)),
            producer_waker_set: AtomicBool::new(false),
            consumer_waker_set: AtomicBool::new(false),
        });

        RingBuffer { shared }
    }

    /// Split the ring buffer into a producer/consumer pair
    pub fn split(self) -> (Producer<T>, Consumer<T>) {
        let producer = Producer {
            shared: self.shared.clone(),
            cached_read: 0,
            cached_write: 0,
            _marker: PhantomData,
        };

        let consumer = Consumer {
            shared: self.shared,
            cached_read: 0,
            cached_write: 0,
            _marker: PhantomData,
        };

        (producer, consumer)
    }
}

/// Producer half of the ring buffer
pub struct Producer<T> {
    shared: Arc<RingBufferShared<T>>,
    /// Cached read index to avoid atomic loads
    cached_read: usize,
    /// Cached write index to avoid atomic loads
    cached_write: usize,
    _marker: PhantomData<*mut T>, // !Send + !Sync
}

unsafe impl<T: Send> Send for Producer<T> {}

impl<T> Producer<T> {
    /// Try to push an item into the buffer
    ///
    /// Returns `Err(value)` if the buffer is full
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        let write = self.cached_write;
        let read = self.cached_read;

        // Check if buffer appears full based on cached indices
        if write.wrapping_sub(read) >= self.shared.capacity {
            // Update cached read index and check again
            self.cached_read = self.shared.read_index.value.load(Ordering::Acquire);

            if write.wrapping_sub(self.cached_read) >= self.shared.capacity {
                return Err(value);
            }
        }

        // Write the value
        unsafe {
            let slot = self.shared.buffer.add(write & self.shared.mask);
            (*slot).write(value);
        }

        // Update cached write index
        self.cached_write = write.wrapping_add(1);

        // Publish the write
        self.shared
            .write_index
            .value
            .store(self.cached_write, Ordering::Release);

        // Wake consumer if waiting
        if self.shared.consumer_waker_set.load(Ordering::Acquire) {
            self.wake_consumer();
        }

        Ok(())
    }

    /// Push an item asynchronously, waiting if the buffer is full
    pub async fn push(&mut self, mut value: T) {
        // First try synchronously
        match self.try_push(value) {
            Ok(()) => return,
            Err(v) => value = v,
        }

        // Create future for async push
        PushFuture {
            producer: self,
            value: Some(value),
        }
        .await
    }

    /// Try to push multiple items from a slice using bulk copy
    /// Returns the number of items successfully pushed
    pub fn try_push_slice(&mut self, items: &[T]) -> usize
    where
        T: Copy,
    {
        if items.is_empty() {
            return 0;
        }

        let write = self.cached_write;
        let read = self.cached_read;

        // Calculate available space
        let mut available = self
            .shared
            .capacity
            .saturating_sub(write.wrapping_sub(read));

        if available == 0 {
            // Update cached read index and check again
            self.cached_read = self.shared.read_index.value.load(Ordering::Acquire);
            available = self
                .shared
                .capacity
                .saturating_sub(write.wrapping_sub(self.cached_read));

            if available == 0 {
                return 0;
            }
        }

        let to_push = items.len().min(available);

        unsafe {
            // Calculate write position and contiguous space until wraparound
            let write_idx = write & self.shared.mask;
            let contiguous = (self.shared.capacity - write_idx).min(to_push);

            // First bulk copy
            ptr::copy_nonoverlapping(
                items.as_ptr(),
                self.shared.buffer.add(write_idx) as *mut T,
                contiguous,
            );

            // Second bulk copy if wrapped around
            if contiguous < to_push {
                ptr::copy_nonoverlapping(
                    items.as_ptr().add(contiguous),
                    self.shared.buffer as *mut T,
                    to_push - contiguous,
                );
            }
        }

        // Update cached write index
        self.cached_write = write.wrapping_add(to_push);

        // Publish the writes with a single atomic store
        self.shared
            .write_index
            .value
            .store(self.cached_write, Ordering::Release);

        // Wake consumer once if needed
        if self.shared.consumer_waker_set.load(Ordering::Acquire) {
            self.wake_consumer();
        }

        to_push
    }

    /// Push multiple items from a slice asynchronously
    /// Waits if the buffer becomes full until all items are pushed
    pub async fn push_slice(&mut self, items: &[T])
    where
        T: Copy,
    {
        if items.is_empty() {
            return;
        }

        // First try to push as many as possible synchronously
        let pushed = self.try_push_slice(items);

        if pushed == items.len() {
            return;
        }

        // Create a single future for remaining items
        PushSliceFuture {
            producer: self,
            items,
            pushed_so_far: pushed,
        }
        .await
    }

    /// Get the number of items that can be pushed without blocking
    pub fn free_count(&mut self) -> usize {
        self.cached_read = self.shared.read_index.value.load(Ordering::Acquire);
        let write = self.cached_write;
        let read = self.cached_read;

        self.shared.capacity - write.wrapping_sub(read)
    }

    /// Check if the buffer is empty from the producer's perspective
    pub fn is_empty(&mut self) -> bool {
        self.cached_read = self.shared.read_index.value.load(Ordering::Acquire);
        self.cached_write == self.cached_read
    }

    /// Check if the buffer is full
    pub fn is_full(&mut self) -> bool {
        self.free_count() == 0
    }

    /// Wake the consumer if it's waiting
    fn wake_consumer(&self) {
        if self.shared.consumer_waker_set.swap(false, Ordering::AcqRel) {
            unsafe {
                if let Some(waker) = (*self.shared.consumer_waker.value.get()).take() {
                    waker.wake();
                }
            }
        }
    }
}

impl std::io::Write for Producer<u8> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Use try_push_slice for more efficient bulk write
        Ok(self.try_push_slice(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        // Ring buffer doesn't need flushing
        Ok(())
    }
}

/// Consumer half of the ring buffer
pub struct Consumer<T> {
    shared: Arc<RingBufferShared<T>>,
    /// Cached read index to avoid atomic loads
    cached_read: usize,
    /// Cached write index to avoid atomic loads
    cached_write: usize,
    _marker: PhantomData<*mut T>, // !Send + !Sync
}

unsafe impl<T: Send> Send for Consumer<T> {}

impl<T> Consumer<T> {
    /// Try to pop an item from the buffer
    ///
    /// Returns `None` if the buffer is empty
    pub fn try_pop(&mut self) -> Option<T> {
        let read = self.cached_read;
        let write = self.cached_write;

        // Check if buffer appears empty based on cached indices
        if read == write {
            // Update cached write index and check again
            self.cached_write = self.shared.write_index.value.load(Ordering::Acquire);

            if read == self.cached_write {
                return None;
            }
        }

        // Read the value
        let value = unsafe {
            let slot = self.shared.buffer.add(read & self.shared.mask);
            (*slot).assume_init_read()
        };

        // Update cached read index
        self.cached_read = read.wrapping_add(1);

        // Publish the read
        self.shared
            .read_index
            .value
            .store(self.cached_read, Ordering::Release);

        // Wake producer if waiting
        if self.shared.producer_waker_set.load(Ordering::Acquire) {
            self.wake_producer();
        }

        Some(value)
    }

    /// Pop an item asynchronously, waiting if the buffer is empty
    pub async fn pop(&mut self) -> T {
        // First try synchronously
        if let Some(value) = self.try_pop() {
            return value;
        }

        // Create future for async pop
        PopFuture { consumer: self }.await
    }

    /// Try to pop multiple items into a slice using bulk copy
    /// Returns the number of items successfully popped
    pub fn try_pop_slice(&mut self, items: &mut [T]) -> usize
    where
        T: Copy,
    {
        if items.is_empty() {
            return 0;
        }

        let read = self.cached_read;
        let write = self.cached_write;

        // Calculate available items
        let mut available = write.wrapping_sub(read);

        if available == 0 {
            // Update cached write index and check again
            self.cached_write = self.shared.write_index.value.load(Ordering::Acquire);
            available = self.cached_write.wrapping_sub(read);

            if available == 0 {
                return 0;
            }
        }

        let to_pop = items.len().min(available);

        unsafe {
            // Calculate read position and contiguous items until wraparound
            let read_idx = read & self.shared.mask;
            let contiguous = (self.shared.capacity - read_idx).min(to_pop);

            // First bulk copy
            ptr::copy_nonoverlapping(
                self.shared.buffer.add(read_idx) as *const T,
                items.as_mut_ptr(),
                contiguous,
            );

            // Second bulk copy if wrapped around
            if contiguous < to_pop {
                ptr::copy_nonoverlapping(
                    self.shared.buffer as *const T,
                    items.as_mut_ptr().add(contiguous),
                    to_pop - contiguous,
                );
            }
        }

        // Update cached read index
        self.cached_read = read.wrapping_add(to_pop);

        // Publish the reads with a single atomic store
        self.shared
            .read_index
            .value
            .store(self.cached_read, Ordering::Release);

        // Wake producer once if needed
        if self.shared.producer_waker_set.load(Ordering::Acquire) {
            self.wake_producer();
        }

        to_pop
    }

    /// Pop multiple items into a slice asynchronously
    /// Waits if the buffer becomes empty until all items are popped
    pub async fn pop_slice(&mut self, items: &mut [T])
    where
        T: Copy,
    {
        if items.is_empty() {
            return;
        }

        // First try to pop as many as possible synchronously
        let popped = self.try_pop_slice(items);

        if popped == items.len() {
            return;
        }

        // Create a single future for remaining items
        PopSliceFuture {
            consumer: self,
            items,
            popped_so_far: popped,
        }
        .await
    }

    /// Get the number of items available to pop
    pub fn available_count(&mut self) -> usize {
        self.cached_write = self.shared.write_index.value.load(Ordering::Acquire);
        let write = self.cached_write;
        let read = self.cached_read;

        write.wrapping_sub(read)
    }

    /// Check if the buffer is empty
    pub fn is_empty(&mut self) -> bool {
        self.available_count() == 0
    }

    /// Check if the buffer is full from the consumer's perspective
    pub fn is_full(&mut self) -> bool {
        self.cached_write = self.shared.write_index.value.load(Ordering::Acquire);
        let write = self.cached_write;
        let read = self.cached_read;

        write.wrapping_sub(read) >= self.shared.capacity
    }

    /// Wake the producer if it's waiting
    fn wake_producer(&self) {
        if self.shared.producer_waker_set.swap(false, Ordering::AcqRel) {
            unsafe {
                if let Some(waker) = (*self.shared.producer_waker.value.get()).take() {
                    waker.wake();
                }
            }
        }
    }
}

impl std::io::Read for Consumer<u8> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Use try_pop_slice for more efficient bulk read
        Ok(self.try_pop_slice(buf))
    }
}

/// Future for async push operations
struct PushFuture<'a, T> {
    producer: &'a mut Producer<T>,
    value: Option<T>,
}

impl<'a, T> std::future::Future for PushFuture<'a, T> {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Use unsafe to project through the pin
        let this = unsafe { self.get_unchecked_mut() };

        let value = this
            .value
            .take()
            .expect("PushFuture polled after completion");

        match this.producer.try_push(value) {
            Ok(()) => Poll::Ready(()),
            Err(v) => {
                // Store waker for later wake-up
                unsafe {
                    *this.producer.shared.producer_waker.value.get() = Some(cx.waker().clone());
                }
                this.producer
                    .shared
                    .producer_waker_set
                    .store(true, Ordering::Release);

                // Store value back for next poll
                this.value = Some(v);

                Poll::Pending
            }
        }
    }
}

/// Future for async pop operations
struct PopFuture<'a, T> {
    consumer: &'a mut Consumer<T>,
}

impl<'a, T> std::future::Future for PopFuture<'a, T> {
    type Output = T;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Use unsafe to project through the pin
        let this = unsafe { self.get_unchecked_mut() };

        match this.consumer.try_pop() {
            Some(value) => Poll::Ready(value),
            None => {
                // Store waker for later wake-up
                unsafe {
                    *this.consumer.shared.consumer_waker.value.get() = Some(cx.waker().clone());
                }
                this.consumer
                    .shared
                    .consumer_waker_set
                    .store(true, Ordering::Release);

                Poll::Pending
            }
        }
    }
}

/// Future for async push slice operations
struct PushSliceFuture<'a, T> {
    producer: &'a mut Producer<T>,
    items: &'a [T],
    pushed_so_far: usize,
}

impl<'a, T: Copy> std::future::Future for PushSliceFuture<'a, T> {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // Try to push remaining items
        let remaining = &this.items[this.pushed_so_far..];
        let pushed = this.producer.try_push_slice(remaining);

        if pushed > 0 {
            this.pushed_so_far += pushed;

            if this.pushed_so_far == this.items.len() {
                // All items pushed
                return Poll::Ready(());
            }
        }

        // Register waker for when space becomes available
        unsafe {
            *this.producer.shared.producer_waker.value.get() = Some(cx.waker().clone());
        }
        this.producer
            .shared
            .producer_waker_set
            .store(true, Ordering::Release);

        Poll::Pending
    }
}

/// Future for async pop slice operations
struct PopSliceFuture<'a, T> {
    consumer: &'a mut Consumer<T>,
    items: &'a mut [T],
    popped_so_far: usize,
}

impl<'a, T: Copy> std::future::Future for PopSliceFuture<'a, T> {
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        // Try to pop remaining items
        let remaining = &mut this.items[this.popped_so_far..];
        let popped = this.consumer.try_pop_slice(remaining);

        if popped > 0 {
            this.popped_so_far += popped;

            if this.popped_so_far == this.items.len() {
                // All items popped
                return Poll::Ready(());
            }
        }

        // Register waker for when data becomes available
        unsafe {
            *this.consumer.shared.consumer_waker.value.get() = Some(cx.waker().clone());
        }
        this.consumer
            .shared
            .consumer_waker_set
            .store(true, Ordering::Release);

        Poll::Pending
    }
}

impl<T> fmt::Debug for RingBuffer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingBuffer")
            .field("capacity", &self.shared.capacity)
            .finish()
    }
}

impl<T> fmt::Debug for Producer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Producer")
            .field("cached_write", &self.cached_write)
            .field("cached_read", &self.cached_read)
            .finish()
    }
}

impl<T> fmt::Debug for Consumer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumer")
            .field("cached_write", &self.cached_write)
            .field("cached_read", &self.cached_read)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_push_pop() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        // Push some items
        assert!(producer.try_push(1).is_ok());
        assert!(producer.try_push(2).is_ok());
        assert!(producer.try_push(3).is_ok());
        assert!(producer.try_push(4).is_ok());

        // Buffer should be full
        assert!(producer.try_push(5).is_err());

        // Pop items
        assert_eq!(consumer.try_pop(), Some(1));
        assert_eq!(consumer.try_pop(), Some(2));
        assert_eq!(consumer.try_pop(), Some(3));
        assert_eq!(consumer.try_pop(), Some(4));

        // Buffer should be empty
        assert_eq!(consumer.try_pop(), None);
    }

    #[test]
    fn test_wraparound() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        // Fill and empty multiple times
        for i in 0..10 {
            assert!(producer.try_push(i).is_ok());
            assert_eq!(consumer.try_pop(), Some(i));
        }
    }

    #[test]
    fn test_io_write_read() {
        use std::io::{Read, Write};

        let rb = RingBuffer::<u8>::new(8);
        let (mut producer, mut consumer) = rb.split();

        // Test writing
        let data = b"hello";
        let written = producer.write(data).unwrap();
        assert_eq!(written, 5);

        // Test reading
        let mut buf = [0u8; 10];
        let read = consumer.read(&mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");

        // Test partial write when buffer is almost full
        let written = producer.write(b"world!").unwrap();
        assert_eq!(written, 3);
    }

    #[test]
    fn test_io_write_read_chunks() {
        use std::io::{Read, Write};

        let rb = RingBuffer::<u8>::new(16);
        let (mut producer, mut consumer) = rb.split();

        // Write a larger chunk
        let data = b"0123456789ABCDEF";
        let written = producer.write(data).unwrap();
        assert_eq!(written, 16);

        // Try to write more (should return 0)
        let written = producer.write(b"X").unwrap();
        assert_eq!(written, 0);

        // Read in smaller chunks
        let mut buf = [0u8; 4];
        for expected in [b"0123", b"4567", b"89AB", b"CDEF"] {
            let read = consumer.read(&mut buf).unwrap();
            assert_eq!(read, 4);
            assert_eq!(&buf[..], expected);
        }

        // Buffer should be empty now
        let read = consumer.read(&mut buf).unwrap();
        assert_eq!(read, 0);
    }

    #[test]
    fn test_counts() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        assert_eq!(producer.free_count(), 4);
        assert_eq!(consumer.available_count(), 0);

        producer.try_push(1).unwrap();
        producer.try_push(2).unwrap();

        assert_eq!(producer.free_count(), 2);
        assert_eq!(consumer.available_count(), 2);

        consumer.try_pop().unwrap();

        assert_eq!(producer.free_count(), 3);
        assert_eq!(consumer.available_count(), 1);
    }

    #[test]
    fn test_empty_full_checks() {
        let rb = RingBuffer::new(2);
        let (mut producer, mut consumer) = rb.split();

        assert!(producer.is_empty());
        assert!(consumer.is_empty());
        assert!(!producer.is_full());
        assert!(!consumer.is_full());

        producer.try_push(1).unwrap();

        assert!(!producer.is_empty());
        assert!(!consumer.is_empty());
        assert!(!producer.is_full());
        assert!(!consumer.is_full());

        producer.try_push(2).unwrap();

        assert!(!producer.is_empty());
        assert!(!consumer.is_empty());
        assert!(producer.is_full());
        assert!(consumer.is_full());
    }

    #[monoio::test]
    async fn test_async_push_pop() {
        let rb = RingBuffer::new(2);
        let (mut producer, mut consumer) = rb.split();

        // Push items
        producer.push(1).await;
        producer.push(2).await;

        // Pop items
        assert_eq!(consumer.pop().await, 1);
        assert_eq!(consumer.pop().await, 2);
    }

    #[monoio::test]
    async fn test_async_producer_consumer() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        let producer_task = monoio::spawn(async move {
            for i in 0..10 {
                producer.push(i).await;
            }
        });

        let consumer_task = monoio::spawn(async move {
            let mut sum = 0;
            for _ in 0..10 {
                sum += consumer.pop().await;
            }
            sum
        });

        producer_task.await;
        let sum = consumer_task.await;
        assert_eq!(sum, 45); // 0 + 1 + 2 + ... + 9
    }

    #[monoio::test]
    async fn test_async_push_pop_slice() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        // Test async push slice
        let data = [10, 20, 30, 40];
        producer.push_slice(&data).await;

        // Test async pop slice
        let mut buf = [0; 4];
        consumer.pop_slice(&mut buf).await;
        assert_eq!(buf, [10, 20, 30, 40]);
    }

    #[monoio::test]
    async fn test_async_slice_partial_operations() {
        let rb = RingBuffer::new(4);
        let (mut producer, mut consumer) = rb.split();

        // Test pushing more items than capacity
        let producer_task = monoio::spawn(async move {
            let data = [1, 2, 3, 4, 5, 6, 7, 8];
            producer.push_slice(&data).await;
            producer
        });

        // Consumer reads in smaller chunks
        let consumer_task = monoio::spawn(async move {
            let mut total = vec![];

            // Read first chunk
            let mut buf1 = [0; 3];
            consumer.pop_slice(&mut buf1).await;
            total.extend_from_slice(&buf1);

            // Read second chunk
            let mut buf2 = [0; 3];
            consumer.pop_slice(&mut buf2).await;
            total.extend_from_slice(&buf2);

            // Read remaining
            let mut buf3 = [0; 2];
            consumer.pop_slice(&mut buf3).await;
            total.extend_from_slice(&buf3);

            total
        });

        producer_task.await;
        let result = consumer_task.await;
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_async_slice_blocking_behavior() {
        let rb = RingBuffer::new(2);
        let (mut producer, mut consumer) = rb.split();

        // Fill the buffer
        producer.try_push(1).unwrap();
        producer.try_push(2).unwrap();

        // This should block until consumer reads
        let producer_task = monoio::spawn(async move {
            let data = [3, 4];
            producer.push_slice(&data).await;
            true
        });

        // Give producer time to block
        monoio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Consumer reads, unblocking producer
        let mut buf = [0; 2];
        consumer.pop_slice(&mut buf).await;
        assert_eq!(buf, [1, 2]);

        // Now producer should complete
        let completed = producer_task.await;
        assert!(completed);

        // Verify the new data
        let mut buf = [0; 2];
        consumer.pop_slice(&mut buf).await;
        assert_eq!(buf, [3, 4]);
    }

    #[test]
    fn test_bulk_vs_individual_performance() {
        use std::time::Instant;

        const BUFFER_SIZE: usize = 1024;
        const DATA_SIZE: usize = 100_000;

        // Test individual operations
        let rb = RingBuffer::<u8>::new(BUFFER_SIZE);
        let (mut producer, mut consumer) = rb.split();

        let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 256) as u8).collect();
        let mut output = vec![0u8; DATA_SIZE];

        let start = Instant::now();
        let mut written = 0;
        while written < DATA_SIZE {
            // Write one by one
            if let Ok(()) = producer.try_push(data[written]) {
                written += 1;
            }

            // Read one by one
            let mut read = 0;
            while let Some(byte) = consumer.try_pop() {
                if written - read > 0 {
                    output[written - read - 1] = byte;
                    read += 1;
                }
            }
        }

        // Drain remaining
        let mut pos = written;
        while let Some(byte) = consumer.try_pop() {
            if pos < DATA_SIZE {
                output[pos] = byte;
                pos += 1;
            }
        }

        let individual_time = start.elapsed();

        // Test bulk operations
        let rb = RingBuffer::<u8>::new(BUFFER_SIZE);
        let (mut producer, mut consumer) = rb.split();
        let mut output2 = vec![0u8; DATA_SIZE];

        let start = Instant::now();
        let mut written = 0;
        let mut read = 0;

        while written < DATA_SIZE || read < DATA_SIZE {
            // Write in chunks
            if written < DATA_SIZE {
                let chunk_size = (DATA_SIZE - written).min(512);
                let pushed = producer.try_push_slice(&data[written..written + chunk_size]);
                written += pushed;
            }

            // Read in chunks
            if read < DATA_SIZE {
                let chunk_size = (DATA_SIZE - read).min(512);
                let popped = consumer.try_pop_slice(&mut output2[read..read + chunk_size]);
                read += popped;
            }
        }

        let bulk_time = start.elapsed();

        // Verify correctness
        assert_eq!(
            &data[..],
            &output2[..],
            "Bulk operations produced different results"
        );

        // Print performance comparison (bulk should be significantly faster)
        println!("Individual operations: {:?}", individual_time);
        println!("Bulk operations: {:?}", bulk_time);
        println!(
            "Speedup: {:.2}x",
            individual_time.as_secs_f64() / bulk_time.as_secs_f64()
        );

        // Assert bulk is at least 2x faster (conservative estimate)
        assert!(
            bulk_time < individual_time / 2,
            "Bulk operations should be at least 2x faster"
        );
    }
}

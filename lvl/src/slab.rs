use roaring::RoaringBitmap;

pub struct FakeSlabAllocator {
    next_free: usize,
    free_list: RoaringBitmap,
    max_allocated: usize, // Track peak allocation count
}

impl FakeSlabAllocator {
    /// Create a new allocator starting from index 0
    pub fn new() -> Self {
        Self {
            next_free: 0,
            free_list: RoaringBitmap::new(),
            max_allocated: 0,
        }
    }

    /// Create a new allocator with a specific starting index
    pub fn with_starting_index(start: usize) -> Self {
        Self {
            next_free: start,
            free_list: RoaringBitmap::new(),
            max_allocated: 0,
        }
    }

    /// Allocate and return the next available index
    pub fn allocate(&mut self) -> usize {
        let index = if let Some(free_index) = self.free_list.min() {
            // Remove from free list and return it
            self.free_list.remove(free_index);
            free_index as usize
        } else {
            // No recycled indices, use the next fresh one
            let index = self.next_free;
            self.next_free += 1;
            index
        };

        // Update max_allocated if we've hit a new peak
        let current_allocated = self.allocated_count();
        if current_allocated > self.max_allocated {
            self.max_allocated = current_allocated;
        }

        index
    }

    /// Deallocate an index, making it available for reuse
    pub fn deallocate(&mut self, index: usize) {
        // Add to free list for future reuse
        // Only add if it's less than next_free (was previously allocated)
        if index < self.next_free && !self.free_list.contains(index as u32) {
            self.free_list.insert(index as u32);
        }
    }

    /// Check if an index is currently allocated
    pub fn is_allocated(&self, index: usize) -> bool {
        index < self.next_free && !self.free_list.contains(index as u32)
    }

    /// Get the count of currently allocated slots
    pub fn allocated_count(&self) -> usize {
        self.next_free - self.free_list.len() as usize
    }

    /// Get the total number of indices ever allocated (including recycled ones)
    pub fn total_allocated(&self) -> usize {
        self.next_free
    }

    /// Get the maximum number of slots that were allocated concurrently
    pub fn max_allocated_concurrently(&self) -> usize {
        self.max_allocated
    }

    /// Reset the max allocated counter (useful for monitoring periods)
    pub fn reset_max_allocated(&mut self) {
        self.max_allocated = self.allocated_count();
    }
}

// Example usage
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_allocated_tracking() {
        let mut allocator = FakeSlabAllocator::new();

        // Allocate 5 indices
        let indices: Vec<usize> = (0..5).map(|_| allocator.allocate()).collect();

        // Max should be 5
        assert_eq!(allocator.max_allocated_concurrently(), 5);
        assert_eq!(allocator.allocated_count(), 5);

        // Deallocate 2 indices
        allocator.deallocate(indices[1]);
        allocator.deallocate(indices[3]);

        // Current is 3, but max remains 5
        assert_eq!(allocator.allocated_count(), 3);
        assert_eq!(allocator.max_allocated_concurrently(), 5);

        // Allocate 4 more (reusing 2 freed + 2 new)
        for _ in 0..4 {
            allocator.allocate();
        }

        // Now we have 7 allocated, which is a new peak
        assert_eq!(allocator.allocated_count(), 7);
        assert_eq!(allocator.max_allocated_concurrently(), 7);

        // Deallocate everything
        for i in 0..7 {
            allocator.deallocate(i);
        }

        // Current is 0, but max remains 7
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.max_allocated_concurrently(), 7);
    }

    #[test]
    fn test_reset_max_allocated() {
        let mut allocator = FakeSlabAllocator::new();

        // Create a peak of 3
        let _idx1 = allocator.allocate();
        let idx2 = allocator.allocate();
        let _idx3 = allocator.allocate();

        assert_eq!(allocator.max_allocated_concurrently(), 3);

        // Deallocate one
        allocator.deallocate(idx2);
        assert_eq!(allocator.allocated_count(), 2);

        // Reset max to current
        allocator.reset_max_allocated();
        assert_eq!(allocator.max_allocated_concurrently(), 2);

        // Allocate more to create new peak
        allocator.allocate();
        allocator.allocate();
        allocator.allocate();

        assert_eq!(allocator.max_allocated_concurrently(), 5);
    }
}

use std::alloc::{alloc, dealloc, realloc, Layout};
use std::marker::PhantomData;
use std::mem;
use std::ops::{Index, IndexMut};
use std::ptr::{self, NonNull};

#[repr(C)]
pub struct ThinVecInternal {
    len: usize,      // length
    capacity: usize, // capacity
}

/// A Vec with its length and capacity on the heap with the elements.
pub struct ThinVec<T> {
    ptr: NonNull<ThinVecInternal>,
    _marker: PhantomData<T>,
}

/// Iterator over ThinVec elements
pub struct ThinVecIter<'a, T> {
    data: *const T,
    len: usize,
    current: usize,
    _marker: PhantomData<&'a T>,
}

impl<'a, T> Iterator for ThinVecIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.len {
            unsafe {
                let item = &*self.data.add(self.current);
                self.current += 1;
                Some(item)
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.current;
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for ThinVecIter<'a, T> {
    fn len(&self) -> usize {
        self.len - self.current
    }
}

/// Mutable iterator over ThinVec elements
pub struct ThinVecIterMut<'a, T> {
    data: *mut T,
    len: usize,
    current: usize,
    _marker: PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for ThinVecIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.len {
            unsafe {
                let item = &mut *self.data.add(self.current);
                self.current += 1;
                Some(item)
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.current;
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for ThinVecIterMut<'a, T> {
    fn len(&self) -> usize {
        self.len - self.current
    }
}

/// Owning iterator over ThinVec elements
pub struct ThinVecIntoIter<T> {
    vec: ThinVec<T>,
    current: usize,
}

impl<T> Iterator for ThinVecIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.vec.len() {
            unsafe {
                let item = ptr::read(self.vec.data_ptr().add(self.current));
                self.current += 1;
                Some(item)
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.vec.len() - self.current;
        (remaining, Some(remaining))
    }
}

impl<T> ExactSizeIterator for ThinVecIntoIter<T> {
    fn len(&self) -> usize {
        self.vec.len() - self.current
    }
}

impl<T> Drop for ThinVecIntoIter<T> {
    fn drop(&mut self) {
        // Drop any remaining elements
        while self.next().is_some() {}
    }
}

impl<T> ThinVec<T> {
    /// Creates a new empty ThinVec
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Creates a new ThinVec with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let header_layout = Layout::new::<ThinVecInternal>();
        let elem_layout = Layout::array::<T>(capacity).expect("Layout calculation failed");

        let (layout, _) = header_layout
            .extend(elem_layout)
            .expect("Layout extension failed");

        let ptr = unsafe {
            let ptr = if capacity == 0 {
                // Allocate just the header for zero capacity
                alloc(header_layout) as *mut ThinVecInternal
            } else {
                alloc(layout) as *mut ThinVecInternal
            };

            if ptr.is_null() {
                panic!("allocation failed");
            }

            (*ptr).len = 0;
            (*ptr).capacity = capacity;
            NonNull::new_unchecked(ptr)
        };

        ThinVec {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Consumes the ThinVec and returns a raw pointer to the header
    ///
    /// # Safety
    /// The caller is responsible for:
    /// - Properly dropping all elements
    /// - Deallocating the memory
    /// - Not using the pointer after it's been freed
    pub unsafe fn into_raw(self) -> *mut ThinVecInternal {
        let ptr = self.ptr.as_ptr();
        mem::forget(self);
        ptr
    }

    /// Constructs a ThinVec from a raw pointer to the header
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The pointer was obtained from `into_raw`
    /// - The pointer hasn't been freed
    /// - The header and data are still valid
    /// - No other ThinVec owns this allocation
    pub unsafe fn from_raw(ptr: *mut ThinVecInternal) -> Self {
        ThinVec {
            ptr: NonNull::new_unchecked(ptr),
            _marker: PhantomData,
        }
    }

    /// Returns the number of elements
    #[inline]
    pub fn len(&self) -> usize {
        unsafe { (*self.ptr.as_ptr()).len }
    }

    /// Returns true if the vector contains no elements
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe { (*self.ptr.as_ptr()).capacity }
    }

    /// Returns a pointer to the data area
    #[inline]
    fn data_ptr(&self) -> *mut T {
        unsafe {
            // Calculate pointer to data immediately after header
            let header_ptr = self.ptr.as_ptr() as *mut u8;
            let header_size = mem::size_of::<ThinVecInternal>();
            // Align the data pointer properly for type T
            let align = mem::align_of::<T>();
            let data_offset = (header_size + align - 1) / align * align;
            header_ptr.add(data_offset) as *mut T
        }
    }

    /// Returns an iterator over the elements
    pub fn iter(&self) -> ThinVecIter<T> {
        ThinVecIter {
            data: self.data_ptr(),
            len: self.len(),
            current: 0,
            _marker: PhantomData,
        }
    }

    /// Returns a mutable iterator over the elements
    pub fn iter_mut(&mut self) -> ThinVecIterMut<T> {
        ThinVecIterMut {
            data: self.data_ptr(),
            len: self.len(),
            current: 0,
            _marker: PhantomData,
        }
    }

    /// Checks if the vector contains the given value
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        let len = self.len();
        let data = self.data_ptr();

        unsafe {
            for i in 0..len {
                if &*data.add(i) == value {
                    return true;
                }
            }
        }
        false
    }

    /// Pushes a new element to the vector
    pub fn push(&mut self, value: T) {
        let len = self.len();
        let capacity = self.capacity();

        if len == capacity {
            self.grow();
        }

        unsafe {
            let data = self.data_ptr();
            ptr::write(data.add(len), value);
            (*self.ptr.as_ptr()).len = len + 1;
        }
    }

    /// Gets a reference to the element at the given index
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len() {
            unsafe { Some(&*self.data_ptr().add(index)) }
        } else {
            None
        }
    }

    /// Gets a mutable reference to the element at the given index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len() {
            unsafe { Some(&mut *self.data_ptr().add(index)) }
        } else {
            None
        }
    }

    /// Removes the last element and returns it, or None if empty
    pub fn pop(&mut self) -> Option<T> {
        let len = self.len();
        if len == 0 {
            None
        } else {
            unsafe {
                (*self.ptr.as_ptr()).len = len - 1;
                Some(ptr::read(self.data_ptr().add(len - 1)))
            }
        }
    }

    /// Clears the vector, removing all values
    pub fn clear(&mut self) {
        let len = self.len();
        unsafe {
            let data = self.data_ptr();
            for i in 0..len {
                ptr::drop_in_place(data.add(i));
            }
            (*self.ptr.as_ptr()).len = 0;
        }
    }

    /// Grows the capacity (doubles it, or sets to 4 if 0)
    fn grow(&mut self) {
        let old_capacity = self.capacity();
        let new_capacity = if old_capacity == 0 {
            4
        } else {
            old_capacity * 2
        };

        let header_layout = Layout::new::<ThinVecInternal>();
        let old_elem_layout = if old_capacity == 0 {
            Layout::new::<()>()
        } else {
            Layout::array::<T>(old_capacity).expect("Layout failed")
        };
        let new_elem_layout = Layout::array::<T>(new_capacity).expect("Layout failed");

        let (old_layout, _) = header_layout
            .extend(old_elem_layout)
            .expect("Layout failed");
        let (new_layout, _) = header_layout
            .extend(new_elem_layout)
            .expect("Layout failed");

        unsafe {
            let new_ptr = if old_capacity == 0 {
                alloc(new_layout) as *mut ThinVecInternal
            } else {
                realloc(self.ptr.as_ptr() as *mut u8, old_layout, new_layout.size())
                    as *mut ThinVecInternal
            };

            if new_ptr.is_null() {
                panic!("reallocation failed");
            }

            self.ptr = NonNull::new_unchecked(new_ptr);
            (*self.ptr.as_ptr()).capacity = new_capacity;
        }
    }
}

// Implement IntoIterator for ThinVec
impl<T> IntoIterator for ThinVec<T> {
    type Item = T;
    type IntoIter = ThinVecIntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        ThinVecIntoIter {
            vec: self,
            current: 0,
        }
    }
}

// Implement IntoIterator for &ThinVec
impl<'a, T> IntoIterator for &'a ThinVec<T> {
    type Item = &'a T;
    type IntoIter = ThinVecIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// Implement IntoIterator for &mut ThinVec
impl<'a, T> IntoIterator for &'a mut ThinVec<T> {
    type Item = &'a mut T;
    type IntoIter = ThinVecIterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

// Implement Index trait for immutable indexing
impl<T> Index<usize> for ThinVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= self.len() {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.len(),
                index
            );
        }
        unsafe { &*self.data_ptr().add(index) }
    }
}

// Implement IndexMut trait for mutable indexing
impl<T> IndexMut<usize> for ThinVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let len = self.len();
        if index >= len {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                len, index
            );
        }
        unsafe { &mut *self.data_ptr().add(index) }
    }
}

// Implement Drop to clean up memory
impl<T> Drop for ThinVec<T> {
    fn drop(&mut self) {
        unsafe {
            // Drop all elements
            self.clear();

            // Deallocate memory
            let header_layout = Layout::new::<ThinVecInternal>();
            let capacity = self.capacity();
            let elem_layout = if capacity == 0 {
                Layout::new::<()>()
            } else {
                Layout::array::<T>(capacity).expect("Layout failed")
            };
            let (layout, _) = header_layout.extend(elem_layout).expect("Layout failed");

            dealloc(self.ptr.as_ptr() as *mut u8, layout);
        }
    }
}

// Implement Clone where T is Clone
impl<T: Clone> Clone for ThinVec<T> {
    fn clone(&self) -> Self {
        let mut new = Self::with_capacity(self.capacity());
        let len = self.len();
        let data = self.data_ptr();

        unsafe {
            for i in 0..len {
                new.push((*data.add(i)).clone());
            }
        }
        new
    }
}

// Implement Debug where T is Debug
impl<T: std::fmt::Debug> std::fmt::Debug for ThinVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        let len = self.len();
        let data = self.data_ptr();

        unsafe {
            for i in 0..len {
                list.entry(&*data.add(i));
            }
        }
        list.finish()
    }
}

// Safe Send/Sync impls
unsafe impl<T: Send> Send for ThinVec<T> {}
unsafe impl<T: Sync> Sync for ThinVec<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut vec: ThinVec<i32> = ThinVec::new();
        assert_eq!(vec.len(), 0);
        assert_eq!(vec.capacity(), 0);

        vec.push(10);
        vec.push(20);
        vec.push(30);

        assert_eq!(vec.len(), 3);
        assert!(vec.capacity() >= 3);
        assert!(vec.contains(&20));
        assert!(!vec.contains(&40));

        assert_eq!(vec.pop(), Some(30));
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn test_indexing() {
        let mut vec: ThinVec<i32> = ThinVec::new();
        vec.push(10);
        vec.push(20);
        vec.push(30);

        assert_eq!(vec[0], 10);
        assert_eq!(vec[1], 20);
        assert_eq!(vec[2], 30);

        vec[1] = 99;
        assert_eq!(vec[1], 99);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_indexing_out_of_bounds() {
        let vec: ThinVec<i32> = ThinVec::new();
        let _ = vec[0];
    }

    #[test]
    fn test_raw_pointer_roundtrip() {
        let mut vec: ThinVec<String> = ThinVec::with_capacity(10);
        vec.push("hello".to_string());
        vec.push("world".to_string());

        unsafe {
            let raw = vec.into_raw();
            let vec2 = ThinVec::<String>::from_raw(raw);
            assert_eq!(vec2.len(), 2);
            assert_eq!(vec2.get(0).map(|s| s.as_str()), Some("hello"));
        }
    }

    #[test]
    fn test_iterator() {
        let mut vec: ThinVec<i32> = ThinVec::new();
        vec.push(10);
        vec.push(20);
        vec.push(30);

        let collected: Vec<&i32> = vec.iter().collect();
        assert_eq!(collected, vec![&10, &20, &30]);

        let collected: Vec<i32> = vec.into_iter().collect();
        assert_eq!(collected, vec![10, 20, 30]);
    }

    #[test]
    fn test_mutable_iterator() {
        let mut vec: ThinVec<i32> = ThinVec::new();
        vec.push(10);
        vec.push(20);
        vec.push(30);

        for item in vec.iter_mut() {
            *item *= 2;
        }

        assert_eq!(vec[0], 20);
        assert_eq!(vec[1], 40);
        assert_eq!(vec[2], 60);
    }

    #[test]
    fn test_for_loop() {
        let mut vec: ThinVec<i32> = ThinVec::new();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        let mut sum = 0;
        for &item in &vec {
            sum += item;
        }
        assert_eq!(sum, 6);
    }
}

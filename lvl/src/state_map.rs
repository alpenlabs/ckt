//! Safe, high-level API for wire state management.
//!
//! This module encapsulates the internal slotted hash map implementation behind a safe,
//! lifetime-based API. The core design uses a compression scheme where:
//! - 34-bit wire IDs are split: lower 32 bits → HashMap key, upper 2 bits → slot index
//! - Each HashMap entry has 4 slots to handle collisions from this compression
//! - Slots store wire states (Available, WaitingInline, or Waiting) in packed unions
//!
//! # Safety
//! All unsafe code is private and protected by Rust's borrow checker. The public API
//! (`WireStateMap`) provides only safe operations with proper lifetime management.

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use cynosure::hints::cold_and_empty;
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use crate::types::{CompactDependency, CompactWireId, Credits, WireAvailability};

// ============================================================================
// Internal implementation types (moved from types.rs for encapsulation)
// ============================================================================

/// Internal: Heap-allocated set of dependencies waiting on a wire.
type DepSet = HashSet<CompactDependency>;

/// Internal: RAII guards for safe in-place mutation of slot contents.
///
/// These guards temporarily take ownership of slot data, allowing mutation
/// without cloning. The data is automatically written back on drop.
pub(crate) enum WireAvailabilityMut<'a> {
    Available(AvailableGuard<'a>),
    WaitingInline(InlineGuard<'a>),
    Waiting(WaitingSetGuard<'a>),
}

/// Internal: Guard for mutating available wire credits.
///
/// Holds a raw pointer to the slot's Wire union. The lifetime ensures the
/// SlottedValue cannot be moved or dropped while this guard exists.
pub struct AvailableGuard<'a> {
    slot_ptr: *mut Wire,
    _l: PhantomData<&'a mut SlottedValue>,
}

impl<'a> AvailableGuard<'a> {
    fn get(&self) -> Credits {
        unsafe {
            let p = std::ptr::addr_of!((*self.slot_ptr).credits);
            Credits(std::ptr::read_unaligned(p))
        }
    }
    fn set(&mut self, c: Credits) {
        unsafe {
            let p = std::ptr::addr_of_mut!((*self.slot_ptr).credits);
            std::ptr::write_unaligned(p, c.0);
        }
    }
    fn update<F: FnOnce(&mut Credits)>(&mut self, f: F) {
        let mut v = self.get();
        f(&mut v);
        self.set(v);
    }
}

/// Internal: Guard for mutating inline dependency storage.
///
/// The dependency is read into `tmp` on creation and written back to the
/// slot on drop, allowing safe mutation of the packed bytes.
pub(crate) struct InlineGuard<'a> {
    slot_ptr: *mut Wire,
    tmp: CompactDependency,
    _l: PhantomData<&'a mut SlottedValue>,
}

impl<'a> InlineGuard<'a> {
    fn get(&self) -> CompactDependency {
        self.tmp
    }
    fn set(&mut self, dep: CompactDependency) {
        self.tmp = dep;
    }
}

impl<'a> Drop for InlineGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            let p = std::ptr::addr_of_mut!((*self.slot_ptr).waiting_inline);
            std::ptr::write_unaligned(p, self.tmp.bytes);
        }
    }
}

/// Internal: Guard for mutating a heap-allocated dependency set.
///
/// Takes ownership of the Box by setting the slot pointer to null (as a "lock").
/// The Box is restored to the slot on drop. If the pointer is already null when
/// accessed, it means another guard is active (prevented by borrow checker in safe code).
pub(crate) struct WaitingSetGuard<'a> {
    slot_ptr: *mut Wire,
    set: Option<Box<DepSet>>,
    _l: PhantomData<&'a mut SlottedValue>,
}

impl<'a> Deref for WaitingSetGuard<'a> {
    type Target = DepSet;
    fn deref(&self) -> &Self::Target {
        self.set.as_ref().expect("set already taken")
    }
}

impl<'a> DerefMut for WaitingSetGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.set.as_mut().expect("set already taken")
    }
}

impl<'a> Drop for WaitingSetGuard<'a> {
    fn drop(&mut self) {
        if let Some(set) = self.set.take() {
            let ptr = Box::into_raw(set);
            unsafe {
                std::ptr::write_unaligned(
                    std::ptr::addr_of_mut!((*self.slot_ptr).waiting_ptr),
                    ptr,
                );
            }
        }
    }
}

/// Internal: Packed union for storing different wire state types.
///
/// Uses `#[repr(packed)]` to minimize memory overhead. All access must use
/// unaligned reads/writes.
#[repr(C, packed)]
union Wire {
    credits: u32,             // Credits (4 bytes) - only lower 24 bits used
    waiting_inline: [u8; 12], // Single CompactDependency (12 bytes)
    waiting_ptr: *mut DepSet, // Multiple dependencies using HashSet
}

/// Internal: Slotted storage for handling 34-bit wire IDs in a 32-bit HashMap.
///
/// The compression scheme uses:
/// - Lower 32 bits of wire ID → HashMap key
/// - Upper 2 bits of wire ID → slot index (0-3)
///
/// This allows 2^34 unique wire IDs using only 2^32 HashMap entries, with each
/// entry containing 4 slots for collision handling.
///
/// # Mask Encoding (2 bits per slot)
/// - `00` (0): Empty
/// - `01` (1): Available (contains Credits)
/// - `10` (2): Waiting with HashSet (contains pointer)
/// - `11` (3): Waiting inline (contains CompactDependency bytes)
#[repr(C, packed)]
struct SlottedValue {
    mask: u8,
    slots: [Wire; 4],
}

impl SlottedValue {
    fn new() -> Self {
        Self {
            mask: 0,
            slots: std::array::from_fn(|_| Wire {
                waiting_ptr: std::ptr::null_mut(),
            }),
        }
    }

    /// Returns a guard for safe mutation of the slot, or None if empty.
    ///
    /// For waiting sets (mask_bits == 2), implements a "null sentinel lock":
    /// - Reads the pointer and sets it to null
    /// - Returns a guard that owns the Box
    /// - On drop, the guard writes the pointer back
    /// - If pointer is already null, returns None (guard is active elsewhere)
    fn get_slot_mut(&mut self, wire_id: CompactWireId) -> Option<WireAvailabilityMut<'_>> {
        let wire_id_u64 = wire_id.to_u64();
        let slot_idx = ((wire_id_u64 >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;
        let slot_ptr: *mut Wire = unsafe { self.slots.as_mut_ptr().add(slot_idx) };

        match mask_bits {
            0 => None,
            1 => Some(WireAvailabilityMut::Available(AvailableGuard {
                slot_ptr,
                _l: PhantomData,
            })),
            2 => {
                // Read pointer unaligned
                let ptr = unsafe {
                    std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).waiting_ptr))
                };
                if ptr.is_null() {
                    None
                } else {
                    // LOCK: write null back so a second call can't from_raw the same allocation
                    unsafe {
                        std::ptr::write_unaligned(
                            std::ptr::addr_of_mut!((*slot_ptr).waiting_ptr),
                            std::ptr::null_mut(),
                        );
                    }
                    let set = unsafe { Box::from_raw(ptr) };
                    Some(WireAvailabilityMut::Waiting(WaitingSetGuard {
                        slot_ptr,
                        set: Some(set),
                        _l: PhantomData,
                    }))
                }
            }
            3 => {
                let bytes = unsafe {
                    std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).waiting_inline))
                };
                Some(WireAvailabilityMut::WaitingInline(InlineGuard {
                    slot_ptr,
                    tmp: CompactDependency { bytes },
                    _l: PhantomData,
                }))
            }
            _ => unreachable!(),
        }
    }

    /// Sets a slot to the given value, clearing any previous contents.
    fn set_slot(&mut self, wire_id: CompactWireId, value: WireAvailability) {
        let wire_id_u64 = wire_id.to_u64();
        let slot_idx = ((wire_id_u64 >> 32) & 0x3) as usize;

        // Clear existing slot if occupied
        self.clear_slot_internal(slot_idx);

        // Clear mask bits for this slot
        self.mask &= !(0x3 << (slot_idx * 2));

        match value {
            WireAvailability::Available(credits) => {
                // Set mask bits to 01
                self.mask |= 1 << (slot_idx * 2);
                self.slots[slot_idx] = Wire { credits: credits.0 };
            }
            WireAvailability::WaitingInline(dep) => {
                // Single dependency - use inline storage
                self.mask |= 3 << (slot_idx * 2);
                self.slots[slot_idx] = Wire {
                    waiting_inline: dep.bytes,
                };
            }
            WireAvailability::Waiting(set) => {
                // Multiple dependencies - use HashSet
                self.mask |= 2 << (slot_idx * 2);
                let ptr = Box::into_raw(Box::new(set));
                self.slots[slot_idx] = Wire { waiting_ptr: ptr };
            }
        };
    }

    /// Removes and returns a slot's value, indicating if all slots are now empty.
    ///
    /// Returns `(None, _)` if the slot is empty or if a guard is currently active
    /// (pointer is null for waiting sets).
    fn remove_slot(&mut self, wire_id: CompactWireId) -> (Option<WireAvailability>, bool) {
        let wire_id_u64 = wire_id.to_u64();
        let slot_idx = ((wire_id_u64 >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;
        let slot_ptr: *mut Wire = unsafe { self.slots.as_mut_ptr().add(slot_idx) };

        let result = match mask_bits {
            0 => None,
            1 => {
                let credits =
                    unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).credits)) };
                self.mask &= !(0x3 << (slot_idx * 2));
                unsafe {
                    std::ptr::write_unaligned(
                        std::ptr::addr_of_mut!((*slot_ptr).waiting_ptr),
                        std::ptr::null_mut(),
                    );
                }
                Some(WireAvailability::Available(Credits(credits)))
            }
            2 => {
                let ptr = unsafe {
                    std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).waiting_ptr))
                };
                if ptr.is_null() {
                    None
                } else {
                    let boxed = unsafe { Box::from_raw(ptr) };
                    let set = *boxed; // avoid double-drop
                    self.mask &= !(0x3 << (slot_idx * 2));
                    unsafe {
                        std::ptr::write_unaligned(
                            std::ptr::addr_of_mut!((*slot_ptr).waiting_ptr),
                            std::ptr::null_mut(),
                        );
                    }
                    Some(WireAvailability::Waiting(set))
                }
            }
            3 => {
                let bytes = unsafe {
                    std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).waiting_inline))
                };
                self.mask &= !(0x3 << (slot_idx * 2));
                unsafe {
                    std::ptr::write_unaligned(
                        std::ptr::addr_of_mut!((*slot_ptr).waiting_ptr),
                        std::ptr::null_mut(),
                    );
                }
                Some(WireAvailability::WaitingInline(CompactDependency { bytes }))
            }
            _ => unreachable!(),
        };

        let all_empty = self.mask == 0;
        (result, all_empty)
    }

    /// Cleans up heap-allocated data (waiting sets) for a slot.
    ///
    /// Only acts on mask_bits == 2 (waiting_ptr). Other types need no cleanup.
    fn clear_slot_internal(&mut self, slot_idx: usize) {
        let slot_ptr: *mut Wire = unsafe { self.slots.as_mut_ptr().add(slot_idx) };
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;
        if mask_bits == 2 {
            let ptr =
                unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*slot_ptr).waiting_ptr)) };
            if !ptr.is_null() {
                unsafe {
                    drop(Box::from_raw(ptr));
                }
                unsafe {
                    std::ptr::write_unaligned(
                        std::ptr::addr_of_mut!((*slot_ptr).waiting_ptr),
                        std::ptr::null_mut(),
                    );
                }
            }
        }
    }
}

impl Drop for SlottedValue {
    fn drop(&mut self) {
        // Clean up any waiting sets
        for slot_idx in 0..4 {
            self.clear_slot_internal(slot_idx);
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Encapsulates the state map (u32 → slotted value) with safe, lifetime-based access.
/// - Keeps the current slotting: key = low 32 bits; slot index = top 2 bits of 34-bit id.
/// - Exposes only safe APIs. Internals still use the compact/packed representation.
///
/// Design notes:
/// - `get_slot_mut` returns a safe enum of guard types (`SlotRef`).
/// - `set` and `remove` handle allocation / deallocation and slot cleanup.
/// - Keys are pruned when all four slots are empty to avoid map bloat.
pub struct WireStateMap {
    inner: HashMap<u32, SlottedValue>,
}

impl Default for WireStateMap {
    fn default() -> Self {
        Self::new()
    }
}

impl WireStateMap {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Returns a mutable guard to access or modify a wire's state.
    ///
    /// # Returns
    /// - `None` if the wire has no stored state
    /// - `Some(SlotRef::Available)` if the wire is available with credits
    /// - `Some(SlotRef::WaitingInline)` if one gate is waiting
    /// - `Some(SlotRef::Waiting)` if multiple gates are waiting
    ///
    /// The returned guard holds a mutable borrow of the entire map, preventing
    /// other operations until the guard is dropped.
    #[inline]
    pub fn get_slot_mut<'a>(&'a mut self, id: CompactWireId) -> Option<SlotRef<'a>> {
        let key = (id.to_u64() & 0xFFFF_FFFF) as u32;
        let slotted = self.inner.get_mut(&key)?;
        match slotted.get_slot_mut(id) {
            None => None,
            Some(WireAvailabilityMut::Available(g)) => {
                Some(SlotRef::Available(AvailableCredits { inner: g }))
            }
            Some(WireAvailabilityMut::WaitingInline(g)) => {
                Some(SlotRef::WaitingInline(InlineDep { inner: g }))
            }
            Some(WireAvailabilityMut::Waiting(g)) => {
                Some(SlotRef::Waiting(WaitingSet { inner: g }))
            }
        }
    }

    /// Sets a wire to the given state, replacing any previous state.
    ///
    /// This clears any existing data (available credits or waiting dependencies)
    /// and stores the new value.
    #[inline]
    pub fn set(&mut self, id: CompactWireId, value: WireAvailability) {
        let key = (id.to_u64() & 0xFFFF_FFFF) as u32;
        self.inner
            .entry(key)
            .or_insert_with(SlottedValue::new)
            .set_slot(id, value);
    }

    /// Removes and returns a wire's state, freeing memory.
    ///
    /// If this was the last occupied slot in the HashMap bucket, the entire
    /// bucket is removed to keep the map compact.
    #[inline]
    pub fn remove(&mut self, id: CompactWireId) -> Option<WireAvailability> {
        let key = (id.to_u64() & 0xFFFF_FFFF) as u32;
        let slotted = self.inner.get_mut(&key)?;
        let (value, all_empty) = slotted.remove_slot(id);
        if all_empty {
            self.inner.remove(&key);
        }
        value
    }

    /// Convenience: marks a wire as available with the given credits.
    #[inline]
    pub fn set_available(&mut self, id: CompactWireId, credits: Credits) {
        self.set(id, WireAvailability::Available(credits));
    }

    /// Enqueues a gate to wait for a wire, returning whether it's still waiting.
    ///
    /// This method is idempotent: adding the same dependency multiple times has no effect.
    ///
    /// # State Transitions
    /// - `None` → `WaitingInline(dep)`: First dependency, uses inline storage
    /// - `WaitingInline(old)` → `Waiting({old, dep})`: Second dependency, upgrades to HashSet
    /// - `Waiting(set)` → `Waiting(set ∪ {dep})`: Additional dependencies added to set
    /// - `Available` → unchanged: Wire is already available, gate doesn't wait
    ///
    /// # Returns
    /// - `true` if the gate is waiting (wire not yet available)
    /// - `false` if the wire is already available (no waiting needed)
    pub fn enqueue_waiting(&mut self, waiting_on: CompactWireId, dep: CompactDependency) -> bool {
        let mut replacement: Option<WireAvailability> = None;

        let status = match self.get_slot_mut(waiting_on) {
            None => {
                cold_and_empty();
                replacement = Some(WireAvailability::WaitingInline(dep));
                true
            }
            Some(SlotRef::Waiting(mut set_guard)) => {
                set_guard.insert(dep);
                true
            }
            Some(SlotRef::WaitingInline(inline_guard)) => {
                if inline_guard.get() != dep {
                    let mut set = HashSet::with_capacity(2);
                    set.insert(inline_guard.get());
                    set.insert(dep);
                    replacement = Some(WireAvailability::Waiting(set));
                }
                true
            }
            Some(SlotRef::Available(..)) => false,
        };

        if let Some(value) = replacement {
            self.set(waiting_on, value);
        }

        status
    }

    /// Returns the number of occupied HashMap buckets (not individual wires).
    ///
    /// Each bucket can contain up to 4 wire states.
    #[inline]
    pub fn buckets(&self) -> usize {
        self.inner.len()
    }
}

impl fmt::Debug for WireStateMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireStateMap")
            .field("buckets", &self.inner.len())
            .finish()
    }
}

/// A safe handle to a wire's mutable state.
///
/// This enum provides access to different wire states through type-safe wrappers.
/// All modifications are written back automatically when the guard is dropped.
pub enum SlotRef<'a> {
    Available(AvailableCredits<'a>),
    WaitingInline(InlineDep<'a>),
    Waiting(WaitingSet<'a>),
}

/// Public: Guard for reading/modifying available wire credits.
///
/// Provides safe access to the credits without exposing raw memory.
/// All operations handle unaligned access correctly.
pub struct AvailableCredits<'a> {
    inner: AvailableGuard<'a>,
}

impl<'a> AvailableCredits<'a> {
    #[inline]
    pub fn get(&self) -> Credits {
        self.inner.get()
    }

    #[inline]
    pub fn set(&mut self, c: Credits) {
        self.inner.set(c);
    }

    #[inline]
    pub fn update(&mut self, f: impl FnOnce(&mut Credits)) {
        self.inner.update(f);
    }
}

/// Public: Guard for reading/modifying an inline dependency.
///
/// The dependency bytes are cached in the guard and written back on drop.
pub struct InlineDep<'a> {
    inner: InlineGuard<'a>,
}

impl<'a> InlineDep<'a> {
    #[inline]
    pub fn get(&self) -> CompactDependency {
        self.inner.get()
    }

    #[inline]
    pub fn set(&mut self, dep: CompactDependency) {
        self.inner.set(dep);
    }

    /// Takes the current dependency, replacing it with zeros.
    ///
    /// The caller should typically replace the slot entirely after calling this.
    #[inline]
    pub fn take(&mut self) -> CompactDependency {
        let current = self.inner.get();
        self.inner.set(CompactDependency { bytes: [0; 12] });
        current
    }
}

/// Public: Guard for reading/modifying a heap-allocated set of dependencies.
///
/// The set is temporarily owned by this guard and restored to the slot on drop.
/// Use this to add dependencies or query the waiting list.
pub struct WaitingSet<'a> {
    inner: WaitingSetGuard<'a>,
}

impl<'a> WaitingSet<'a> {
    #[inline]
    pub fn insert(&mut self, dep: CompactDependency) -> bool {
        self.inner.insert(dep)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Copies all dependencies into a vector.
    ///
    /// This is useful when you need to process dependencies without holding
    /// the guard (which prevents other map operations).
    pub fn drain_to_vec(&mut self) -> Vec<CompactDependency> {
        let mut v = Vec::with_capacity(self.inner.len());
        for d in self.inner.iter() {
            v.push(*d);
        }
        v
    }
}

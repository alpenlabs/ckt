use ckt::GateType;
use indexmap::IndexSet;

use std::cmp::Ordering;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use ahash::{HashSet, HashSetExt};

// 34 bit uint
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactWireId([u8; 5]);

impl CompactWireId {
    pub fn from_u64(value: u64) -> Self {
        // Mask to ensure we only use 34 bits (0x3_FFFF_FFFF)
        let masked_value = value & 0x3_FFFF_FFFF;

        let bytes = [
            (masked_value & 0xFF) as u8,
            ((masked_value >> 8) & 0xFF) as u8,
            ((masked_value >> 16) & 0xFF) as u8,
            ((masked_value >> 24) & 0xFF) as u8,
            ((masked_value >> 32) & 0x3) as u8, // Only 2 bits for the 5th byte
        ];

        Self(bytes)
    }

    pub fn to_u64(&self) -> u64 {
        (self.0[0] as u64)
            | ((self.0[1] as u64) << 8)
            | ((self.0[2] as u64) << 16)
            | ((self.0[3] as u64) << 24)
            | ((self.0[4] as u64) << 32)
    }
}

impl Ord for CompactWireId {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        use core::cmp::Ordering::*;
        for i in (0..5).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Equal => continue,
                non_eq => return non_eq,
            }
        }
        Equal
    }
}

impl PartialOrd for CompactWireId {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for CompactWireId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WireId({})", self.to_u64())
    }
}

#[derive(Debug, Clone, Copy, Hash)]
pub struct IntermediateGate {
    pub in1: CompactWireId,
    pub in2: CompactWireId,
    pub out: CompactWireId,
    pub credits: Credits,
}

impl PartialEq for IntermediateGate {
    fn eq(&self, other: &Self) -> bool {
        self.out == other.out
    }
}

impl Eq for IntermediateGate {}

pub struct Level {
    pub id: u32,
    pub xor_gates: IndexSet<IntermediateGate>,
    pub and_gates: IndexSet<IntermediateGate>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PendingLevel {
    pub xor_gates: IndexSet<IntermediateGate>,
    pub and_gates: IndexSet<IntermediateGate>,
}

#[derive(Debug, Clone, Copy, Hash)]
pub struct Credits(pub u16);

#[derive(Debug, Clone)]
pub enum WireAvailability {
    Available(Credits),
    Waiting(HashSet<CompactDependency>),
    WaitingInline(CompactDependency),
}

// Compact dependency: 11 bytes (34-bit other_in, 34-bit out, 1-bit gate_type, 1 bit padding, 16 bit credits)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactDependency {
    pub(crate) bytes: [u8; 11],
}

impl std::fmt::Debug for CompactDependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dep = self.to_dependency();
        f.debug_struct("CompactDependency")
            .field("other_in", &dep.other_in)
            .field("out", &dep.out)
            .field("gate_type", &dep.gate_type)
            .field("credits", &dep.credits)
            .finish()
    }
}

impl CompactDependency {
    pub fn new(
        other_in: CompactWireId,
        out: CompactWireId,
        gate_type: GateType,
        credits: Credits,
    ) -> Self {
        let other_in_u64 = other_in.to_u64();
        let out_u64 = out.to_u64();

        debug_assert!(other_in_u64 < (1u64 << 34), "other_in exceeds 34 bits");
        debug_assert!(out_u64 < (1u64 << 34), "out exceeds 34 bits");

        let mut bytes = [0u8; 11];
        // Pack: 34 bits other_in | 34 bits out | 1 bit gate_type | 16 bit credits

        // other_in: bits 0-33
        bytes[0] = (other_in_u64 & 0xFF) as u8;
        bytes[1] = ((other_in_u64 >> 8) & 0xFF) as u8;
        bytes[2] = ((other_in_u64 >> 16) & 0xFF) as u8;
        bytes[3] = ((other_in_u64 >> 24) & 0xFF) as u8;
        bytes[4] = ((other_in_u64 >> 32) & 0x3) as u8; // 2 bits

        // out: bits 34-67 (34 bits)
        bytes[4] |= ((out_u64 & 0x3F) << 2) as u8; // 6 bits of out
        bytes[5] = ((out_u64 >> 6) & 0xFF) as u8;
        bytes[6] = ((out_u64 >> 14) & 0xFF) as u8;
        bytes[7] = ((out_u64 >> 22) & 0xFF) as u8;
        bytes[8] = ((out_u64 >> 30) & 0xF) as u8; // 4 bits

        // gate_type: bit 68
        if gate_type == GateType::AND {
            bytes[8] |= 0x10; // Set bit 4
        }

        // credits: bytes 9-10 (bits 72-87)
        bytes[9] = (credits.0 & 0xFF) as u8;
        bytes[10] = ((credits.0 >> 8) & 0xFF) as u8;

        Self { bytes }
    }

    pub fn to_dependency(&self) -> Dependency {
        // Unpack other_in
        let other_in_u64 = self.bytes[0] as u64
            | ((self.bytes[1] as u64) << 8)
            | ((self.bytes[2] as u64) << 16)
            | ((self.bytes[3] as u64) << 24)
            | (((self.bytes[4] & 0x3) as u64) << 32);

        // Unpack out
        let out_u64 = ((self.bytes[4] >> 2) as u64)
            | ((self.bytes[5] as u64) << 6)
            | ((self.bytes[6] as u64) << 14)
            | ((self.bytes[7] as u64) << 22)
            | (((self.bytes[8] & 0xF) as u64) << 30);

        // Unpack gate_type
        let gate_type = if (self.bytes[8] & 0x10) != 0 {
            GateType::AND
        } else {
            GateType::XOR
        };

        // Unpack credits
        let credits = Credits((self.bytes[9] as u16) | ((self.bytes[10] as u16) << 8));

        Dependency {
            other_in: CompactWireId::from_u64(other_in_u64),
            out: CompactWireId::from_u64(out_u64),
            gate_type,
            credits,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Dependency {
    pub other_in: CompactWireId,
    pub out: CompactWireId,
    pub gate_type: GateType,
    pub credits: Credits,
}

impl Ord for Dependency {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.out.cmp(&other.out)
    }
}

impl PartialOrd for Dependency {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Dependency {
    fn eq(&self, other: &Self) -> bool {
        self.out == other.out
    }
}

impl Eq for Dependency {}

// Type alias for the dependency set
type DepSet = HashSet<CompactDependency>;

/// Guards for in-place mutation without cloning
pub enum WireAvailabilityMut<'a> {
    Available(AvailableGuard<'a>),
    WaitingInline(InlineGuard<'a>),
    Waiting(WaitingSetGuard<'a>),
}

pub struct AvailableGuard<'a> {
    slot_ptr: *mut Wire,
    _l: PhantomData<&'a mut SlottedValue>,
}

impl<'a> AvailableGuard<'a> {
    pub fn get(&self) -> Credits {
        unsafe {
            let p = std::ptr::addr_of!((*self.slot_ptr).credits);
            Credits(std::ptr::read_unaligned(p))
        }
    }
    pub fn set(&mut self, c: Credits) {
        unsafe {
            let p = std::ptr::addr_of_mut!((*self.slot_ptr).credits);
            std::ptr::write_unaligned(p, c.0);
        }
    }
    pub fn update<F: FnOnce(&mut Credits)>(&mut self, f: F) {
        let mut v = self.get();
        f(&mut v);
        self.set(v);
    }
}

pub struct InlineGuard<'a> {
    slot_ptr: *mut Wire,
    tmp: CompactDependency,
    _l: PhantomData<&'a mut SlottedValue>,
}

impl<'a> InlineGuard<'a> {
    pub fn get(&self) -> CompactDependency {
        self.tmp
    }
    pub fn get_mut(&mut self) -> &mut CompactDependency {
        &mut self.tmp
    }
    pub fn set(&mut self, dep: CompactDependency) {
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

pub struct WaitingSetGuard<'a> {
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

// Union for storing Credits, inline CompactDependency, or pointer to HashSet
#[repr(packed)]
union Wire {
    credits: u16,             // Credits (2 bytes)
    waiting_inline: [u8; 11], // Single CompactDependency (11 bytes)
    waiting_ptr: *mut DepSet, // Multiple dependencies using HashSet
}

// Slotted value for HashMap: handles collisions from u64→u32 key compression
#[repr(packed)]
pub(crate) struct SlottedValue {
    // 2 bits per slot: 00=empty, 01=available, 10=waiting_set, 11=waiting_inline
    mask: u8,
    slots: [Wire; 4],
}

impl SlottedValue {
    pub fn new() -> Self {
        Self {
            mask: 0,
            slots: std::array::from_fn(|_| Wire {
                waiting_ptr: std::ptr::null_mut(),
            }),
        }
    }

    // Mutable accessor: returns guards for in-place mutation without cloning
    pub fn get_slot_mut(&mut self, wire_id: CompactWireId) -> Option<WireAvailabilityMut<'_>> {
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

    pub fn set_slot(&mut self, wire_id: CompactWireId, value: WireAvailability) {
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

    pub fn remove_slot(&mut self, wire_id: CompactWireId) -> (Option<WireAvailability>, bool) {
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

impl Clone for SlottedValue {
    fn clone(&self) -> Self {
        let mut new = SlottedValue::new();

        for i in 0..4 {
            let mask_bits = (self.mask >> (i * 2)) & 0x3;

            let src: *const Wire = unsafe { self.slots.as_ptr().add(i) };
            let dst: *mut Wire = unsafe { new.slots.as_mut_ptr().add(i) };

            match mask_bits {
                0 => {
                    // Empty
                }
                1 => {
                    // Available: copy credits with unaligned ops
                    let credits =
                        unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*src).credits)) };
                    new.mask |= 1 << (i * 2);
                    unsafe {
                        std::ptr::write_unaligned(std::ptr::addr_of_mut!((*dst).credits), credits);
                    }
                }
                2 => {
                    // Waiting: clone the HashSet the pointer refers to
                    let ptr =
                        unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*src).waiting_ptr)) };

                    // If you use the "null sentinel" while a guard is active, cloning
                    // during an active guard would see ptr == null. You can assert or
                    // treat it as empty. Here we assert in debug builds.
                    assert!(
                        ptr.is_null(),
                        "SlottedValue::clone: waiting_ptr is null (guard active?)"
                    );
                    if !ptr.is_null() {
                        // Safe: we only create a shared reference to the heap object and clone it.
                        let set_ref: &DepSet = unsafe { &*ptr };
                        let cloned = set_ref.clone();
                        let new_ptr = Box::into_raw(Box::new(cloned));

                        new.mask |= 2 << (i * 2);
                        unsafe {
                            std::ptr::write_unaligned(
                                std::ptr::addr_of_mut!((*dst).waiting_ptr),
                                new_ptr,
                            );
                        }
                    } else {
                        // Optional: if you prefer, keep the slot empty in the clone
                        // (leave mask bits as 0 for this slot).
                    }
                }
                3 => {
                    // Waiting inline: copy the 11-byte payload unaligned
                    let bytes = unsafe {
                        std::ptr::read_unaligned(std::ptr::addr_of!((*src).waiting_inline))
                    };
                    new.mask |= 3 << (i * 2);
                    unsafe {
                        std::ptr::write_unaligned(
                            std::ptr::addr_of_mut!((*dst).waiting_inline),
                            bytes,
                        );
                    }
                }
                _ => unsafe { std::hint::unreachable_unchecked() },
            }
        }

        new
    }
}

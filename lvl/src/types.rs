use ckt::GateType;
use indexmap::IndexSet;

use crate::thinvec::{ThinVec, ThinVecInternal};

/// 34 bit uint
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    Waiting(ThinVec<CompactDependency>),
    WaitingInline(CompactDependency),
}

// Compact dependency: 11 bytes (34-bit other_in, 34-bit out, 1-bit gate_type, 1 bit padding, 16 bit credits)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompactDependency {
    bytes: [u8; 11],
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

// Union for storing Credits, inline CompactDependency, or pointer to Vec
#[repr(packed)]
union Wire {
    credits: u16,                      // Credits (2 bytes)
    waiting_inline: [u8; 11],          // Single CompactDependency (11 bytes)
    waiting_ptr: *mut ThinVecInternal, // Multiple dependencies using ThinVec
}

// Slotted value for HashMap: handles collisions from u64→u32 key compression
#[repr(packed)]
pub(crate) struct SlottedValue {
    mask: u8, // 2 bits per slot: 00=empty, 01=available, 10=waiting_vec, 11=waiting_inline
    slots: [Wire; 4], // 4 slots using union (11 bytes each)
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

    pub fn get_slot(&self, wire_id: CompactWireId) -> Option<WireAvailability> {
        let wire_id_u64 = wire_id.to_u64();
        let slot_idx = ((wire_id_u64 >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;

        match mask_bits {
            0 => None, // Empty
            1 => {
                // Available
                let credits = unsafe { self.slots[slot_idx].credits };
                Some(WireAvailability::Available(Credits(credits)))
            }
            2 => {
                // Waiting - clone from ThinVec
                let ptr = unsafe { self.slots[slot_idx].waiting_ptr };
                if ptr.is_null() {
                    None
                } else {
                    // Create a ThinVec from the pointer, clone it, then forget the original
                    let thinvec = unsafe { ThinVec::<CompactDependency>::from_raw(ptr) };
                    let cloned = thinvec.clone();
                    // Return the pointer without dropping (preventing deallocation)
                    let _ = unsafe { thinvec.into_raw() };
                    Some(WireAvailability::Waiting(cloned))
                }
            }
            3 => {
                // Waiting inline - single dependency
                let bytes = unsafe { self.slots[slot_idx].waiting_inline };
                let compact_dep = CompactDependency { bytes };
                Some(WireAvailability::WaitingInline(compact_dep))
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
            WireAvailability::Waiting(deps) => {
                // Multiple dependencies - use ThinVec
                self.mask |= 2 << (slot_idx * 2);
                let ptr = unsafe { deps.into_raw() };
                self.slots[slot_idx] = Wire { waiting_ptr: ptr };
            }
        };
    }

    #[allow(dead_code)]
    pub fn remove_slot(&mut self, wire_id: CompactWireId) -> (Option<WireAvailability>, bool) {
        let wire_id_u64 = wire_id.to_u64();
        let slot_idx = ((wire_id_u64 >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;

        let result = match mask_bits {
            0 => None,
            1 => {
                // Available
                let credits = Credits(unsafe { self.slots[slot_idx].credits });
                // Clear mask bits and slot
                self.mask &= !(0x3 << (slot_idx * 2));
                self.slots[slot_idx] = Wire {
                    waiting_ptr: std::ptr::null_mut(),
                };
                Some(WireAvailability::Available(credits))
            }
            2 => {
                // Waiting - take ownership of ThinVec
                let ptr = unsafe { self.slots[slot_idx].waiting_ptr };
                if ptr.is_null() {
                    None
                } else {
                    let thinvec = unsafe { ThinVec::<CompactDependency>::from_raw(ptr) };
                    // Clear mask bits and slot
                    self.mask &= !(0x3 << (slot_idx * 2));
                    self.slots[slot_idx] = Wire {
                        waiting_ptr: std::ptr::null_mut(),
                    };
                    Some(WireAvailability::Waiting(thinvec))
                }
            }
            3 => {
                // Waiting inline - single dependency
                let bytes = unsafe { self.slots[slot_idx].waiting_inline };
                let compact_dep = CompactDependency { bytes };
                // Clear mask bits and slot
                self.mask &= !(0x3 << (slot_idx * 2));
                self.slots[slot_idx] = Wire {
                    waiting_ptr: std::ptr::null_mut(),
                };
                Some(WireAvailability::WaitingInline(compact_dep))
            }
            _ => unreachable!(),
        };

        let all_empty = self.mask == 0;
        (result, all_empty)
    }

    fn clear_slot_internal(&mut self, slot_idx: usize) {
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;
        if mask_bits == 2 {
            // Free the waiting list (ThinVec)
            let ptr = unsafe { self.slots[slot_idx].waiting_ptr };
            if !ptr.is_null() {
                unsafe { drop(ThinVec::<CompactDependency>::from_raw(ptr)) };
            }
        }
        // mask_bits == 3 (inline) doesn't need cleanup
    }
}

impl Drop for SlottedValue {
    fn drop(&mut self) {
        // Clean up any waiting lists
        for slot_idx in 0..4 {
            self.clear_slot_internal(slot_idx);
        }
    }
}

impl Clone for SlottedValue {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        for i in 0..4 {
            let mask_bits = (self.mask >> (i * 2)) & 0x3;
            match mask_bits {
                0 => {}
                1 => {
                    // Copy CompactWireLocation
                    new.mask |= 1 << (i * 2);
                    new.slots[i] = Wire {
                        credits: unsafe { self.slots[i].credits },
                    };
                }
                2 => {
                    // Clone waiting list using ThinVec
                    new.mask |= 2 << (i * 2);
                    let ptr = unsafe { self.slots[i].waiting_ptr };
                    if !ptr.is_null() {
                        let thinvec = unsafe { ThinVec::<CompactDependency>::from_raw(ptr) };
                        let cloned_thinvec = thinvec.clone();
                        // Convert back to raw pointer without dropping the original
                        let _ = unsafe { thinvec.into_raw() };
                        let new_ptr = unsafe { cloned_thinvec.into_raw() };
                        new.slots[i] = Wire {
                            waiting_ptr: new_ptr,
                        };
                    }
                }
                3 => {
                    // Copy inline dependency
                    new.mask |= 3 << (i * 2);
                    new.slots[i] = Wire {
                        waiting_inline: unsafe { self.slots[i].waiting_inline },
                    };
                }
                _ => unreachable!(),
            }
        }
        new
    }
}

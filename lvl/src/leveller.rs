use std::{collections::BTreeSet, mem};

use crate::thinvec::{ThinVec, ThinVecInternal};
use ahash::{HashMap, HashMapExt};
use ckt::{
    v3::{
        a::Gate as GateA,
        b::{CompactWireLocation, Gate as GateB, Level, WireLocation},
    },
    GateType,
};
use cynosure::hints::{cold_and_empty, likely, unlikely};

type WireId = u64;

// Compact dependency: 9 bytes (34-bit other_in, 34-bit out, 1-bit gate_type)
#[derive(Clone, Copy)]
struct CompactDependency {
    bytes: [u8; 9],
}

impl CompactDependency {
    fn new(other_in: u64, out: u64, gate_type: GateType) -> Self {
        debug_assert!(other_in < (1u64 << 34), "other_in exceeds 34 bits");
        debug_assert!(out < (1u64 << 34), "out exceeds 34 bits");

        let mut bytes = [0u8; 9];
        // Pack: 34 bits other_in | 34 bits out | 1 bit gate_type

        // other_in: bits 0-33
        bytes[0] = (other_in & 0xFF) as u8;
        bytes[1] = ((other_in >> 8) & 0xFF) as u8;
        bytes[2] = ((other_in >> 16) & 0xFF) as u8;
        bytes[3] = ((other_in >> 24) & 0xFF) as u8;
        bytes[4] = ((other_in >> 32) & 0x3) as u8; // 2 bits

        // out: bits 34-67 (34 bits)
        bytes[4] |= ((out & 0x3F) << 2) as u8; // 6 bits of out
        bytes[5] = ((out >> 6) & 0xFF) as u8;
        bytes[6] = ((out >> 14) & 0xFF) as u8;
        bytes[7] = ((out >> 22) & 0xFF) as u8;
        bytes[8] = ((out >> 30) & 0xF) as u8; // 4 bits

        // gate_type: bit 68
        if gate_type == GateType::AND {
            bytes[8] |= 0x10; // Set bit 4
        }

        Self { bytes }
    }

    fn to_dependency(&self) -> Dependency {
        // Unpack other_in
        let other_in = self.bytes[0] as u64
            | ((self.bytes[1] as u64) << 8)
            | ((self.bytes[2] as u64) << 16)
            | ((self.bytes[3] as u64) << 24)
            | (((self.bytes[4] & 0x3) as u64) << 32);

        // Unpack out
        let out = ((self.bytes[4] >> 2) as u64)
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

        Dependency {
            other_in,
            out,
            gate_type,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Dependency {
    other_in: u64,
    out: u64,
    gate_type: GateType,
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

// Union for storing CompactWireLocation, inline CompactDependency, or pointer to Vec
#[repr(packed)]
union SlotData {
    location: [u8; 9],                 // CompactWireLocation (7 bytes) padded to 9
    waiting_inline: [u8; 9],           // Single CompactDependency (9 bytes)
    waiting_ptr: *mut ThinVecInternal, // Multiple dependencies using ThinVec
}

// Slotted value for HashMap: handles collisions from u64→u32 key compression
#[repr(packed)]
struct SlottedValue {
    mask: u8, // 2 bits per slot: 00=empty, 01=available, 10=waiting_vec, 11=waiting_inline
    slots: [SlotData; 4], // 4 slots using union (9 bytes each)
}

impl SlottedValue {
    fn new() -> Self {
        Self {
            mask: 0,
            slots: std::array::from_fn(|_| SlotData {
                waiting_ptr: std::ptr::null_mut(),
            }),
        }
    }

    fn get_slot(&self, wire_id: u64) -> Option<WireAvailability> {
        let slot_idx = ((wire_id >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;

        match mask_bits {
            0 => None, // Empty
            1 => {
                // Available - decompress CompactWireLocation
                let mut bytes = [0u8; 7];
                bytes.copy_from_slice(unsafe { &self.slots[slot_idx].location[..7] });
                let compact_loc = CompactWireLocation { bytes };
                Some(WireAvailability::Available(compact_loc.to_wire_location()))
            }
            2 => {
                // Waiting - clone from ThinVec
                let ptr = unsafe { self.slots[slot_idx].waiting_ptr };
                if ptr.is_null() {
                    None
                } else {
                    let thinvec = unsafe { ThinVec::<CompactDependency>::from_raw(ptr) };
                    let mut deps = Vec::new();
                    for i in 0..thinvec.len() {
                        if let Some(compact_dep) = thinvec.get(i) {
                            deps.push(compact_dep.to_dependency());
                        }
                    }
                    // Convert back to raw pointer without dropping
                    let _ = unsafe { thinvec.into_raw() };
                    Some(WireAvailability::Waiting(deps))
                }
            }
            3 => {
                // Waiting inline - single dependency
                let bytes = unsafe { self.slots[slot_idx].waiting_inline };
                let compact_dep = CompactDependency { bytes };
                Some(WireAvailability::WaitingInline(compact_dep.to_dependency()))
            }
            _ => unreachable!(),
        }
    }

    fn set_slot(&mut self, wire_id: u64, value: WireAvailability) {
        let slot_idx = ((wire_id >> 32) & 0x3) as usize;

        // Clear existing slot if occupied
        self.clear_slot_internal(slot_idx);

        // Clear mask bits for this slot
        self.mask &= !(0x3 << (slot_idx * 2));

        match value {
            WireAvailability::Available(loc) => {
                // Set mask bits to 01
                self.mask |= 1 << (slot_idx * 2);
                // Store CompactWireLocation in union
                let compact_loc = CompactWireLocation::new(loc.level, loc.index);
                let mut location = [0u8; 9];
                location[..7].copy_from_slice(&compact_loc.bytes);
                self.slots[slot_idx] = SlotData { location };
            }
            WireAvailability::WaitingInline(dep) => {
                // Single dependency - use inline storage
                self.mask |= 3 << (slot_idx * 2);
                let compact_dep = CompactDependency::new(dep.other_in, dep.out, dep.gate_type);
                self.slots[slot_idx] = SlotData {
                    waiting_inline: compact_dep.bytes,
                };
            }
            WireAvailability::Waiting(deps) => {
                // Multiple dependencies - use ThinVec
                self.mask |= 2 << (slot_idx * 2);
                let mut thinvec = ThinVec::<CompactDependency>::with_capacity(deps.len());
                for dep in deps {
                    thinvec.push(CompactDependency::new(dep.other_in, dep.out, dep.gate_type));
                }
                let ptr = unsafe { thinvec.into_raw() };
                self.slots[slot_idx] = SlotData { waiting_ptr: ptr };
            }
        };
    }

    #[allow(dead_code)]
    fn remove_slot(&mut self, wire_id: u64) -> Option<WireAvailability> {
        let slot_idx = ((wire_id >> 32) & 0x3) as usize;
        let mask_bits = (self.mask >> (slot_idx * 2)) & 0x3;

        match mask_bits {
            0 => None,
            1 => {
                // Available - decompress CompactWireLocation
                let mut bytes = [0u8; 7];
                bytes.copy_from_slice(unsafe { &self.slots[slot_idx].location[..7] });
                let compact_loc = CompactWireLocation { bytes };
                // Clear mask bits and slot
                self.mask &= !(0x3 << (slot_idx * 2));
                self.slots[slot_idx] = SlotData {
                    waiting_ptr: std::ptr::null_mut(),
                };
                Some(WireAvailability::Available(compact_loc.to_wire_location()))
            }
            2 => {
                // Waiting - take ownership of ThinVec
                let ptr = unsafe { self.slots[slot_idx].waiting_ptr };
                if ptr.is_null() {
                    None
                } else {
                    let thinvec = unsafe { ThinVec::<CompactDependency>::from_raw(ptr) };
                    let mut deps = Vec::new();
                    for i in 0..thinvec.len() {
                        if let Some(compact_dep) = thinvec.get(i) {
                            deps.push(compact_dep.to_dependency());
                        }
                    }
                    // Clear mask bits and slot
                    self.mask &= !(0x3 << (slot_idx * 2));
                    self.slots[slot_idx] = SlotData {
                        waiting_ptr: std::ptr::null_mut(),
                    };
                    // ThinVec will be dropped here, freeing its memory
                    Some(WireAvailability::Waiting(deps))
                }
            }
            3 => {
                // Waiting inline - single dependency
                let bytes = unsafe { self.slots[slot_idx].waiting_inline };
                let compact_dep = CompactDependency { bytes };
                // Clear mask bits and slot
                self.mask &= !(0x3 << (slot_idx * 2));
                self.slots[slot_idx] = SlotData {
                    waiting_ptr: std::ptr::null_mut(),
                };
                Some(WireAvailability::WaitingInline(compact_dep.to_dependency()))
            }
            _ => unreachable!(),
        }
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
                    new.slots[i] = SlotData {
                        location: unsafe { self.slots[i].location },
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
                        new.slots[i] = SlotData {
                            waiting_ptr: new_ptr,
                        };
                    }
                }
                3 => {
                    // Copy inline dependency
                    new.mask |= 3 << (i * 2);
                    new.slots[i] = SlotData {
                        waiting_inline: unsafe { self.slots[i].waiting_inline },
                    };
                }
                _ => unreachable!(),
            }
        }
        new
    }
}

// No longer needed - we work directly with WireAvailability in SlottedValue

#[derive(Debug, Clone)]
enum WireAvailability {
    Available(WireLocation),
    Waiting(Vec<Dependency>),
    WaitingInline(Dependency),
}

#[derive(Debug, Clone, Default)]
struct PendingLevel {
    and_gates: Vec<GateB>,
    xor_gates: Vec<GateB>,
    outputs: GateOutputs,
}

#[derive(Debug, Clone, Default)]
struct GateOutputs {
    and_gates: BTreeSet<WireId>,
    xor_gates: BTreeSet<WireId>,
}

#[derive(Clone)]
pub struct Leveller {
    primary_inputs: u64,
    level_id: u32,
    pending_level: PendingLevel,
    state: HashMap<u32, SlottedValue>, // Changed to use u32 key with SlottedValue
}

impl Leveller {
    // Helper to get wire availability
    fn get_wire(&self, wire_id: u64) -> Option<WireAvailability> {
        let key = (wire_id & 0xFFFFFFFF) as u32;
        self.state
            .get(&key)
            .and_then(|slotted| slotted.get_slot(wire_id))
    }

    // Helper to set wire availability
    fn set_wire(&mut self, wire_id: u64, value: WireAvailability) {
        let key = (wire_id & 0xFFFFFFFF) as u32;
        self.state
            .entry(key)
            .or_insert_with(SlottedValue::new)
            .set_slot(wire_id, value);
    }
}

#[derive(Debug, Clone, Copy)]
enum Status {
    Waiting,
    Available(WireLocation),
}

#[inline]
fn append_if_not_exists<T: Eq>(set: &mut Vec<T>, item: T) {
    if !set.contains(&item) {
        set.push(item);
    }
}

impl Leveller {
    fn check_in1(&mut self, gate: GateA, gate_type: GateType) -> Status {
        if unlikely(gate.in1 < self.primary_inputs) {
            return Status::Available(WireLocation {
                level: 0,
                index: gate.in1 as u32,
            });
        }
        match self.get_wire(gate.in1) {
            None => {
                cold_and_empty();

                self.set_wire(
                    gate.in1,
                    WireAvailability::WaitingInline(Dependency {
                        other_in: gate.in2,
                        out: gate.out,
                        gate_type,
                    }),
                );

                Status::Waiting
            }
            Some(WireAvailability::Waiting(mut in1_waiting_list)) => {
                append_if_not_exists(
                    &mut in1_waiting_list,
                    Dependency {
                        other_in: gate.in2,
                        out: gate.out,
                        gate_type,
                    },
                );
                self.set_wire(gate.in1, WireAvailability::Waiting(in1_waiting_list));
                Status::Waiting
            }
            Some(WireAvailability::WaitingInline(existing_dep)) => {
                let new_dep = Dependency {
                    other_in: gate.in2,
                    out: gate.out,
                    gate_type,
                };
                if existing_dep != new_dep {
                    self.set_wire(
                        gate.in1,
                        WireAvailability::Waiting(vec![existing_dep, new_dep]),
                    );
                }
                Status::Waiting
            }
            Some(WireAvailability::Available(in1_loc)) => Status::Available(in1_loc),
        }
    }

    fn check_in2(&mut self, gate: GateA, gate_type: GateType, in1_status: Status) -> Status {
        if unlikely(gate.in2 < self.primary_inputs) {
            return Status::Available(WireLocation {
                level: 0,
                index: gate.in2 as u32,
            });
        }
        match in1_status {
            Status::Waiting => match self.get_wire(gate.in2) {
                Some(WireAvailability::Waiting(mut in2_waiting_list)) => {
                    append_if_not_exists(
                        &mut in2_waiting_list,
                        Dependency {
                            other_in: gate.in1,
                            out: gate.out,
                            gate_type,
                        },
                    );
                    self.set_wire(gate.in2, WireAvailability::Waiting(in2_waiting_list));
                    Status::Waiting
                }
                None => {
                    cold_and_empty();

                    self.set_wire(
                        gate.in2,
                        WireAvailability::WaitingInline(Dependency {
                            other_in: gate.in1,
                            out: gate.out,
                            gate_type,
                        }),
                    );
                    Status::Waiting
                }
                Some(WireAvailability::WaitingInline(existing_dep)) => {
                    let new_dep = Dependency {
                        other_in: gate.in1,
                        out: gate.out,
                        gate_type,
                    };
                    if existing_dep != new_dep {
                        self.set_wire(
                            gate.in2,
                            WireAvailability::Waiting(vec![existing_dep, new_dep]),
                        );
                    }
                    Status::Waiting
                }

                Some(WireAvailability::Available(in2_loc)) => Status::Available(in2_loc),
            },
            Status::Available(_) => match self.get_wire(gate.in2) {
                None => {
                    cold_and_empty();

                    self.set_wire(
                        gate.in2,
                        WireAvailability::WaitingInline(Dependency {
                            other_in: gate.in1,
                            out: gate.out,
                            gate_type,
                        }),
                    );

                    Status::Waiting
                }
                Some(WireAvailability::Waiting(mut in2_waiting_list)) => {
                    append_if_not_exists(
                        &mut in2_waiting_list,
                        Dependency {
                            other_in: gate.in1,
                            out: gate.out,
                            gate_type,
                        },
                    );
                    self.set_wire(gate.in2, WireAvailability::Waiting(in2_waiting_list));
                    Status::Waiting
                }
                Some(WireAvailability::WaitingInline(existing_dep)) => {
                    let new_dep = Dependency {
                        other_in: gate.in1,
                        out: gate.out,
                        gate_type,
                    };
                    if existing_dep != new_dep {
                        self.set_wire(
                            gate.in2,
                            WireAvailability::Waiting(vec![existing_dep, new_dep]),
                        );
                    }
                    Status::Waiting
                }
                Some(WireAvailability::Available(in2_loc)) => Status::Available(in2_loc),
            },
        }
    }

    fn process_gate(
        &mut self,
        gate: GateA,
        gate_type: GateType,
        newly_available: Option<(WireId, WireLocation)>, // save a hashmap lookup when we know one has just been made available
    ) {
        let in1_status = match newly_available {
            Some((wire_id, wire_location)) if gate.in1 == wire_id => {
                Status::Available(wire_location)
            }
            _ => self.check_in1(gate, gate_type),
        };

        let in2_status = match newly_available {
            Some((wire_id, wire_location)) if gate.in2 == wire_id => {
                Status::Available(wire_location)
            }
            _ => self.check_in2(gate, gate_type, in1_status),
        };

        if likely(matches!(
            (in1_status, in2_status),
            (Status::Available(_), Status::Available(_))
        )) {
            if self.pending_level.outputs.and_gates.contains(&gate.out)
                || self.pending_level.outputs.xor_gates.contains(&gate.out)
            {
                return;
            }
            let Status::Available(in1_loc) = in1_status else {
                unreachable!()
            };
            let Status::Available(in2_loc) = in2_status else {
                unreachable!()
            };
            // queue the gate in this level
            match gate_type {
                GateType::AND => {
                    self.pending_level.and_gates.push(GateB {
                        in1: in1_loc,
                        in2: in2_loc,
                    });
                    self.pending_level.outputs.and_gates.insert(gate.out);
                }
                GateType::XOR => {
                    self.pending_level.xor_gates.push(GateB {
                        in1: in1_loc,
                        in2: in2_loc,
                    });
                    self.pending_level.outputs.xor_gates.insert(gate.out);
                }
            };
        }
    }

    pub fn take_level(&mut self) -> Option<Level> {
        if unlikely(
            self.pending_level.and_gates.is_empty() && self.pending_level.xor_gates.is_empty(),
        ) {
            return None;
        }
        let level = Level {
            id: self.level_id,
            and_gates: mem::take(&mut self.pending_level.and_gates),
            xor_gates: mem::take(&mut self.pending_level.xor_gates),
        };
        self.level_id += 1;

        let newly_available_wires = mem::take(&mut self.pending_level.outputs);

        let mut base_idx = 0;
        let mut waiting_lists = Vec::new();
        // mark newly available wires
        for ids in [
            newly_available_wires.xor_gates,
            newly_available_wires.and_gates,
        ] {
            let num = ids.len();
            for (idx, real_out) in ids.into_iter().enumerate() {
                let loc = WireLocation {
                    level: level.id,
                    index: base_idx + idx as u32,
                };
                match self.get_wire(real_out) {
                    None => {
                        self.set_wire(real_out, WireAvailability::Available(loc));
                    }
                    Some(WireAvailability::Available(_)) => {
                        cold_and_empty();
                        panic!("gate already processed");
                    }
                    Some(WireAvailability::Waiting(waiting_list)) => {
                        self.set_wire(real_out, WireAvailability::Available(loc));
                        waiting_lists.push((real_out, loc, waiting_list));
                    }
                    Some(WireAvailability::WaitingInline(dep)) => {
                        self.set_wire(real_out, WireAvailability::Available(loc));
                        waiting_lists.push((real_out, loc, vec![dep]));
                    }
                }
            }
            base_idx += num as u32;
        }
        // prep next level
        for (real_out, loc, waiting_list) in waiting_lists {
            for dep in waiting_list {
                self.process_gate(
                    GateA {
                        in1: real_out,
                        in2: dep.other_in,
                        out: dep.out,
                    },
                    dep.gate_type,
                    Some((real_out, loc)),
                );
            }
        }

        Some(level)
    }

    pub fn new(primary_inputs: u64) -> Self {
        Self {
            primary_inputs,
            level_id: 1,
            pending_level: PendingLevel::default(),
            state: HashMap::new(),
        }
    }

    pub fn add_gate(&mut self, gate: GateA, gate_type: GateType) {
        self.process_gate(gate, gate_type, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_gate_with_primary_inputs() {
        // Test a simple AND gate with two primary inputs
        let mut leveller = Leveller::new(10);

        // Add gate with both inputs as primary (0 and 1)
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::AND,
        );

        // Should create first level immediately
        let level = leveller.take_level().expect("Should produce a level");
        assert_eq!(level.id, 1);
        assert_eq!(level.and_gates.len(), 1);
        assert_eq!(level.xor_gates.len(), 0);

        // Check the gate has correct inputs
        let gate = &level.and_gates[0];
        let in1 = gate.in1;
        let in2 = gate.in2;
        assert_eq!(in1.level, 0); // Primary input level
        assert_eq!(in1.index, 0);
        assert_eq!(in2.level, 0); // Primary input level
        assert_eq!(in2.index, 1);

        // No more levels should be produced
        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_dependency_chain() {
        // Test gates that depend on each other
        let mut leveller = Leveller::new(10);

        // Gate A: inputs 0,1 -> output 100
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::AND,
        );

        // Gate B: inputs 100,2 -> output 101 (depends on gate A)
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 2,
                out: 101,
            },
            GateType::XOR,
        );

        // Gate C: inputs 101,3 -> output 102 (depends on gate B)
        leveller.add_gate(
            GateA {
                in1: 101,
                in2: 3,
                out: 102,
            },
            GateType::AND,
        );

        // Level 1: Only gate A should be ready
        let level1 = leveller.take_level().expect("Should produce level 1");
        assert_eq!(level1.id, 1);
        assert_eq!(level1.and_gates.len(), 1);
        assert_eq!(level1.xor_gates.len(), 0);

        // Level 2: Gate B should be ready
        let level2 = leveller.take_level().expect("Should produce level 2");
        assert_eq!(level2.id, 2);
        assert_eq!(level2.and_gates.len(), 0);
        assert_eq!(level2.xor_gates.len(), 1);

        // Level 3: Gate C should be ready
        let level3 = leveller.take_level().expect("Should produce level 3");
        assert_eq!(level3.id, 3);
        assert_eq!(level3.and_gates.len(), 1);
        assert_eq!(level3.xor_gates.len(), 0);

        // No more levels
        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_fanout() {
        // Test one wire feeding multiple gates
        let mut leveller = Leveller::new(10);

        // Gate A: inputs 0,1 -> output 100
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::AND,
        );

        // Gate B: inputs 100,2 -> output 101 (depends on A)
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 2,
                out: 101,
            },
            GateType::XOR,
        );

        // Gate C: inputs 100,3 -> output 102 (also depends on A)
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 3,
                out: 102,
            },
            GateType::XOR,
        );

        // Gate D: inputs 100,4 -> output 103 (also depends on A)
        leveller.add_gate(
            GateA {
                in1: 4,
                in2: 100, // Note: wire 100 as second input
                out: 103,
            },
            GateType::AND,
        );

        // Level 1: Gate A
        let level1 = leveller.take_level().expect("Should produce level 1");
        assert_eq!(level1.and_gates.len(), 1);

        // Level 2: Gates B, C, and D should all be ready
        let level2 = leveller.take_level().expect("Should produce level 2");
        assert_eq!(level2.and_gates.len(), 1); // Gate D
        assert_eq!(level2.xor_gates.len(), 2); // Gates B and C

        // No more levels
        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_convergent_paths() {
        // Test gates with inputs from different levels
        let mut leveller = Leveller::new(10);

        // Level 1 gates
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::AND,
        );

        leveller.add_gate(
            GateA {
                in1: 2,
                in2: 3,
                out: 101,
            },
            GateType::XOR,
        );

        // Level 2 gate - depends on both level 1 gates
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 101,
                out: 102,
            },
            GateType::AND,
        );

        // Level 1: Two parallel gates
        let level1 = leveller.take_level().expect("Should produce level 1");
        assert_eq!(level1.and_gates.len(), 1);
        assert_eq!(level1.xor_gates.len(), 1);

        // Level 2: Convergent gate
        let level2 = leveller.take_level().expect("Should produce level 2");
        assert_eq!(level2.and_gates.len(), 1);

        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_complex_circuit() {
        // Test a more complex circuit with multiple dependencies
        let mut leveller = Leveller::new(10);

        // Add gates in random order to test dependency resolution

        // This gate depends on outputs from other gates
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 101,
                out: 200,
            },
            GateType::AND,
        );

        // Primary input gates (can execute immediately)
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::XOR,
        );

        // Another dependent gate
        leveller.add_gate(
            GateA {
                in1: 200,
                in2: 102,
                out: 201,
            },
            GateType::XOR,
        );

        leveller.add_gate(
            GateA {
                in1: 2,
                in2: 3,
                out: 101,
            },
            GateType::AND,
        );

        leveller.add_gate(
            GateA {
                in1: 4,
                in2: 5,
                out: 102,
            },
            GateType::XOR,
        );

        // Level 1: Three gates with primary inputs
        let level1 = leveller.take_level().expect("Should produce level 1");
        assert_eq!(level1.and_gates.len(), 1);
        assert_eq!(level1.xor_gates.len(), 2);

        // Level 2: Gate depending on level 1 outputs
        let level2 = leveller.take_level().expect("Should produce level 2");
        assert_eq!(level2.and_gates.len(), 1);
        assert_eq!(level2.xor_gates.len(), 0);

        // Level 3: Final gate
        let level3 = leveller.take_level().expect("Should produce level 3");
        assert_eq!(level3.and_gates.len(), 0);
        assert_eq!(level3.xor_gates.len(), 1);

        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_stats_tracking() {
        let mut leveller = Leveller::new(10);

        // Add a gate that can't execute yet
        leveller.add_gate(
            GateA {
                in1: 100,
                in2: 101,
                out: 200,
            },
            GateType::AND,
        );

        // Add gates that provide inputs
        leveller.add_gate(
            GateA {
                in1: 0,
                in2: 1,
                out: 100,
            },
            GateType::XOR,
        );

        leveller.add_gate(
            GateA {
                in1: 2,
                in2: 3,
                out: 101,
            },
            GateType::AND,
        );

        // Process first level
        let level1 = leveller.take_level().expect("Level 1");
        assert_eq!(level1.and_gates.len(), 1);
        assert_eq!(level1.xor_gates.len(), 1);

        // Process second level - pending should decrease
        let level2 = leveller.take_level().expect("Level 2");
        assert_eq!(level2.and_gates.len(), 1);
    }
}

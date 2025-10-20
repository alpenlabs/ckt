use std::hash::Hash;
use std::mem;

pub mod slab;
// thinvec is no longer needed by this module
pub mod thinvec;
pub mod types;

use crate::types::{
    CompactDependency, CompactWireId, Credits, IntermediateGate, Level, PendingLevel, SlottedValue,
    WireAvailability, WireAvailabilityMut,
};

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use ckt::GateType;
use cynosure::hints::{cold_and_empty, likely, unlikely};

#[derive(Clone)]
pub struct Leveller {
    permanent_wires: CompactWireId,
    level_id: u32,
    pending_level: PendingLevel,
    state: HashMap<u32, SlottedValue>, // u32 key with SlottedValue
}

impl Leveller {
    fn get_wire_mut(&mut self, wire_id: CompactWireId) -> Option<WireAvailabilityMut<'_>> {
        let wire_id_u64 = wire_id.to_u64();
        let key = (wire_id_u64 & 0xFFFFFFFF) as u32;
        self.state
            .get_mut(&key)
            .and_then(|slotted| slotted.get_slot_mut(wire_id))
    }

    // Helper to set wire availability
    fn set_wire(&mut self, wire_id: CompactWireId, value: WireAvailability) {
        let wire_id_u64 = wire_id.to_u64();
        let key = (wire_id_u64 & 0xFFFFFFFF) as u32;
        self.state
            .entry(key)
            .or_insert_with(SlottedValue::new)
            .set_slot(wire_id, value);
    }

    // Helper to remove wire availability
    fn remove_wire(&mut self, wire_id: CompactWireId) -> Option<WireAvailability> {
        let wire_id_u64 = wire_id.to_u64();
        let key = (wire_id_u64 & 0xFFFFFFFF) as u32;
        if let Some(slotted) = self.state.get_mut(&key) {
            let (result, all_empty) = slotted.remove_slot(wire_id);
            if all_empty {
                self.state.remove(&key);
            }
            result
        } else {
            None
        }
    }

    fn wire_used(&mut self, wire_id: CompactWireId) {
        let Some(WireAvailabilityMut::Available(mut guard)) = self.get_wire_mut(wire_id) else {
            panic!("Wire is not available");
        };
        // cleanup memory if no future gates reference this wire
        let credits = guard.get();
        if credits.0 > 1 {
            guard.set(Credits(credits.0 - 1));
        } else {
            self.remove_wire(wire_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Waiting,
    Available { is_primary: bool },
}

#[inline]
fn append_if_not_exists<T: Eq + Hash>(set: &mut HashSet<T>, item: T) {
    // HashSet insert is idempotent; fast path vs O(n) contains + push
    let _ = set.insert(item);
}

impl Leveller {
    fn check_in1(&mut self, gate: IntermediateGate, gate_type: GateType) -> Status {
        if unlikely(gate.in1 < self.permanent_wires) {
            return Status::Available { is_primary: true };
        }
        let mut replacement = None;
        let status = match self.get_wire_mut(gate.in1) {
            None => {
                cold_and_empty();

                replacement = Some(WireAvailability::WaitingInline(CompactDependency::new(
                    gate.in2,
                    gate.out,
                    gate_type,
                    gate.credits,
                )));

                Status::Waiting
            }
            Some(WireAvailabilityMut::Waiting(mut in1_waiting_set)) => {
                append_if_not_exists(
                    &mut in1_waiting_set,
                    CompactDependency::new(gate.in2, gate.out, gate_type, gate.credits),
                );
                Status::Waiting
            }
            Some(WireAvailabilityMut::WaitingInline(existing_dep)) => {
                let new_dep = CompactDependency::new(gate.in2, gate.out, gate_type, gate.credits);
                if existing_dep.get() != new_dep {
                    let mut set = HashSet::with_capacity(2);
                    set.insert(existing_dep.get());
                    set.insert(new_dep);
                    replacement = Some(WireAvailability::Waiting(set));
                }
                Status::Waiting
            }
            Some(WireAvailabilityMut::Available(..)) => Status::Available { is_primary: false },
        };

        if let Some(replacement) = replacement {
            self.set_wire(gate.in1, replacement);
        }
        status
    }

    fn check_in2(
        &mut self,
        gate: IntermediateGate,
        gate_type: GateType,
        in1_status: Status,
    ) -> Status {
        if unlikely(gate.in2 < self.permanent_wires) {
            return Status::Available { is_primary: true };
        }
        let mut replacement = None;
        let status =
            match in1_status {
                Status::Waiting => match self.get_wire_mut(gate.in2) {
                    Some(WireAvailabilityMut::Waiting(mut in2_waiting_set)) => {
                        append_if_not_exists(
                            &mut in2_waiting_set,
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits),
                        );
                        Status::Waiting
                    }
                    None => {
                        cold_and_empty();

                        replacement = Some(WireAvailability::WaitingInline(
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits),
                        ));
                        Status::Waiting
                    }
                    Some(WireAvailabilityMut::WaitingInline(existing_dep)) => {
                        let new_dep =
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits);
                        if existing_dep.get() != new_dep {
                            let mut set = HashSet::with_capacity(2);
                            set.insert(existing_dep.get());
                            set.insert(new_dep);
                            replacement = Some(WireAvailability::Waiting(set));
                        }
                        Status::Waiting
                    }

                    Some(WireAvailabilityMut::Available(..)) => {
                        Status::Available { is_primary: false }
                    }
                },
                Status::Available { .. } => match self.get_wire_mut(gate.in2) {
                    None => {
                        cold_and_empty();

                        replacement = Some(WireAvailability::WaitingInline(
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits),
                        ));

                        Status::Waiting
                    }
                    Some(WireAvailabilityMut::Waiting(mut in2_waiting_set)) => {
                        append_if_not_exists(
                            &mut in2_waiting_set,
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits),
                        );
                        Status::Waiting
                    }
                    Some(WireAvailabilityMut::WaitingInline(existing_dep)) => {
                        let new_dep =
                            CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits);
                        if existing_dep.get() != new_dep {
                            let mut set = HashSet::with_capacity(2);
                            set.insert(existing_dep.get());
                            set.insert(new_dep);
                            replacement = Some(WireAvailability::Waiting(set));
                        }
                        Status::Waiting
                    }
                    Some(WireAvailabilityMut::Available(..)) => {
                        Status::Available { is_primary: false }
                    }
                },
            };

        if let Some(replacement) = replacement {
            self.set_wire(gate.in2, replacement);
        }
        status
    }

    fn process_gate(
        &mut self,
        gate: IntermediateGate,
        gate_type: GateType,
        newly_available: Option<CompactWireId>, // save a hashmap lookup when we know one has just been made available
    ) {
        let in1_status = match newly_available {
            Some(wire_id) if gate.in1 == wire_id => Status::Available { is_primary: false },
            _ => self.check_in1(gate, gate_type),
        };

        let in2_status = match newly_available {
            Some(wire_id) if gate.in2 == wire_id => Status::Available { is_primary: false },
            _ => self.check_in2(gate, gate_type, in1_status),
        };

        if let (
            Status::Available {
                is_primary: in1_is_primary,
            },
            Status::Available {
                is_primary: in2_is_primary,
            },
        ) = (in1_status, in2_status)
        {
            if self.pending_level.and_gates.contains(&gate)
                || self.pending_level.xor_gates.contains(&gate)
            {
                return;
            }

            if !in1_is_primary {
                self.wire_used(gate.in1);
            }
            if !in2_is_primary {
                self.wire_used(gate.in2);
            }

            // queue the gate in this level
            match gate_type {
                GateType::AND => {
                    self.pending_level.and_gates.insert(gate);
                }
                GateType::XOR => {
                    self.pending_level.xor_gates.insert(gate);
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

        let newly_available_wires = {
            let mut buf = Vec::with_capacity(level.and_gates.len() + level.xor_gates.len());
            for gate in level.and_gates.iter() {
                buf.push((gate.out, gate.credits));
            }
            for gate in level.xor_gates.iter() {
                buf.push((gate.out, gate.credits));
            }
            buf
        };

        let mut waiting_lists: Vec<(CompactWireId, HashSet<CompactDependency>)> = Vec::new();
        // mark newly available wires
        for (wire_id, credits) in newly_available_wires {
            match self.remove_wire(wire_id) {
                None => {
                    self.set_wire(wire_id, WireAvailability::Available(credits));
                }
                Some(WireAvailability::Available(_)) => {
                    cold_and_empty();
                    panic!("gate already processed");
                }
                Some(WireAvailability::Waiting(waiting_set)) => {
                    self.set_wire(wire_id, WireAvailability::Available(credits));
                    waiting_lists.push((wire_id, waiting_set));
                }
                Some(WireAvailability::WaitingInline(dep)) => {
                    self.set_wire(wire_id, WireAvailability::Available(credits));
                    let mut set = HashSet::with_capacity(1);
                    set.insert(dep);
                    waiting_lists.push((wire_id, set));
                }
            }
        }
        // prep next level
        for (real_out, waiting_set) in waiting_lists {
            for dep in waiting_set {
                let dep = dep.to_dependency();
                self.process_gate(
                    IntermediateGate {
                        in1: real_out,
                        in2: dep.other_in,
                        out: dep.out,
                        credits: dep.credits,
                    },
                    dep.gate_type,
                    Some(real_out),
                );
            }
        }

        Some(level)
    }

    pub fn new(primary_inputs: u64) -> Self {
        Self {
            permanent_wires: CompactWireId::from_u64(
                primary_inputs + 2, /* false, true wires at the start */
            ),
            level_id: 1,
            pending_level: PendingLevel::default(),
            state: HashMap::new(),
        }
    }

    pub fn add_gate(&mut self, gate: IntermediateGate, gate_type: GateType) {
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
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(1),
            },
            GateType::AND,
        );

        // Should create first level immediately
        let level = leveller.take_level().expect("Should produce a level");
        assert_eq!(level.id, 1);
        assert_eq!(level.and_gates.len(), 1);
        assert_eq!(level.xor_gates.len(), 0);

        // No more levels should be produced
        assert!(leveller.take_level().is_none());
    }

    #[test]
    fn test_dependency_chain() {
        // Test gates that depend on each other
        let mut leveller = Leveller::new(10);

        // Gate A: inputs 0,1 -> output 100
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(1),
            },
            GateType::AND,
        );

        // Gate B: inputs 100,2 -> output 101 (depends on gate A)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(2),
                out: CompactWireId::from_u64(101),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        // Gate C: inputs 101,3 -> output 102 (depends on gate B)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(101),
                in2: CompactWireId::from_u64(3),
                out: CompactWireId::from_u64(102),
                credits: Credits(1),
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
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(3), // Wire 100 feeds 3 gates
            },
            GateType::AND,
        );

        // Gate B: inputs 100,2 -> output 101 (depends on A)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(2),
                out: CompactWireId::from_u64(101),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        // Gate C: inputs 100,3 -> output 102 (also depends on A)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(3),
                out: CompactWireId::from_u64(102),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        // Gate D: inputs 100,4 -> output 103 (also depends on A)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(4),
                in2: CompactWireId::from_u64(100), // Note: wire 100 as second input
                out: CompactWireId::from_u64(103),
                credits: Credits(1),
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
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(1),
            },
            GateType::AND,
        );

        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(2),
                in2: CompactWireId::from_u64(3),
                out: CompactWireId::from_u64(101),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        // Level 2 gate - depends on both level 1 gates
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(101),
                out: CompactWireId::from_u64(102),
                credits: Credits(1),
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
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(101),
                out: CompactWireId::from_u64(200),
                credits: Credits(1),
            },
            GateType::AND,
        );

        // Primary input gates (can execute immediately)
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        // Another dependent gate
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(200),
                in2: CompactWireId::from_u64(102),
                out: CompactWireId::from_u64(201),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(2),
                in2: CompactWireId::from_u64(3),
                out: CompactWireId::from_u64(101),
                credits: Credits(1),
            },
            GateType::AND,
        );

        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(4),
                in2: CompactWireId::from_u64(5),
                out: CompactWireId::from_u64(102),
                credits: Credits(1),
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
            IntermediateGate {
                in1: CompactWireId::from_u64(100),
                in2: CompactWireId::from_u64(101),
                out: CompactWireId::from_u64(200),
                credits: Credits(1),
            },
            GateType::AND,
        );

        // Add gates that provide inputs
        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(0),
                in2: CompactWireId::from_u64(1),
                out: CompactWireId::from_u64(100),
                credits: Credits(1),
            },
            GateType::XOR,
        );

        leveller.add_gate(
            IntermediateGate {
                in1: CompactWireId::from_u64(2),
                in2: CompactWireId::from_u64(3),
                out: CompactWireId::from_u64(101),
                credits: Credits(1),
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

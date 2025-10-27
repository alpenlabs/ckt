//! Circuit levelling algorithm for organizing gates into evaluable levels.
//!
//! This module implements a topological sorting algorithm that organizes circuit gates
//! into "levels" where all gates in a level can be evaluated in parallel. Each level's
//! gates have their inputs available from either:
//! - Primary inputs (circuit inputs)
//! - Outputs from gates in previous levels
//!
//! # Key Features
//! - **Memory efficient**: Uses compact 34-bit wire IDs and 11-byte dependency encoding
//! - **Reference counting**: Automatically frees wire state when no longer needed
//! - **Inline optimization**: Single dependencies stored inline to avoid heap allocation
//! - **Safe API**: All unsafe code encapsulated behind safe abstractions
//!
//! # Example
//! ```ignore
//! let mut leveller = Leveller::new(num_primary_inputs);
//!
//! // Add gates to the leveller
//! for gate in gates {
//!     leveller.add_gate(gate, gate_type);
//! }
//!
//! // Extract levels for evaluation
//! while let Some(level) = leveller.take_level() {
//!     // Evaluate all gates in this level in parallel
//!     process_level(level);
//! }
//! ```

use std::mem;

// pub mod new;
pub mod slab;
pub mod state_map;
pub mod types;

use crate::state_map::WireStateMap;
use crate::types::{
    CompactDependency, CompactWireId, Credits, IntermediateGate, Level, PendingLevel,
    WireAvailability,
};

use ahash::{HashSet, HashSetExt};
use ckt::GateType;
use cynosure::hints::{cold_and_empty, unlikely};
use fixedbitset::FixedBitSet;

/// The main levelling algorithm state.
///
/// Maintains wire availability state and organizes gates into evaluable levels.
/// Gates are processed as their inputs become available, and grouped into levels
/// where all gates can be evaluated in parallel.
///
/// # Invariants
/// - All gate outputs must have unique wire IDs
/// - Wire IDs below `permanent_wires` are always considered available (primary inputs + constants)
/// - Credits track how many gates still need each wire; wires are freed when credits reach 1
pub struct Leveller {
    permanent_wires: CompactWireId,
    level_id: u32,
    pending_level: PendingLevel,
    state: WireStateMap,
    available: FixedBitSet,
}

impl Leveller {
    fn wire_used(&mut self, wire_id: CompactWireId) {
        // use crate::state_map::SlotRef;

        // let Some(SlotRef::Available(mut guard)) = self.state.get_slot_mut(wire_id) else {
        //     panic!("Wire is not available");
        // };
        // // cleanup memory if no future gates reference this wire
        // let credits = guard.get();
        // if credits.0 > 1 {
        //     guard.set(Credits(credits.0 - 1));
        // } else {
        //     self.state.remove(wire_id);
        // }
    }
}

/// Internal: Status of a gate input wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Wire is not yet available; gate must wait
    Waiting,
    /// Wire is available for use
    Available {
        /// True if this is a primary input (below permanent_wires threshold)
        is_primary: bool,
    },
}

impl Leveller {
    /// Checks if input 1 of a gate is available, enqueueing if not.
    ///
    /// If the wire is not available, registers this gate as waiting for it.
    fn check_in1(&mut self, gate: IntermediateGate, gate_type: GateType) -> Status {
        if unlikely(gate.in1 < self.permanent_wires) {
            return Status::Available { is_primary: true };
        }

        if self.available.contains(gate.in1.to_u64() as usize) {
            return Status::Available { is_primary: false };
        }

        let dep = CompactDependency::new(gate.in2, gate.out, gate_type, gate.credits);
        let waiting = self.state.enqueue_waiting(gate.in1, dep);

        if waiting {
            Status::Waiting
        } else {
            Status::Available { is_primary: false }
        }
    }

    /// Checks if input 2 of a gate is available, enqueueing if not.
    ///
    /// If the wire is not available, registers this gate as waiting for it.
    fn check_in2(&mut self, gate: IntermediateGate, gate_type: GateType) -> Status {
        if unlikely(gate.in2 < self.permanent_wires) {
            return Status::Available { is_primary: true };
        }

        if self.available.contains(gate.in2.to_u64() as usize) {
            return Status::Available { is_primary: false };
        }

        let dep = CompactDependency::new(gate.in1, gate.out, gate_type, gate.credits);
        let waiting = self.state.enqueue_waiting(gate.in2, dep);

        if waiting {
            Status::Waiting
        } else {
            Status::Available { is_primary: false }
        }
    }

    /// Processes a gate, adding it to the current level if both inputs are ready.
    ///
    /// # Arguments
    /// - `newly_available`: Optional optimization hint - if provided, skips checking
    ///   this wire's availability (caller guarantees it's available)
    fn process_gate(
        &mut self,
        gate: IntermediateGate,
        gate_type: GateType,
        newly_available: Option<CompactWireId>,
    ) {
        let in1_status = match newly_available {
            Some(wire_id) if gate.in1 == wire_id => Status::Available { is_primary: false },
            _ => self.check_in1(gate, gate_type),
        };

        let in2_status = match newly_available {
            Some(wire_id) if gate.in2 == wire_id => Status::Available { is_primary: false },
            _ => self.check_in2(gate, gate_type),
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

    /// Extracts the next complete level of gates, or None if no gates are ready.
    ///
    /// This method:
    /// 1. Returns None if the pending level is empty
    /// 2. Takes all gates from the pending level
    /// 3. Marks their outputs as available
    /// 4. Processes any gates that were waiting for these outputs
    /// 5. Returns the completed level
    ///
    /// # Panics
    /// Panics if a gate output is already marked as available, which indicates
    /// duplicate output wires (invalid circuit structure).
    ///
    /// # Example
    /// ```ignore
    /// while let Some(level) = leveller.take_level() {
    ///     println!("Level {}: {} AND gates, {} XOR gates",
    ///              level.id, level.and_gates.len(), level.xor_gates.len());
    ///     // Evaluate the level...
    /// }
    /// ```
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
            match self.state.remove(wire_id) {
                None => {
                    self.available.insert(wire_id.to_u64() as usize);
                }
                Some(WireAvailability::Available(_)) => {
                    cold_and_empty();
                    panic!("gate already processed");
                }
                Some(WireAvailability::Waiting(waiting_set)) => {
                    self.available.insert(wire_id.to_u64() as usize);
                    waiting_lists.push((wire_id, waiting_set));
                }
                Some(WireAvailability::WaitingInline(dep)) => {
                    self.available.insert(wire_id.to_u64() as usize);
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

    /// Creates a new leveller for a circuit with the given number of primary inputs.
    ///
    /// # Arguments
    /// - `primary_inputs`: Number of primary input wires in the circuit
    ///
    /// The first `primary_inputs + 2` wires are reserved for:
    /// - Wire 0: constant false
    /// - Wire 1: constant true
    /// - Wires 2..primary_inputs+2: actual primary inputs
    ///
    /// These wires are always considered available and never stored in the state map.
    pub fn new(primary_inputs: u64) -> Self {
        Self {
            permanent_wires: CompactWireId::from_u64(
                primary_inputs + 2, /* false, true wires at the start */
            ),
            level_id: 1,
            pending_level: PendingLevel::default(),
            state: WireStateMap::new(),
            available: FixedBitSet::with_capacity(2usize.pow(34)),
        }
    }

    /// Adds a gate to the leveller.
    ///
    /// If both inputs are available, the gate is added to the current level immediately.
    /// Otherwise, the gate is registered as waiting for its unavailable input(s).
    ///
    /// # Requirements
    /// - Gate output wire ID must be unique (not used by any other gate)
    /// - Gate output must not be a primary input wire
    ///
    /// # Example
    /// ```ignore
    /// leveller.add_gate(
    ///     IntermediateGate {
    ///         in1: CompactWireId::from_u64(0),  // false constant
    ///         in2: CompactWireId::from_u64(2),  // first primary input
    ///         out: CompactWireId::from_u64(100),
    ///         credits: Credits(1),
    ///     },
    ///     GateType::AND,
    /// );
    /// ```
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

use std::collections::*;

use super::circuit::Circuit;
use super::coords::*;
use super::gate::*;

/// Manages tracking of gates that have and haven't been satisfied.
pub struct GateSatisfactionTracker<'c> {
    circuit: &'c Circuit,

    /// Set of wires that have been satisfied one.
    singly_satisfied_idxs: HashSet<AbsWireIdx>,

    /// Indexes that are ready to be included in a level.
    ///
    /// `BTreeSet` because we want to make ordering deterministic.
    ready_idxs: BTreeSet<AbsWireIdx>,

    /// Set of all wires that have been evaluated already.
    evaluated_idxs: BTreeSet<AbsWireIdx>,
}

impl<'c> GateSatisfactionTracker<'c> {
    /// Constructs a new instance with new wires assigned values.
    ///
    /// Does NOT mark input wires.
    pub fn new(circuit: &'c Circuit) -> Self {
        Self {
            circuit,
            singly_satisfied_idxs: HashSet::new(),
            ready_idxs: BTreeSet::new(),
            evaluated_idxs: BTreeSet::new(),
        }
    }

    /// Gets the inner circuit.
    pub fn circuit(&self) -> &'c Circuit {
        self.circuit
    }

    /// Gets the set of ready indexes.
    pub fn ready_idxs(&self) -> &BTreeSet<AbsWireIdx> {
        &self.ready_idxs
    }

    /// Checks if there's wires that haven't been computed based on the size of
    /// the sets of evaluated idxs and whatnot.
    fn has_uncomputed_wires(&self) -> bool {
        self.evaluated_idxs.len() == self.circuit.num_wires() as usize
    }

    /// Promotes a gate's satisfaction value.
    fn promote_idx(&mut self, i: AbsWireIdx) {
        if self.ready_idxs.contains(&i) {
            panic!("builder: triply satisfy wire {i:?}");
        }

        if self.singly_satisfied_idxs.contains(&i) {
            self.singly_satisfied_idxs.remove(&i);
            self.ready_idxs.insert(i);
        } else {
            self.singly_satisfied_idxs.insert(i);
        }
    }

    fn mark_wire_evaled_inner(&mut self, i: AbsWireIdx) {
        let wu = self
            .circuit
            .get_wire_uses(i)
            .expect("builder: get invalid wire");

        for i in wu {
            self.promote_idx(*i);
        }

        self.evaluated_idxs.insert(i);
    }

    /// Marks a wire as a ready input wire.  This just skips satisfaction
    /// checks (since they have no internal satisfaction requirements) and
    /// directly performs the downstream updates in accordance with it.
    pub fn mark_input_wire(&mut self, i: AbsWireIdx) {
        self.mark_wire_evaled_inner(i);
    }

    /// Marks a wire as having been evaluated, and performs bookkeeping to
    /// determine which other wires *could* be evaluated.
    pub fn mark_wire_evaled(&mut self, i: AbsWireIdx) {
        // Sanity check.
        if !self.ready_idxs.contains(&i) {
            panic!("builder: evaling wire not ready {i:?}");
        }

        self.mark_wire_evaled_inner(i);
        self.ready_idxs.remove(&i);
    }
}

/// Information about the wires that are made available at a particular level,
/// either as an input or as an output of an evaluatable gate.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct LevelWires {
    wires: Vec<AbsWireIdx>,
}

impl LevelWires {
    pub fn new(wires: Vec<AbsWireIdx>) -> Self {
        Self { wires }
    }

    pub fn new_inputs(inputs: usize) -> Self {
        Self::new((0..inputs).map(AbsWireIdx::from).collect())
    }

    pub fn wires(&self) -> &[AbsWireIdx] {
        &self.wires
    }
}

/// Updates to wires as of a level.
pub struct LevelWireUpdates {
    /// Wires that are last used in this layer that can be removed from the state.
    last_use: Vec<AbsWireIdx>,

    /// Wires that are newly produced.
    ///
    /// The indexes in this vec are the second parts of the [`WireLevelIdx`] for
    /// the wires referenced in each entry.
    produced: Vec<AbsWireIdx>,
}

/// Takes a circuit and returns a list of levels, containing the wires that can
/// be evaluated on each level.
fn gen_level_allocs(circuit: &Circuit) -> Vec<LevelWires> {
    let mut tracker = GateSatisfactionTracker::new(circuit);
    for w in circuit.input_idxs_iter().clone() {
        tracker.mark_input_wire(w);
    }

    let mut levels = Vec::new();
    levels.push(LevelWires::new_inputs(circuit.num_inputs()));

    // Keep looping while there's wires that haven't been computed yet.
    while tracker.has_uncomputed_wires() {
        // Get the ready gates as a vec.
        let ready_gates = tracker.ready_idxs().iter().copied().collect::<Vec<_>>();

        // Sanity check.
        if ready_gates.is_empty() {
            panic!(
                "builder: no more ready gates, unable to make progress, aborting (near level {})",
                levels.len()
            );
        }

        // Mark all these gates as evaluated and store them it in the table.
        for r in &ready_gates {
            tracker.mark_wire_evaled(*r);
        }

        levels.push(LevelWires::new(ready_gates));
    }

    levels
}

/// Information about a wire's lifespan across evaluation levels
#[derive(Clone, Debug)]
pub struct WireLifespan {
    /// Level where the wire first becomes available (computed or input)
    birth_level: usize,
    /// Level where the wire is last used as input to a gate
    last_use_level: Option<usize>,
}

impl WireLifespan {
    pub fn new(birth_level: usize, last_use_level: Option<usize>) -> Self {
        Self {
            birth_level,
            last_use_level,
        }
    }

    pub fn birth_level(&self) -> usize {
        self.birth_level
    }

    pub fn last_use_level(&self) -> Option<usize> {
        self.last_use_level
    }

    /// Returns the level after which this wire's state slot can be reused
    pub fn slot_free_level(&self) -> Option<usize> {
        self.last_use_level.map(|level| level + 1)
    }
}

/// Analyzes wire lifespans across evaluation levels
pub fn analyze_wire_lifespans(
    circuit: &Circuit,
    level_wires: &[LevelWires],
) -> HashMap<AbsWireIdx, WireLifespan> {
    let mut lifespans: HashMap<AbsWireIdx, WireLifespan> = HashMap::new();

    // First pass: Record birth levels for all wires
    for (level_idx, level) in level_wires.iter().enumerate() {
        for &wire_idx in level.wires() {
            lifespans.insert(wire_idx, WireLifespan::new(level_idx, None));
        }
    }

    // Second pass: Find last use levels by examining gate inputs
    for (level_idx, level) in level_wires.iter().enumerate().skip(1) {
        // Skip level 0 (inputs)
        for &wire_idx in level.wires() {
            if let Some(gate) = circuit.get_wire_as_gate(wire_idx) {
                // Update last use for input wires
                update_last_use(&mut lifespans, gate.inp1(), level_idx);
                update_last_use(&mut lifespans, gate.inp2(), level_idx);
            }
        }
    }

    lifespans
}

/// Helper function to update the last use level for a wire
fn update_last_use(
    lifespans: &mut HashMap<AbsWireIdx, WireLifespan>,
    wire_idx: AbsWireIdx,
    use_level: usize,
) {
    if let Some(lifespan) = lifespans.get_mut(&wire_idx) {
        lifespan.last_use_level = Some(
            lifespan
                .last_use_level
                .map(|current| current.max(use_level))
                .unwrap_or(use_level),
        );
    }
}

/// Manages state slot allocation and tracks wire-to-slot mappings
pub struct StateAllocationTracker {
    /// Mapping from wire indices to their assigned state slots
    wire_to_slot: HashMap<AbsWireIdx, LevelStateIdx>,
    /// Pool of available state slots that can be reused
    available_slots: BTreeSet<u32>,
    /// Next slot ID to allocate if no slots are available for reuse
    next_slot_id: u32,
}

impl StateAllocationTracker {
    /// Creates a new state allocation tracker
    pub fn new() -> Self {
        Self {
            wire_to_slot: HashMap::new(),
            available_slots: BTreeSet::new(),
            next_slot_id: 0,
        }
    }

    /// Allocates a state slot, reusing available slots or creating a new one
    pub fn allocate_slot(&mut self) -> LevelStateIdx {
        if let Some(&slot) = self.available_slots.iter().next() {
            self.available_slots.remove(&slot);
            LevelStateIdx::from(slot)
        } else {
            let slot = self.next_slot_id;
            self.next_slot_id += 1;
            LevelStateIdx::from(slot)
        }
    }

    /// Assigns a slot to a wire
    pub fn assign_wire(&mut self, wire_idx: AbsWireIdx, slot: LevelStateIdx) {
        self.wire_to_slot.insert(wire_idx, slot);
    }

    /// Assigns a new slot to a wire
    pub fn assign_new_slot(&mut self, wire_idx: AbsWireIdx) -> LevelStateIdx {
        let slot = self.allocate_slot();
        self.assign_wire(wire_idx, slot);
        slot
    }

    /// Gets the slot assigned to a wire
    pub fn get_wire_slot(&self, wire_idx: AbsWireIdx) -> Option<LevelStateIdx> {
        self.wire_to_slot.get(&wire_idx).copied()
    }

    /// Frees slots for wires that are no longer needed
    pub fn free_wires_at_level(
        &mut self,
        lifespans: &HashMap<AbsWireIdx, WireLifespan>,
        level_idx: usize,
    ) {
        let mut wires_to_free = Vec::new();

        for (&wire_idx, &slot_idx) in &self.wire_to_slot {
            if let Some(lifespan) = lifespans.get(&wire_idx) {
                if lifespan.slot_free_level() == Some(level_idx) {
                    wires_to_free.push(wire_idx);
                    self.available_slots.insert(slot_idx.into());
                }
            }
        }

        for wire_idx in wires_to_free {
            self.wire_to_slot.remove(&wire_idx);
        }
    }
}

/// Computes efficient state slot assignments for wire values in a circuit evaluation.
///
/// Takes a circuit and its level-wise wire organization, and produces compact gate IO
/// mappings that reuse state slots when wires are no longer needed.
pub fn compute_state_slot_assignments(
    circuit: &Circuit,
    level_wires: &[LevelWires],
) -> Vec<CompactLevelGates> {
    // First analyze wire lifespans
    let lifespans = analyze_wire_lifespans(circuit, level_wires);

    let mut result = Vec::new();
    let mut tracker = StateAllocationTracker::new();

    for (level_idx, level) in level_wires.iter().enumerate() {
        // Free slots for wires that are no longer needed after this level
        tracker.free_wires_at_level(&lifespans, level_idx);

        // Process wires in this level
        if level_idx == 0 {
            // Level 0: Assign slots to input wires
            for &wire_idx in level.wires() {
                tracker.assign_new_slot(wire_idx);
            }
        } else {
            // Level > 0: Process gates and assign output slots
            let mut level_gates = Vec::new();

            for &wire_idx in level.wires() {
                if let Some(gate) = circuit.get_wire_as_gate(wire_idx) {
                    let input1_slot = tracker
                        .get_wire_slot(gate.inp1())
                        .expect("Input wire should have been assigned a slot");
                    let input2_slot = tracker
                        .get_wire_slot(gate.inp2())
                        .expect("Input wire should have been assigned a slot");

                    let output_slot = tracker.assign_new_slot(wire_idx);

                    let compact_io = CompactGateIo::new(input1_slot, input2_slot, output_slot);
                    level_gates.push((gate.ty(), compact_io));
                }
            }

            result.push(CompactLevelGates::from_ty_iter(level_gates.into_iter()));
        }
    }

    result
}

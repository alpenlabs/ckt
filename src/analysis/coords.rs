//! Gate coordinates.

/// Inner typedef that's used for absolute gate indexes.
pub type RawAbsGateIdx = u32;

/// Absolute index of a wire within a circuit, either as an input or from a gate.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AbsWireIdx(RawAbsGateIdx);

impl From<RawAbsGateIdx> for AbsWireIdx {
    fn from(value: RawAbsGateIdx) -> Self {
        Self(value)
    }
}

impl From<AbsWireIdx> for RawAbsGateIdx {
    fn from(value: AbsWireIdx) -> Self {
        value.0
    }
}

impl From<usize> for AbsWireIdx {
    fn from(value: usize) -> Self {
        Self(value as RawAbsGateIdx)
    }
}

impl From<AbsWireIdx> for usize {
    fn from(value: AbsWireIdx) -> Self {
        value.0 as usize
    }
}

/// Absolute index of a level within a circuit.
///
/// Level 0's gate "outputs" are actually the circuit's inputs.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LevelIdx(u32);

impl From<u32> for LevelIdx {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<LevelIdx> for u32 {
    fn from(value: LevelIdx) -> Self {
        value.0
    }
}

/// Coordinates of a wire grouped within the circuit's gates' levels.
///
/// Level 0 corresponds to inputs.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct WireLevelIdx(u32, u32);

impl WireLevelIdx {
    /// If the wire is an input wire.
    pub fn is_input(&self) -> bool {
        self.0 == 0
    }

    /// Gets the wire's level as a [`LevelIdx`].
    pub fn level(self) -> LevelIdx {
        LevelIdx(self.0)
    }
}

impl From<(u32, u32)> for WireLevelIdx {
    fn from(value: (u32, u32)) -> Self {
        Self(value.0, value.1)
    }
}

impl From<WireLevelIdx> for (u32, u32) {
    fn from(value: WireLevelIdx) -> Self {
        (value.0, value.1)
    }
}

/// Index within a state that a wire occupies.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LevelStateIdx(u32);

impl From<u32> for LevelStateIdx {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<LevelStateIdx> for u32 {
    fn from(value: LevelStateIdx) -> Self {
        value.0
    }
}

/// Index into the output buffer.
pub type OutputIdx = usize;

/// Describes a slot that should be copied to the output buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OutputStateCopy {
    /// Index in the output buffer where this value should be copied.
    output_idx: OutputIdx,

    /// State slot index that contains the value to copy.
    state_slot: LevelStateIdx,
}

impl OutputStateCopy {
    /// Creates a new output state copy descriptor.
    pub fn new(output_idx: OutputIdx, state_slot: LevelStateIdx) -> Self {
        Self {
            output_idx,
            state_slot,
        }
    }

    /// Gets the output buffer index.
    pub fn output_idx(&self) -> OutputIdx {
        self.output_idx
    }

    /// Gets the state slot index.
    pub fn state_slot(&self) -> LevelStateIdx {
        self.state_slot
    }
}

//! Gate concepts

use super::coords::*;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct AbsGateIo([AbsWireIdx; 3]);

impl AbsGateIo {
    pub fn new(input1: AbsWireIdx, input2: AbsWireIdx, output: AbsWireIdx) -> Self {
        assert_ne!(input1, output);
        assert_ne!(input2, output);
        Self([input1, input2, output])
    }

    pub fn input1(&self) -> AbsWireIdx {
        self.0[0]
    }

    pub fn input2(&self) -> AbsWireIdx {
        self.0[1]
    }

    pub fn output(&self) -> AbsWireIdx {
        self.0[2]
    }
}

#[derive(Clone, Debug)]
pub struct LevelWireBuf {
    /// The number of AND gates in the level.
    and_gates: usize,

    /// The number of XOR gates in the level.
    xor_gates: usize,

    /// Packed buffer of gate inputs/outputs.
    ///
    /// Length MUST be `3 * (and_gates + xor_gates)`.
    buf: Vec<u32>,
}

#[derive(Copy, Clone, Debug)]
pub enum Wire {
    Input,
    Gate(Gate),
}

#[derive(Copy, Clone, Debug)]
pub struct Gate {
    inp1: AbsWireIdx,
    inp2: AbsWireIdx,
    ty: GateType,
}

impl Gate {
    pub fn new(inp1: AbsWireIdx, inp2: AbsWireIdx, ty: GateType) -> Self {
        Self { inp1, inp2, ty }
    }

    pub fn inp1(&self) -> AbsWireIdx {
        self.inp1
    }

    pub fn inp2(&self) -> AbsWireIdx {
        self.inp2
    }

    pub fn ty(&self) -> GateType {
        self.ty
    }
}

#[derive(Copy, Clone, Debug)]
pub enum GateType {
    AND,
    XOR,
}

/// Compact representation of the gates in a level
#[derive(Clone, Debug)]
pub struct CompactLevelGates {
    /// The number of AND gates in the level.
    and_gates: usize,

    /// The number of XOR gates in the level.
    xor_gates: usize,

    /// The IO for all of the gates in the level.
    gates: Vec<CompactGateIo>,

    /// Output mappings for values that should be copied to the output buffer after this level is evaluated.
    outputs: Vec<OutputStateCopy>,
}

impl CompactLevelGates {
    /// Constructs a new instance.
    ///
    /// # Panics
    ///
    /// If `and_gates` and `xor_gates` do not add to the length of `gates`.
    pub fn new(
        and_gates: usize,
        xor_gates: usize,
        gates: Vec<CompactGateIo>,
        outputs: Vec<OutputStateCopy>,
    ) -> Self {
        assert_eq!(and_gates + xor_gates, gates.len());
        Self {
            and_gates,
            xor_gates,
            gates,
            outputs,
        }
    }

    /// Constructs a new instance from an iterator over the type and the IO data
    /// for each gate.
    pub fn from_ty_iter(iter: impl Iterator<Item = (GateType, CompactGateIo)>) -> Self {
        let mut and_gates = 0;
        let mut xor_gates = 0;

        let mut gates = Vec::new();
        let mut buffered_xor_gates = Vec::new();
        for (ty, io) in iter {
            match ty {
                GateType::AND => {
                    and_gates += 1;
                    gates.push(io);
                }
                GateType::XOR => {
                    xor_gates += 1;
                    buffered_xor_gates.push(io);
                }
            }
        }

        // Copy over the XOR gates.
        gates.extend(buffered_xor_gates.drain(..));

        Self::new(and_gates, xor_gates, gates, Vec::new())
    }

    /// Constructs a new instance from two iterators over the two types of gate.
    pub fn from_iters(
        and_iter: impl Iterator<Item = CompactGateIo>,
        xor_iter: impl Iterator<Item = CompactGateIo>,
    ) -> Self {
        let mut and_gates = 0;
        let mut xor_gates = 0;
        let mut gates = Vec::new();

        for g in and_iter {
            and_gates += 1;
            gates.push(g);
        }

        for g in xor_iter {
            xor_gates += 1;
            gates.push(g);
        }

        Self::new(and_gates, xor_gates, gates, Vec::new())
    }

    /// Returns an iterator over the AND gates.
    pub fn and_gates_iter(&self) -> impl Iterator<Item = CompactGateIo> {
        self.gates.iter().take(self.and_gates).copied()
    }

    /// Returns an iterator over the XOR gates.
    pub fn xor_gates_iter(&self) -> impl Iterator<Item = CompactGateIo> {
        self.gates
            .iter()
            .skip(self.and_gates)
            .take(self.xor_gates)
            .copied()
    }

    /// Gets the output mappings for this level.
    pub fn outputs(&self) -> &[OutputStateCopy] {
        &self.outputs
    }
}

/// Compact representation of a gates inputs and outputs with respect to the
/// state table.
///
/// The `input1` and `input2` fields determine the indexes that are read from
/// the state table, then the gate's operation is performed, then the value is
/// written to the `output` field index.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompactGateIo([LevelStateIdx; 3]);

impl CompactGateIo {
    pub fn new(input1: LevelStateIdx, input2: LevelStateIdx, output: LevelStateIdx) -> Self {
        assert_ne!(input1, output);
        assert_ne!(input2, output);
        Self([input1, input2, output])
    }

    pub fn input1(&self) -> LevelStateIdx {
        self.0[0]
    }

    pub fn input2(&self) -> LevelStateIdx {
        self.0[1]
    }

    pub fn output(&self) -> LevelStateIdx {
        self.0[2]
    }
}

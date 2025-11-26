/// Statistics about a written circuit
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_gates: u64,
    pub xor_gates: u64,
    pub and_gates: u64,
    pub primary_inputs: u64,
    pub scratch_space: u64,
    pub num_outputs: u64,
    pub checksum: [u8; 32],
}

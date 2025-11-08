use std::arch::aarch64::*;

#[derive(Debug, Clone, Copy)]
pub struct Label(pub uint8x16_t);

#[derive(Debug, Clone, Copy)]
pub struct Ciphertext(pub uint8x16_t);

pub struct WorkingSpace(pub Vec<Label>);

impl std::ops::DerefMut for WorkingSpace {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for WorkingSpace {
    type Target = Vec<Label>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct GarblingInstance {
    pub gate_ctr: u64,
    pub working_space: WorkingSpace,
    pub delta: uint8x16_t,
    pub round_key: uint8x16_t,
}

impl GarblingInstance {
    pub fn garble_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];
        self.working_space[out_addr] = Label(unsafe { xor128(in1.0, in2.0) });
        self.gate_ctr += 1;
    }

    pub fn garble_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
    ) -> Ciphertext {
        // Retrieve input labels for in1_0 and in2_0
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];

        let t = unsafe { index_to_tweak(self.gate_ctr) };
        let xor_in1 = unsafe { xor128(in1.0, self.delta) };

        // H(xor_in1, t) and H(in1, t) interleaved
        let mut h_xor_in1_t = unsafe { aes_round(xor_in1, t) };
        let mut h_out = unsafe { aes_round(in1.0, t) };

        for _ in 0..9 {
            h_xor_in1_t = unsafe { aes_round(h_xor_in1_t, t) };
            h_out = unsafe { aes_round(h_out, t) };
        }

        let ciphertext = unsafe { xor128(xor128(h_out, h_xor_in1_t), in2.0) };

        // Write output label to working space
        self.working_space[out_addr] = Label(h_out);

        // Increment gate counter to enforce uniqueness
        self.gate_ctr += 1;

        Ciphertext(ciphertext)
    }
}

/// Extract the point-and-permute bit (LSB) from a label
#[inline]
pub unsafe fn get_permute_bit(label: uint8x16_t) -> bool {
    let bytes: [u8; 16] = unsafe { std::mem::transmute(label) };
    (bytes[0] & 1) == 1
}

/// XOR two 128-bit values
#[inline]
pub unsafe fn xor128(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(a, b) }
}

/// Convert gate index to tweak value
#[inline]
pub unsafe fn index_to_tweak(index: u64) -> uint8x16_t {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&index.to_le_bytes());
    unsafe { std::mem::transmute(bytes) }
}

/// Convert u64 counter to uint8x16_t for RNG
#[inline]
unsafe fn counter_to_vec(counter: u64) -> uint8x16_t {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&counter.to_le_bytes());
    unsafe { vld1q_u8(&bytes as *const u8) }
}

#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
unsafe fn aes_round(input: uint8x16_t, round_key: uint8x16_t) -> uint8x16_t {
    vaesmcq_u8(vaeseq_u8(input, round_key))
}

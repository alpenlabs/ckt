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
    pub rng_counter: u64,
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

        // Extract point-and-permute bits (LSB of each label)
        let p_in1 = unsafe { get_permute_bit(in1.0) };
        let p_in2 = unsafe { get_permute_bit(in2.0) };
        let p_both_1 = p_in1 && p_in2;

        // Compute tweaks for generator and evaluator half-gates
        let tg = unsafe { index_to_tweak(self.gate_ctr * 2) }; // Generator half-gate tweak
        let te = unsafe { index_to_tweak(self.gate_ctr * 2 + 1) };

        // Prepare RNG counter as uint8x16_t
        let rng_counter_vec = unsafe { counter_to_vec(self.rng_counter) };

        // FIRST AES ROUND - 3-way parallel (hash inputs + RNG)
        let aes_in1 = unsafe { aes_round(in1.0, self.round_key) };
        let aes_in2 = unsafe { aes_round(in2.0, self.round_key) };
        let aes_rng1 = unsafe { aes_round(rng_counter_vec, self.round_key) };

        // Continue hash pipeline: XOR with tweaks
        let xor_i1 = unsafe { veorq_u8(aes_in1, tg) };
        let xor_i2 = unsafe { veorq_u8(aes_in2, te) };

        // SECOND AES ROUND - 3-way parallel (hash second round + RNG second round)
        let aes_xor1 = unsafe { aes_round(xor_i1, self.round_key) };
        let aes_xor2 = unsafe { aes_round(xor_i2, self.round_key) };
        let aes_rng2 = unsafe { aes_round(aes_rng1, self.round_key) };

        // Complete hash calculations: H(x,i) = aes(aes(x) xor i) xor aes(x)
        let h_in1_0_tg = unsafe { veorq_u8(aes_xor1, aes_in1) };
        let h_in2_0_te = unsafe { veorq_u8(aes_xor2, aes_in2) };

        // RNG output (2 rounds of AES on counter)
        let c0 = Label(aes_rng2);

        // Build ciphertext step by step:
        // Step 1: XOR the two hash values
        let mut ciphertext = unsafe { xor128(h_in1_0_tg, h_in2_0_te) };

        // Step 2: XOR with the output 0-label
        ciphertext = unsafe { xor128(ciphertext, c0.0) };

        // Step 3: Conditionally XOR with delta if BOTH permute bits are 1
        if p_both_1 {
            ciphertext = unsafe { xor128(ciphertext, self.delta) };
        }

        // Write output label to working space
        self.working_space[out_addr] = c0;

        // Increment gate counter to enforce uniqueness
        self.gate_ctr += 1;

        // Increment RNG counter for next gate
        self.rng_counter = self.rng_counter.wrapping_add(1);

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

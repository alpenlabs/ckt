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
    pub round_keys: [uint8x16_t; 11],
}

const KEYS: [uint8x16_t; 11] = [
    unsafe { std::mem::transmute([0x00u8; 16]) },
    unsafe { std::mem::transmute([0x01u8; 16]) },
    unsafe { std::mem::transmute([0x02u8; 16]) },
    unsafe { std::mem::transmute([0x03u8; 16]) },
    unsafe { std::mem::transmute([0x04u8; 16]) },
    unsafe { std::mem::transmute([0x05u8; 16]) },
    unsafe { std::mem::transmute([0x06u8; 16]) },
    unsafe { std::mem::transmute([0x07u8; 16]) },
    unsafe { std::mem::transmute([0x08u8; 16]) },
    unsafe { std::mem::transmute([0x09u8; 16]) },
    unsafe { std::mem::transmute([0x0Au8; 16]) },
];

impl GarblingInstance {
    pub fn new(scratch_space: u32, delta: uint8x16_t, round_key: uint8x16_t) -> Self {
        let mut bytes = [0u8; 16];
        let empty_label = unsafe { std::mem::transmute(bytes) };

        let key1 = round_key;
        let key2 = unsafe { xor128(key1, empty_label) };
        let key3 = unsafe { xor128(key2, empty_label) };
        let key4 = unsafe { xor128(key3, empty_label) };
        let key5 = unsafe { xor128(key4, empty_label) };
        let key6 = unsafe { xor128(key5, empty_label) };
        let key7 = unsafe { xor128(key6, empty_label) };
        let key8 = unsafe { xor128(key7, empty_label) };
        let key9 = unsafe { xor128(key8, empty_label) };
        let key10 = unsafe { xor128(key9, empty_label) };
        let key11 = unsafe { xor128(key10, empty_label) };

        GarblingInstance {
            gate_ctr: 0,
            working_space: WorkingSpace(vec![Label(empty_label); scratch_space as usize]),
            delta,
            round_keys: [
                key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11,
            ],
        }
    }
}

impl GarblingInstance {
    pub fn garble_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize) {
        let in1 = self.working_space[in1_addr];
        let in2 = self.working_space[in2_addr];
        self.working_space[out_addr] = Label(unsafe { xor128(in1.0, in2.0) });
        self.gate_ctr += 1;
    }

    /// ```
    /// let t = self.gate_ctr;
    /// // H(x,i) -> XOR(AES(XOR(AES(x), i)), AES(x))
    /// // AES(x) -> 10 rounds of AES with fixed keys
    /// self.working_space[out_addr] = H(in1, t);
    /// let ciphertext = H(in1, t) ^ H(in1^self.delta, t) ^ in2;
    /// ```
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
        let xor_in1_delta = unsafe { xor128(in1.0, self.delta) };

        let h_in1_t = unsafe {
            // AES(in1)
            let mut aes_in1 = aes_round(in1.0, KEYS[0]);
            for i in 1..9 {
                aes_in1 = aes_round(aes_in1, KEYS[i]);
            }
            aes_in1 = vaeseq_u8(aes_in1, KEYS[9]);
            aes_in1 = xor128(aes_in1, KEYS[10]);

            // AES(in1) ⊕ t
            let xor_aes_in1_t = xor128(aes_in1, t);

            // AES(AES(in1) ⊕ t)
            let mut aes_xor_aes_in1_t = aes_round(xor_aes_in1_t, KEYS[0]);
            for i in 1..9 {
                aes_xor_aes_in1_t = aes_round(aes_xor_aes_in1_t, KEYS[i]);
            }
            aes_xor_aes_in1_t = vaeseq_u8(aes_xor_aes_in1_t, KEYS[9]);
            aes_xor_aes_in1_t = xor128(aes_xor_aes_in1_t, KEYS[10]);

            // AES(AES(in1) ⊕ t) ⊕ AES(in1)
            xor128(aes_xor_aes_in1_t, aes_in1)
        };

        let h_in1_delta_t = unsafe {
            // AES(in1 ⊕ delta)
            let mut aes_in1_delta = aes_round(xor_in1_delta, KEYS[0]);
            for i in 1..9 {
                aes_in1_delta = aes_round(aes_in1_delta, KEYS[i]);
            }
            aes_in1_delta = vaeseq_u8(aes_in1_delta, KEYS[9]);
            aes_in1_delta = xor128(aes_in1_delta, KEYS[10]);

            // AES(in1 ⊕ delta) ⊕ t
            let xor_aes_in1_delta_t = xor128(aes_in1_delta, t);

            // AES(AES(in1 ⊕ delta) ⊕ t)
            let mut aes_xor_aes_in1_delta_t = aes_round(xor_aes_in1_delta_t, KEYS[0]);
            for i in 1..9 {
                aes_xor_aes_in1_delta_t = aes_round(aes_xor_aes_in1_delta_t, KEYS[i]);
            }
            aes_xor_aes_in1_delta_t = vaeseq_u8(aes_xor_aes_in1_delta_t, KEYS[9]);
            aes_xor_aes_in1_delta_t = xor128(aes_xor_aes_in1_delta_t, KEYS[10]);

            // AES(AES(in1 ⊕ delta) ⊕ t) ⊕ AES(in1 ⊕ delta)
            xor128(aes_xor_aes_in1_delta_t, aes_in1_delta)
        };

        let ciphertext = unsafe { xor128(xor128(h_in1_t, h_in1_delta_t), in2.0) };

        // Write output label to working space
        self.working_space[out_addr] = Label(h_in1_t);

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

trait GarblingInstance {
    type Ciphertext;

    fn feed_xor_gate(&mut self, in1_addr: usize, in2_addr: usize, out_addr: usize);
    fn feed_and_gate(
        &mut self,
        in1_addr: usize,
        in2_addr: usize,
        out_addr: usize,
    ) -> Self::Ciphertext;

    fn gate_ctr(&self) -> u64;
}


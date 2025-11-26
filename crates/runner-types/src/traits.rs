//! Runner task traits.

pub trait CircuitTask {
    type Error;

    fn visit_chunk(&mut self, chunk: &Chunk);
}

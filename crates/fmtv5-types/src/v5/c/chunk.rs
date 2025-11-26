//! Chunk of blocks that the reader returns.

use super::Block;

/// A chunk of blocks borrowed from the reader.
#[derive(Clone)]
#[expect(missing_debug_implementations, reason = "it's garbage data in there")]
pub struct Chunk<'b> {
    buf: &'b [u8],
    num_blocks: usize,
}

impl<'b> Chunk<'b> {
    /// Constructs a new instance.
    ///
    /// # Safety
    ///
    /// The `num_blocks` value must correspond to the amount of space available
    /// in the buffer passed, with respect to the size of a [`Block`]
    pub(crate) unsafe fn from_blocks_buf(buf: &'b [u8], num_blocks: usize) -> Self {
        Self { buf, num_blocks }
    }

    /// Returns an iterator over the blocks in the chunk buffer.
    pub fn blocks_iter(&self) -> impl Iterator<Item = &'b Block> {
        // SAFETY: we get the number of blocks sized properly from this always
        unsafe {
            let blocks = &*(self.buf.as_ptr() as *const [Block; 16]);
            blocks.iter().take(self.num_blocks)
        }
    }
}

struct Engine {
    max_threads: usize,
    max_mem: usize,
}

use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct WorkQueue {
    buffer_a: [u8; 4 * 1024 * 1024],
    buffer_b: [u8; 4 * 1024 * 1024],

    // Which buffer workers should read from
    active_buffer: AtomicBool, // false = A, true = B

    // Number of valid blocks in each buffer (0-16, 0 means shutdown)
    blocks_in_a: AtomicUsize,
    blocks_in_b: AtomicUsize,

    // Synchronization barrier
    barrier: Arc<Barrier>,
}

fn worker_thread(queue: Arc<WorkQueue>, worker_id: usize, num_workers: usize) {
    loop {
        // Determine which buffer to process
        let use_buffer_a = !queue.active_buffer.load(Ordering::Acquire);

        let (buffer, num_blocks) = if use_buffer_a {
            (&queue.buffer_a, queue.blocks_in_a.load(Ordering::Acquire))
        } else {
            (&queue.buffer_b, queue.blocks_in_b.load(Ordering::Acquire))
        };

        // If num_blocks is 0, shutdown
        if num_blocks == 0 {
            queue.barrier.wait(); // Synchronize one last time
            break;
        }

        // Process valid blocks (distribute work among workers)
        for block_idx in (worker_id..num_blocks).step_by(num_workers) {
            process_block(buffer, block_idx);
        }

        // Wait at barrier
        queue.barrier.wait();
    }
}

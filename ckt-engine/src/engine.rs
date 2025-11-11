use std::{
    cell::UnsafeCell,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Instant,
};

use ckt::{
    GateType,
    v5::c::{BLOCK_SIZE, Block, GATES_PER_BLOCK, reader::ReaderV5c},
};
use cynosure::hints::{likely, unlikely};
use indicatif::ProgressBar;

use crate::aarch64::GarblingInstance;

struct State {
    // Index of the buffer currently active for workers: 0 or 1
    active_idx: usize,
    // Number of valid blocks in the active buffer (0 means shutdown phase)
    blocks_in_active: usize,
    // Global block index of the first block in the active buffer
    phase_base_block_index: usize,
    // Phase counter; workers wait until this increases
    phase: u64,
    // Number of workers that haven't yet finished the current phase
    workers_remaining: usize,
    // Shutdown flag: true when no more data will be published
    shutdown: bool,
}

struct WorkQueue {
    // Two fixed buffers. Invariants:
    // - Master writes only to the inactive buffer.
    // - Workers read only from the active buffer.
    buffers: [UnsafeCell<Box<[u8; BLOCK_SIZE * 16]>>; 2],

    state: Mutex<State>,
    cv: Condvar,

    total_gates: usize,
    num_workers: usize,
}

// Safe because we enforce race-free access via the state machine above
unsafe impl Sync for WorkQueue {}

pub async fn run_double_buffer_all_workers_identical(
    path: &str,
    num_workers: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = ReaderV5c::open(path)?;
    let scratch_space = reader.header().scratch_space as u32;
    let total_gates = reader.header().total_gates() as usize;

    let queue = Arc::new(WorkQueue {
        buffers: [
            UnsafeCell::new(Box::new([0u8; BLOCK_SIZE * 16])),
            UnsafeCell::new(Box::new([0u8; BLOCK_SIZE * 16])),
        ],
        state: Mutex::new(State {
            active_idx: 0,
            blocks_in_active: 0,
            phase_base_block_index: 0,
            phase: 0,
            workers_remaining: 0,
            shutdown: false,
        }),
        cv: Condvar::new(),
        total_gates,
        num_workers,
    });

    // Pre-fill buffer 0 and publish the first phase
    let first_blocks = {
        let buf0 = unsafe { &mut *queue.buffers[0].get() };
        reader.read_blocks(&mut buf0[..]).await?
    };
    let mut total_blocks_read = first_blocks;

    {
        let mut st = queue.state.lock().unwrap();
        st.active_idx = 0;
        st.blocks_in_active = first_blocks;
        st.phase_base_block_index = 0; // first buffer starts at global block index 0
        st.phase = 1;
        st.workers_remaining = num_workers;
        st.shutdown = first_blocks == 0;
        queue.cv.notify_all();
    }

    // Spawn workers
    let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let q = Arc::clone(&queue);
        workers.push(thread::spawn(move || worker_thread_all(q, scratch_space)));
    }

    let pb = ProgressBar::new(total_gates as u64);
    let start = Instant::now();

    let mut gates_left = total_gates;

    // Master loop: read into inactive while workers process active
    loop {
        // Determine inactive buffer
        let inactive_idx = {
            let st = queue.state.lock().unwrap();
            st.active_idx ^ 1
        };

        // Read next batch into inactive buffer (overlapped with worker compute)
        let next_blocks = {
            let buf = unsafe { &mut *queue.buffers[inactive_idx].get() };
            reader.read_blocks(&mut buf[..]).await?
        };
        total_blocks_read += next_blocks;

        for _ in 0..next_blocks {
            let gates_in_block = gates_left.min(GATES_PER_BLOCK);
            gates_left -= gates_in_block;
            pb.inc(gates_in_block as u64);
        }

        // Wait until all workers finished current phase
        {
            let mut st = queue.state.lock().unwrap();
            while st.workers_remaining > 0 {
                st = queue.cv.wait(st).unwrap();
            }
        }

        // Publish the next phase (flip buffers) or shutdown
        {
            let mut st = queue.state.lock().unwrap();

            if next_blocks == 0 {
                // Shutdown phase: notify workers, wait for their acknowledgement, then exit
                st.shutdown = true;
                st.blocks_in_active = 0;
                st.phase += 1;
                st.workers_remaining = queue.num_workers;
                queue.cv.notify_all();

                while st.workers_remaining > 0 {
                    st = queue.cv.wait(st).unwrap();
                }
                break;
            }

            st.active_idx = inactive_idx;
            st.blocks_in_active = next_blocks;
            st.phase_base_block_index = total_blocks_read - next_blocks;
            st.phase += 1;
            st.workers_remaining = queue.num_workers;
            queue.cv.notify_all();
        }
    }

    for h in workers {
        let _ = h.join();
    }
    pb.finish();
    let elapsed = start.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    Ok(())
}

fn worker_thread_all(queue: Arc<WorkQueue>, scratch_space: u32) {
    // Each worker has its own local garbling instance with identical parameters
    let delta = [0u8; 16];

    let mut instance = GarblingInstance::new(scratch_space, unsafe { std::mem::transmute(delta) });

    let mut seen_phase = 0u64;

    loop {
        // Wait for a new phase
        let (active_idx, blocks_in_active, phase_base_block_index, shutdown) = {
            let mut st = queue.state.lock().unwrap();
            while st.phase == seen_phase {
                st = queue.cv.wait(st).unwrap();
            }
            seen_phase = st.phase;

            // Snapshot values for this phase, then decide action
            (
                st.active_idx,
                st.blocks_in_active,
                st.phase_base_block_index,
                st.shutdown,
            )
        };

        if shutdown || blocks_in_active == 0 {
            // Acknowledge shutdown and exit
            let mut st = queue.state.lock().unwrap();
            st.workers_remaining -= 1;
            if st.workers_remaining == 0 {
                queue.cv.notify_all();
            }
            return;
        }

        // SAFETY: active buffer is read-only to workers during this phase
        let buf = unsafe { &*queue.buffers[active_idx].get() };
        let blocks = unsafe { &*(buf.as_ptr() as *const [Block; 16]) };

        let mut global_block_idx = phase_base_block_index;
        for block in blocks.iter().take(blocks_in_active) {
            let gates_in_this_block = queue
                .total_gates
                .saturating_sub(global_block_idx * GATES_PER_BLOCK)
                .min(GATES_PER_BLOCK);

            process_block(&mut instance, block, gates_in_this_block);
            global_block_idx += 1;
        }

        // Signal phase completion
        let mut st = queue.state.lock().unwrap();
        st.workers_remaining -= 1;
        if st.workers_remaining == 0 {
            queue.cv.notify_all();
        }
        // Loop to wait for next phase
    }
}

#[inline(always)]
fn process_block(instance: &mut GarblingInstance, block: &Block, gates_in_this_block: usize) {
    let gates = &block.gates;
    let types = &block.types;

    // Number of type bytes we need for this block
    let type_bytes = (gates_in_this_block + 7) / 8;

    // For each type byte, process up to 8 gates from the corresponding gates slice window
    for (byte_idx, &ty) in types.iter().take(type_bytes).enumerate() {
        let base = byte_idx * 8;
        let end = (base + 8).min(gates_in_this_block);

        // One bounds check for the window, then iterate
        for (bit_offset, gate) in gates[base..end].iter().enumerate() {
            let is_and = ((ty >> bit_offset) & 1) == 1;
            if is_and {
                instance.garble_and_gate(gate.in1 as usize, gate.in2 as usize, gate.out as usize);
            } else {
                instance.garble_xor_gate(gate.in1 as usize, gate.in2 as usize, gate.out as usize);
            }
        }
    }
}

use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Instant,
};

use ckt::{
    GateType,
    v5::c::{BLOCK_SIZE, Block, GATES_PER_BLOCK, reader::ReaderV5c},
};
use cynosure::hints::unlikely;
use indicatif::ProgressBar;

use crate::aarch64::GarblingInstance;

struct EngineConfig {
    max_threads: usize,
    max_mem: usize,
}

impl EngineConfig {
    fn max_simultaneous_instances(&self, scratch_space: usize) -> usize {
        self.max_mem / (scratch_space * 16)
    }

    fn instances_per_thread(&self, scratch_space: usize) -> usize {
        (self.max_simultaneous_instances(scratch_space) + self.max_threads - 1) / self.max_threads
    }
}

struct Engine {
    config: EngineConfig,
    workers: Vec<JoinHandle<()>>,
}

/// True double-buffer work queue with overlapped I/O and compute
struct WorkQueue {
    buffer_a: Box<[u8; BLOCK_SIZE * 16]>,
    buffer_b: Box<[u8; BLOCK_SIZE * 16]>,

    // Which buffer workers should read from (false = A, true = B)
    active_buffer: AtomicBool,

    // Number of valid blocks in each buffer (0 means shutdown)
    blocks_in_a: AtomicUsize,
    blocks_in_b: AtomicUsize,

    // Synchronization barrier
    barrier: Arc<Barrier>,
}

unsafe impl Send for WorkQueue {}
unsafe impl Sync for WorkQueue {}

pub async fn master_thread() {
    let mut reader = ReaderV5c::open("/Users/user/g16.5c.ckt").unwrap();
    dbg!(reader.header());
    let scratch_space = reader.header().scratch_space as u32;
    let mut gates_left = reader.header().total_gates() as usize;

    // Pre-fill buffer A
    let mut buf_a = Box::new([0u8; BLOCK_SIZE * 16]);
    let blocks_in_a = reader.read_blocks(&mut buf_a[..]).await.unwrap();

    let queue = Arc::new(WorkQueue {
        buffer_a: buf_a,
        buffer_b: Box::new([0u8; BLOCK_SIZE * 16]),
        active_buffer: AtomicBool::new(false), // Start with buffer A
        blocks_in_a: AtomicUsize::new(blocks_in_a),
        blocks_in_b: AtomicUsize::new(0),
        barrier: Arc::new(Barrier::new(2)),
    });

    let queue_worker = queue.clone();
    let worker_td =
        std::thread::spawn(move || worker_thread(queue_worker, gates_left, scratch_space));

    let pb = ProgressBar::new(gates_left as u64);
    let start = Instant::now();

    // Worker is now processing buffer A
    // Master immediately starts filling buffer B (OVERLAP!)
    let naughty_ptr = Arc::as_ptr(&queue) as *mut WorkQueue;
    let mut next_blocks = unsafe {
        let buf = &mut *(*naughty_ptr).buffer_b;
        reader.read_blocks(&mut buf[..]).await.unwrap()
    };
    queue.blocks_in_b.store(next_blocks, Ordering::Release);

    loop {
        // Wait for worker to finish processing current buffer
        queue.barrier.wait();

        // Update progress for buffer that just finished
        let just_processed = if queue.active_buffer.load(Ordering::Relaxed) {
            queue.blocks_in_b.load(Ordering::Relaxed)
        } else {
            queue.blocks_in_a.load(Ordering::Relaxed)
        };

        for _ in 0..just_processed {
            let gates_in_block = gates_left.min(GATES_PER_BLOCK);
            gates_left -= gates_in_block;
            pb.inc(gates_in_block as u64);
        }

        // Swap buffers - worker will now process the buffer we just filled
        // (Even if next_blocks == 0, we need to swap so worker sees the zero in correct atomic)
        queue.active_buffer.fetch_xor(true, Ordering::Release);

        // Check if we're done AFTER swapping
        if next_blocks == 0 {
            queue.barrier.wait();
            break;
        }

        // Read into the buffer worker just finished (now inactive)
        // This happens in PARALLEL with worker processing the other buffer!
        let use_buffer_a = queue.active_buffer.load(Ordering::Relaxed);
        let (buffer, atomic) = if use_buffer_a {
            unsafe {
                let buf = &mut *(*naughty_ptr).buffer_a;
                (&mut buf[..], &queue.blocks_in_a)
            }
        } else {
            unsafe {
                let buf = &mut *(*naughty_ptr).buffer_b;
                (&mut buf[..], &queue.blocks_in_b)
            }
        };

        next_blocks = reader.read_blocks(buffer).await.unwrap();
        atomic.store(next_blocks, Ordering::Release);
    }

    let elapsed = start.elapsed();
    println!("Elapsed time: {:?}", elapsed);
    pb.finish();

    worker_td.join().unwrap();
}

fn worker_thread(queue: Arc<WorkQueue>, mut gates_left: usize, scratch_space: u32) {
    let delta = [0u8; 16];
    let round_key = [0u8; 16];

    let mut instance = GarblingInstance::new(
        scratch_space,
        unsafe { std::mem::transmute(delta) },
        unsafe { std::mem::transmute(round_key) },
    );

    loop {
        // Determine which buffer to process
        let use_buffer_a = !queue.active_buffer.load(Ordering::Acquire);

        let (buffer, num_blocks) = if use_buffer_a {
            (
                &queue.buffer_a[..],
                queue.blocks_in_a.load(Ordering::Acquire),
            )
        } else {
            (
                &queue.buffer_b[..],
                queue.blocks_in_b.load(Ordering::Acquire),
            )
        };

        // Shutdown signal
        if unlikely(num_blocks == 0) {
            queue.barrier.wait();
            break;
        }

        // SAFETY: Buffer is valid and won't be modified while we process it
        let blocks = unsafe { &*(buffer.as_ptr() as *const [Block; 16]) };

        // Process all blocks in this buffer
        for block_idx in 0..num_blocks {
            let block = &blocks[block_idx];
            let gates_in_this_block = gates_left.min(GATES_PER_BLOCK);

            for gate_idx in 0..gates_in_this_block {
                let byte_idx = (gate_idx / 8) as usize;
                let bit_idx = gate_idx % 8;
                let gate_type = if (block.types[byte_idx] >> bit_idx) & 1 == 1 {
                    GateType::AND
                } else {
                    GateType::XOR
                };
                let gate = block.gates[gate_idx as usize];

                match gate_type {
                    GateType::AND => {
                        instance.garble_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );
                    }
                    GateType::XOR => {
                        instance.garble_xor_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );
                    }
                }
            }
            gates_left -= gates_in_this_block;
        }

        // Wait for master to finish reading next buffer
        queue.barrier.wait();
    }
}

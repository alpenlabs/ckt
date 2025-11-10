use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Instant,
};

use ckt::{
    GateType,
    v5::c::{Block, GATES_PER_BLOCK, reader::ReaderV5c},
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

/// Zero-copy work queue using raw pointers to reader's internal buffer
struct WorkQueue {
    // Raw pointer to current buffer (set by master, read by workers)
    buffer_ptr: AtomicUsize, // *const u8 as usize

    // Number of valid blocks (0 means shutdown)
    num_blocks: AtomicUsize,

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

    let queue = Arc::new(WorkQueue {
        buffer_ptr: AtomicUsize::new(0),
        num_blocks: AtomicUsize::new(0),
        barrier: Arc::new(Barrier::new(2)), // Master + 1 worker
    });

    let queue_worker = queue.clone();
    let worker_td =
        std::thread::spawn(move || worker_thread(queue_worker, gates_left, scratch_space));

    let pb = ProgressBar::new(gates_left as u64);
    let start = Instant::now();

    loop {
        // Get zero-copy reference to next buffer
        let buffer_ref = reader.next_blocks_ref().await.unwrap();

        match buffer_ref {
            None => {
                // Signal shutdown
                queue.num_blocks.store(0, Ordering::Release);
                queue.barrier.wait();
                break;
            }
            Some((buffer, num_blocks)) => {
                // Share buffer pointer with worker (safe because we wait at barrier)
                let ptr = buffer.as_ptr() as usize;
                queue.buffer_ptr.store(ptr, Ordering::Release);
                queue.num_blocks.store(num_blocks, Ordering::Release);

                // Wait for worker to finish processing
                queue.barrier.wait();

                // Update progress
                let mut num_gates_in_buf = 0;
                for _ in 0..num_blocks {
                    let gates_in_block = gates_left.min(GATES_PER_BLOCK);
                    gates_left -= gates_in_block;
                    num_gates_in_buf += gates_in_block;
                }
                pb.inc(num_gates_in_buf as u64);
            }
        }
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
        // Wait for master to provide next buffer
        queue.barrier.wait();

        // Load buffer info
        let num_blocks = queue.num_blocks.load(Ordering::Acquire);

        // Shutdown signal
        if unlikely(num_blocks == 0) {
            break;
        }

        let buffer_ptr = queue.buffer_ptr.load(Ordering::Acquire) as *const u8;

        // SAFETY: Master guarantees this pointer is valid until next barrier
        let blocks = unsafe { &*(buffer_ptr as *const [Block; 16]) };

        // Process all blocks
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
    }
}

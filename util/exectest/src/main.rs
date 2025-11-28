//! exec test

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use ckt_fmtv5_types::v5::b::reader::{CircuitReaderV5b, Level};
use crossbeam_channel::bounded;
use indicatif::ProgressBar;
use monoio::fs::File;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Wrapper for a pointer address that we know is safe to send between threads
/// because of our circuit structure guarantees (unique outputs per level).
/// We store the address as usize to make it trivially Send/Sync.
#[derive(Copy, Clone)]
struct SendPtr(usize);

// SAFETY: The circuit structure guarantees that each gate in a level writes to
// a unique output index, so there are no data races despite concurrent access.
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

impl SendPtr {
    fn from_ptr(ptr: *mut bool) -> Self {
        SendPtr(ptr as usize)
    }

    fn as_ptr(self) -> *mut bool {
        self.0 as *mut bool
    }
}

enum WorkMessage {
    Process {
        level: Arc<Level>,
        state_ptr: SendPtr,
        barrier: Arc<Barrier>,
    },
    Shutdown,
}

#[monoio::main]
async fn main() {
    // Determine number of worker threads
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Create channels for each worker
    let mut senders = Vec::new();
    let mut handles = Vec::new();

    for worker_id in 0..num_threads {
        let (tx, rx) = bounded::<WorkMessage>(1);
        senders.push(tx);

        let handle = thread::spawn(move || {
            loop {
                match rx.recv() {
                    Ok(WorkMessage::Process {
                        level,
                        state_ptr,
                        barrier,
                    }) => {
                        let ptr = state_ptr.as_ptr();

                        // Process AND gates for this worker
                        let and_chunk_size = level.and_gates.len().div_ceil(num_threads);
                        let and_start = worker_id * and_chunk_size;

                        if and_start < level.and_gates.len() {
                            let and_end = (and_start + and_chunk_size).min(level.and_gates.len());

                            for gate in &level.and_gates[and_start..and_end] {
                                unsafe {
                                    let in1 = resolve_in_unsafe(ptr, gate.in1);
                                    let in2 = resolve_in_unsafe(ptr, gate.in2);
                                    *ptr.add(gate.out as usize) = in1 & in2;
                                }
                            }
                        }

                        // Process XOR gates for this worker
                        let xor_chunk_size = level.xor_gates.len().div_ceil(num_threads);
                        let xor_start = worker_id * xor_chunk_size;

                        if xor_start < level.xor_gates.len() {
                            let xor_end = (xor_start + xor_chunk_size).min(level.xor_gates.len());

                            for gate in &level.xor_gates[xor_start..xor_end] {
                                unsafe {
                                    let in1 = resolve_in_unsafe(ptr, gate.in1);
                                    let in2 = resolve_in_unsafe(ptr, gate.in2);
                                    *ptr.add(gate.out as usize) = in1 ^ in2;
                                }
                            }
                        }

                        // Signal completion
                        barrier.wait();
                    }
                    Ok(WorkMessage::Shutdown) => break,
                    Err(_) => break,
                }
            }
        });

        handles.push(handle);
    }

    let circuit_path = "/Users/user/g16.5b.ckt";
    let file_size = std::fs::metadata(circuit_path).unwrap().len();
    let mut reader = CircuitReaderV5b::open(circuit_path).unwrap();
    let header = reader.header();

    // Print header (copy fields to avoid packed struct alignment issues)
    let primary_inputs = header.primary_inputs;
    let scratch_space = header.scratch_space;
    let and_gates = header.and_gates;
    let xor_gates = header.xor_gates;
    println!("Circuit Header:");
    println!("  Primary Inputs: {}", primary_inputs);
    println!("  Scratch Space: {}", scratch_space);
    println!("  AND Gates: {}", and_gates);
    println!("  XOR Gates: {}", xor_gates);
    println!();

    let mut state = Vec::<bool>::new();
    state.resize(header.scratch_space as usize, false);
    {
        let file = File::open("inputs.txt").await.unwrap();
        let num_bytes = file.metadata().await.unwrap().len();
        let (res, bytes) = file.read_exact_at(vec![0; num_bytes as usize], 0).await;
        res.unwrap();
        let string = String::from_utf8(bytes).unwrap();
        assert_eq!(string.chars().count(), header.primary_inputs as usize);
        for (char_idx, char) in string.chars().enumerate() {
            let idx = char_idx + 2;
            match char {
                '0' => state[idx] = false,
                '1' => state[idx] = true,
                _ => panic!("Invalid input character at pos {}", char_idx),
            }
        }
    };
    let pb = ProgressBar::new(header.and_gates + header.xor_gates);
    let start = Instant::now();
    while let Some(level) = reader.next_level().await.unwrap() {
        let gates_in_lvl = level.and_gates.len() + level.xor_gates.len();

        // SAFETY: We know from the circuit structure that all output indices are unique
        // within this level, and all input indices reference previous levels only.
        // Therefore, no two threads will write to the same location.
        let state_ptr = SendPtr::from_ptr(state.as_mut_ptr());

        // For small levels, avoid synchronization overhead and process on main thread
        if gates_in_lvl < 8_000 {
            let ptr = state_ptr.as_ptr();

            // Process AND gates
            for gate in level.and_gates.iter() {
                unsafe {
                    let in1 = resolve_in_unsafe(ptr, gate.in1);
                    let in2 = resolve_in_unsafe(ptr, gate.in2);
                    *ptr.add(gate.out as usize) = in1 & in2;
                }
            }

            // Process XOR gates
            for gate in level.xor_gates.iter() {
                unsafe {
                    let in1 = resolve_in_unsafe(ptr, gate.in1);
                    let in2 = resolve_in_unsafe(ptr, gate.in2);
                    *ptr.add(gate.out as usize) = in1 ^ in2;
                }
            }
        } else {
            // Arc the level only when using parallel execution
            let level = Arc::new(level);

            // Create barrier for synchronization (num_threads + 1 for main thread)
            let barrier = Arc::new(Barrier::new(num_threads + 1));

            // Send work to all workers
            for sender in &senders {
                sender
                    .send(WorkMessage::Process {
                        level: level.clone(),
                        state_ptr,
                        barrier: barrier.clone(),
                    })
                    .unwrap();
            }

            // Wait for all workers to complete
            barrier.wait();
        }

        pb.inc(gates_in_lvl as u64);
    }

    pb.finish_with_message("Finished");

    // Shutdown workers
    for sender in senders {
        let _ = sender.send(WorkMessage::Shutdown);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let out = state[reader.outputs()[0] as usize];
    let elapsed = start.elapsed();
    let gb_per_sec = (file_size as f64 / (1024.0 * 1024.0 * 1024.0)) / elapsed.as_secs_f64();
    println!("Output: {}", out);
    println!("Total execution time: {:.2}s", elapsed.as_secs_f64());
    println!("Throughput: {:.2} GB/s", gb_per_sec);
}

unsafe fn resolve_in_unsafe(state_ptr: *const bool, idx: u32) -> bool {
    match idx {
        0 => false,
        1 => true,
        idx => unsafe { *state_ptr.add(idx as usize) },
    }
}

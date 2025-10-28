use ahash::{HashMap, HashMapExt};
use ckt::v5::a::reader::CircuitReaderV5a;
use ckt::v5::b::writer::CircuitWriterV5b;
use ckt::{v5, GateType};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lvl::slab::FakeSlabAllocator;
use lvl::types::{CompactWireId, Credits, IntermediateGate};
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

mod cli;

use cli::Cli;
use lvl::Leveller;

// Memory tracking wrapper around mimalloc
struct TrackingAllocator {
    inner: mimalloc::MiMalloc,
}

static MEMORY_LIMIT: OnceLock<usize> = OnceLock::new();

thread_local! {
    static ALLOCATED_BYTES: Cell<usize> = Cell::new(0);

    static MAX_ALLOCATED_BYTES: Cell<usize> = Cell::new(0);
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(limit) = MEMORY_LIMIT.get() {
            let current = ALLOCATED_BYTES.with(|bytes| bytes.get());
            if current + layout.size() > *limit {
                std::process::exit(137);
            }
        }
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            let current = ALLOCATED_BYTES.with(|bytes| {
                bytes.set(bytes.get() + layout.size());
                bytes.get()
            });
            MAX_ALLOCATED_BYTES.with(|max| {
                max.set(max.get().max(current));
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATED_BYTES.with(|bytes| {
            bytes.set(bytes.get().saturating_sub(layout.size()));
        });
        self.inner.dealloc(ptr, layout);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if let Some(limit) = MEMORY_LIMIT.get() {
            let current = ALLOCATED_BYTES.with(|bytes| bytes.get());
            if current + layout.size() > *limit {
                std::process::exit(137);
            }
        }
        let ptr = self.inner.alloc_zeroed(layout);
        if !ptr.is_null() {
            let current = ALLOCATED_BYTES.with(|bytes| {
                bytes.set(bytes.get() + layout.size());
                bytes.get()
            });
            MAX_ALLOCATED_BYTES.with(|max| {
                max.set(max.get().max(current));
            });
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.inner.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let current = ALLOCATED_BYTES.with(|bytes| {
                let current = bytes.get();
                bytes.set(current - layout.size() + new_size);
                bytes.get()
            });
            MAX_ALLOCATED_BYTES.with(|max| {
                max.set(max.get().max(current));
            });
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator {
    inner: mimalloc::MiMalloc,
};

fn get_memory_usage_mb() -> f64 {
    ALLOCATED_BYTES.with(|bytes| bytes.get() as f64) / (1024.0 * 1024.0)
}

fn get_max_memory_usage_mb() -> f64 {
    MAX_ALLOCATED_BYTES.with(|max| max.get() as f64) / (1024.0 * 1024.0)
}

// Constants removed - now provided via CLI arguments

#[monoio::main(timer_enabled = true)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Cli::parse_args();

    MEMORY_LIMIT
        .set(args.memory_limit_gb * 1024usize.pow(3))
        .unwrap();

    println!("Circuit Level Organizer - Sliding Window Algorithm");
    println!("===================================================");
    println!("Input:  {}", args.input.display());
    println!("Output: {}", args.output.display());

    // First pass: get total gates count and primary inputs
    let (total_gates, primary_inputs) = {
        let reader = CircuitReaderV5a::open(&args.input)?;
        let total = reader.header().total_gates();
        let primary_inputs = reader.header().primary_inputs;
        (total, primary_inputs)
    };

    println!("Total gates in circuit: {}", total_gates);
    println!("Primary inputs: {}", primary_inputs);

    if args.verbose {
        println!("Memory limit: {} GB", args.memory_limit_gb);
        println!("Target pending gates in memory: {}", args.target_pending);
        println!("Refill check interval: {} gates", args.check_interval);
        println!("Stuck batch size: {} gates", args.stuck_batch_size);
    }

    // Setup dual progress bars
    let multi_pb = MultiProgress::new();

    // Progress bar for gates loaded into leveller
    let pb_load = multi_pb.add(ProgressBar::new(total_gates as u64));
    pb_load.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} Gates loaded:   [{bar:40.cyan/blue}] {pos}/{len} gates | {msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Progress bar for gates processed into levels
    let pb_level = multi_pb.add(ProgressBar::new(total_gates as u64));
    pb_level.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Gates levelled: [{bar:40.yellow/blue}] {pos}/{len} gates ({eta}) | {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb_level.enable_steady_tick(Duration::from_millis(100));
    pb_load.enable_steady_tick(Duration::from_millis(100));

    let mut leveller = Leveller::new(primary_inputs);

    // Counters
    let mut total_gates_added = 0usize; // Gates added to leveller
    let mut total_gates_in_levels = 0usize; // Gates that made it into levels
    let mut total_levels = 0u32;
    let mut gates_since_check = 0usize;
    let mut last_message_update = Instant::now();

    let update_pb_load = |pending: usize| {
        let bytes_per_gate = if pending > 0 {
            ALLOCATED_BYTES.with(|bytes| bytes.get()) / pending
        } else {
            0
        };
        pb_load.set_message(format!(
            "Mem: {:.1}MB ({} B/gate) | Max: {:.1}MB",
            get_memory_usage_mb(),
            bytes_per_gate,
            get_max_memory_usage_mb()
        ));
    };

    let overall_start = Instant::now();

    // Open file for reading
    let mut reader = CircuitReaderV5a::open(&args.input)?;
    let mut reader_exhausted = false;

    // Initial load - fill up to target
    pb_load.set_message("Filling leveller...");
    while !reader_exhausted {
        match reader.next_block_soa().await {
            Ok(Some(block)) => {
                for gate_idx in 0..block.gates_in_block {
                    let new_gate = IntermediateGate {
                        in1: CompactWireId::from_u64(block.in1[gate_idx]),
                        in2: CompactWireId::from_u64(block.in2[gate_idx]),
                        out: CompactWireId::from_u64(block.out[gate_idx]),
                        credits: Credits(block.credits[gate_idx]),
                    };
                    leveller.add_gate(new_gate, block.gate_types[gate_idx]);
                }
                total_gates_added += block.gates_in_block;
                // Always process the entire batch to avoid missing gates
                pb_load.inc(block.gates_in_block as u64);

                // Check if we've loaded enough after processing the entire batch
                if total_gates_added >= args.target_pending {
                    break;
                }
            }
            _ => {
                reader_exhausted = true;
                break;
            }
        }
    }

    let _ = multi_pb.println(format!(
        "Initial load complete: {} gates loaded",
        total_gates_added
    ));

    let mut writer = CircuitWriterV5b::new(
        args.output,
        primary_inputs,
        reader.outputs().iter().count() as u64,
    )
    .await
    .unwrap();

    let mut slab = FakeSlabAllocator::new();
    let mut wire_map = HashMap::new();
    slab.allocate(); // false wire
    slab.allocate(); // true wire
    for _ in 0..primary_inputs {
        slab.allocate(); // primary input wires
    }
    let mut max_slab_entries = primary_inputs as usize;

    // Main processing loop
    loop {
        // Try to make a level
        let level_start = Instant::now();
        if let Some(level) = leveller.take_level() {
            let level_time = level_start.elapsed();
            let level_gates = level.and_gates.len() + level.xor_gates.len();
            total_gates_in_levels += level_gates;
            gates_since_check += level_gates;
            total_levels += 1;

            writer.start_level().unwrap();

            let mut to_free = Vec::new();

            let mut slab_idx =
                |input: CompactWireId, wire_map: &mut HashMap<CompactWireId, (usize, Credits)>| {
                    if input.to_u64() < 2 + primary_inputs {
                        // input is primary input or constant, so will always be available
                        input.to_u64() as usize
                    } else {
                        let Entry::Occupied(mut entry) = wire_map.entry(input) else {
                            panic!(
                                "Input {:?} not found, primary inputs are 0..{}",
                                input, primary_inputs
                            );
                        };
                        // remove the wire from "memory" aka slab allocator if it's ran out of credits
                        let value: &mut (usize, Credits) = entry.get_mut();
                        let slab_idx = value.0;
                        // if its credits is 0, it's a special wire
                        if value.1 .0 != 0 {
                            value.1 .0 -= 1;

                            if value.1 .0 == 0 {
                                // defer free until end of level
                                to_free.push(slab_idx);

                                // remove from mapping table
                                entry.remove_entry();
                            }
                        }
                        slab_idx
                    }
                };

            // Log level creation
            let _ = multi_pb.println(format!(
                "Level {}: {} gates ({} AND {} XOR) in {:?}",
                level.id,
                level_gates,
                level.and_gates.len(),
                level.xor_gates.len(),
                level_time
            ));

            for (gates, gate_type) in [
                (level.xor_gates, GateType::XOR),
                (level.and_gates, GateType::AND),
            ] {
                for gate in gates {
                    let in1_slab_idx = slab_idx(gate.in1, &mut wire_map);
                    let in2_slab_idx = slab_idx(gate.in2, &mut wire_map);

                    // map [level_idx][wire_idx] from leveller to v5b "memory address"
                    let slab_idx = slab.allocate();
                    wire_map.insert(gate.out, (slab_idx, gate.credits));

                    // update max_slab_entries if necessary
                    if max_slab_entries < slab_idx {
                        max_slab_entries = slab_idx;
                    }

                    writer
                        .add_gate(
                            gate_type,
                            v5::b::writer::GateV5b {
                                in1: in1_slab_idx as u32,
                                in2: in2_slab_idx as u32,
                                out: slab_idx as u32,
                            },
                        )
                        .unwrap();
                }
            }

            // freeing outputs AFTER a level completes ensures memory safety
            // and allows all gates in the level to be executed simultaneously
            for idx in to_free.iter() {
                slab.deallocate(*idx);
            }
            to_free.clear();
            writer.finish_level().await.unwrap();

            // Update level progress bar
            pb_level.set_position(total_gates_in_levels as u64);

            // Update both progress bars
            if last_message_update.elapsed().as_millis() >= 100 {
                let avg_gates_per_level = if total_levels > 0 {
                    total_gates_in_levels / total_levels as usize
                } else {
                    0
                };
                // Update load bar message
                let pending = total_gates_added - total_gates_in_levels;
                update_pb_load(pending);
                pb_level.set_message(format!(
                    "avg {} gates/level | pending {}",
                    avg_gates_per_level, pending
                ));
                last_message_update = Instant::now();
            }

            // Check if we should load more gates
            if gates_since_check >= args.check_interval {
                gates_since_check = 0;
                let pending = total_gates_added - total_gates_in_levels;

                // If pending is below target and we haven't exhausted the file, load more
                if pending < args.target_pending && !reader_exhausted {
                    let to_load = args.target_pending - pending;
                    let mut loaded = 0;

                    // Don't update message during refill to reduce flicker

                    while loaded < to_load && !reader_exhausted {
                        match reader.next_block().await {
                            Ok(Some(gates)) => {
                                for v5a_gate in gates {
                                    let gate = IntermediateGate {
                                        in1: CompactWireId::from_u64(v5a_gate.in1),
                                        in2: CompactWireId::from_u64(v5a_gate.in2),
                                        out: CompactWireId::from_u64(v5a_gate.out),
                                        credits: Credits(v5a_gate.credits),
                                    };

                                    leveller.add_gate(gate, v5a_gate.gate_type);
                                    total_gates_added += 1;
                                    loaded += 1;
                                    pb_load.inc(1 as u64);
                                }
                                if loaded % 10000 == 0 {
                                    update_pb_load(total_gates_added - total_gates_in_levels);
                                }
                                // Check if we've loaded enough after processing the entire batch
                                if loaded >= to_load {
                                    break;
                                }
                            }
                            _ => {
                                reader_exhausted = true;
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            // No more levels can be made
            let pending = total_gates_added - total_gates_in_levels;

            // If we have pending gates and haven't exhausted the file, try loading more
            if pending > 0 && !reader_exhausted {
                // Don't update message to reduce flicker

                let to_load = args.stuck_batch_size; // Load a big batch when stuck
                let mut loaded = 0;

                while loaded < to_load && !reader_exhausted {
                    match reader.next_block().await {
                        Ok(Some(gates)) => {
                            for v5a_gate in gates {
                                let gate = IntermediateGate {
                                    in1: CompactWireId::from_u64(v5a_gate.in1),
                                    in2: CompactWireId::from_u64(v5a_gate.in2),
                                    out: CompactWireId::from_u64(v5a_gate.out),
                                    credits: Credits(v5a_gate.credits),
                                };
                                // Always process the entire batch
                                leveller.add_gate(gate, v5a_gate.gate_type);
                                total_gates_added += 1;
                                loaded += 1;
                                pb_load.inc(1);
                            }
                            // Check if we've loaded enough after processing the entire batch
                            if loaded >= to_load {
                                break;
                            }
                        }
                        _ => {
                            reader_exhausted = true;
                            break;
                        }
                    }
                }

                if loaded == 0 {
                    // File exhausted and no more levels
                    break;
                }
            } else {
                // No pending gates or file exhausted
                break;
            }
        }
    }

    pb_level.set_message("Finalizing...");

    let outputs = reader
        .outputs()
        .iter()
        .map(|wid| wire_map.get(&CompactWireId::from_u64(*wid)).unwrap().0 as u32)
        .collect();

    writer
        .finalize(slab.max_allocated_concurrently() as u64, outputs)
        .await
        .unwrap();
    pb_load.finish_with_message("Complete!");
    pb_level.finish_with_message("Complete!");

    let elapsed = overall_start.elapsed();
    let pending_final = total_gates_added - total_gates_in_levels;

    println!("\n=== Final Statistics ===");
    println!(
        "Total gates read from file: {}/{}",
        total_gates_added, total_gates
    );
    println!("Total gates in levels: {}", total_gates_in_levels);
    println!("Total levels created: {}", total_levels);
    let avg_gates_per_level = if total_levels > 0 {
        total_gates_in_levels as f64 / total_levels as f64
    } else {
        0.0
    };
    println!("Average gates per level: {:.1}", avg_gates_per_level);
    println!("Gates still pending: {}", pending_final);
    println!("Total time: {:.2}s", elapsed.as_secs_f64());
    println!("Final memory usage: {:.1} MB", get_memory_usage_mb());
    println!(
        "Throughput: {:.2} gates/sec",
        total_gates_in_levels as f64 / elapsed.as_secs_f64()
    );

    if pending_final > 0 {
        println!("\n⚠️  WARNING: {} gates remain pending!", pending_final);
        println!("    These gates likely have cyclic dependencies or");
        println!("    reference wires that are never produced.");
    }

    if total_gates_added < total_gates as usize {
        println!(
            "\n⚠️  WARNING: Only read {}/{} gates from file!",
            total_gates_added, total_gates
        );
        println!("    The remaining gates were not needed to complete the circuit.");
    }

    Ok(())
}

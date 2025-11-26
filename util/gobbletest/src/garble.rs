use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use bitvec::vec::BitVec;
use ckt_fmtv5_types::{GateType, v5::c::*};
use ckt_gobble::{
    Engine,
    traits::{GarblingInstance, GarblingInstanceConfig, GobbleEngine},
    x86_64::garb::X86_64GarblingInstance,
};
use ckt_runner_exec::process_task;
use ckt_runner_types::{CircuitTask, GateBlock};
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;

use crate::common::read_inputs;

/// Internal garbling state.
struct GarbleState {
    instance: X86_64GarblingInstance,
    writer: BufWriter<File>,

    total_gates: u64,
    total_gates_processed: u64,
    output_wires: u64,

    progress_bar: ProgressBar,
    start: Instant,
}

#[derive(Debug)]
pub struct GarbleTaskOutput {
    instance: X86_64GarblingInstance,

    garbler_output_labels: Vec<[u8; 16]>,
    output_values: BitVec,
}

struct GarbleTask<'c> {
    garb_config: GarblingInstanceConfig<'c>,
    output_file: PathBuf,
}

impl<'c> GarbleTask<'c> {
    pub fn new(garb_config: GarblingInstanceConfig<'c>, output_file: PathBuf) -> Self {
        Self {
            garb_config,
            output_file,
        }
    }
}

impl<'c> CircuitTask for GarbleTask<'c> {
    type Error = std::io::Error;

    type State = GarbleState;

    type Output = GarbleTaskOutput;

    fn initialize(&self, header: &HeaderV5c) -> Result<Self::State, Self::Error> {
        // Create the engine.
        let engine = Engine::new();
        let instance = engine.new_garbling_instance(self.garb_config);

        // Open the output writer.
        let file = File::create(&self.output_file).unwrap();
        let writer = BufWriter::new(file);

        // Progress meters.
        let total_gates = header.total_gates();
        let pb = ProgressBar::new(total_gates);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("🦃 [{bar:50.cyan/blue}] {percent:>3}% | {msg} | {elapsed_precise}")
                .unwrap()
                .progress_chars("█░"),
        );
        let start = Instant::now();

        Ok(GarbleState {
            instance,
            writer,

            total_gates,
            total_gates_processed: 0,
            output_wires: header.num_outputs,

            progress_bar: pb,
            start,
        })
    }

    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error> {
        for (ginfo, gty) in block.gates_iter() {
            match gty {
                GateType::AND => {
                    let ct = state.instance.feed_and_gate(
                        ginfo.in1 as usize,
                        ginfo.in2 as usize,
                        ginfo.out as usize,
                    );

                    let bytes: [u8; 16] = unsafe { std::mem::transmute(ct.0) };

                    state
                        .writer
                        .write_all(&bytes)
                        .expect("garble: write output table");
                }

                GateType::XOR => state.instance.feed_xor_gate(
                    ginfo.in1 as usize,
                    ginfo.in2 as usize,
                    ginfo.out as usize,
                ),
            }
        }

        state.total_gates_processed += block.num_gates() as u64;
        state.progress_bar.inc(block.num_gates() as u64);

        Ok(())
    }

    fn on_after_chunk(&self, state: &mut Self::State) -> Result<(), Self::Error> {
        let elapsed = state.start.elapsed();
        if elapsed.as_secs_f64() > 0.0 {
            let rate_m = (state.total_gates_processed as f64 / elapsed.as_secs_f64()) / 1_000_000.0;
            let processed_b = state.total_gates_processed as f64 / 1_000_000_000.0;
            let total_b = state.total_gates as f64 / 1_000_000_000.0;

            state.progress_bar.set_message(format!(
                "{:.2}B / {:.2}B gates @ {:.0} M/s",
                processed_b, total_b, rate_m
            ));
        }

        Ok(())
    }

    fn finish(
        &self,
        mut state: Self::State,
        output_wire_idxs: &[u64],
    ) -> Result<Self::Output, Self::Error> {
        // Cleanup.
        state.writer.flush().expect("garble: flush output table");
        state.progress_bar.finish();

        // Extract output values.
        let mut garbler_output_labels = vec![[0u8; 16]; output_wire_idxs.len()];
        let output_values = BitVec::repeat(false, output_wire_idxs.len());
        state.instance.get_selected_labels(
            &output_wire_idxs,
            &output_values,
            &mut garbler_output_labels,
        );

        Ok(GarbleTaskOutput {
            instance: state.instance,
            garbler_output_labels,
            output_values,
        })
    }

    fn on_abort(&self, mut state: Self::State) {
        state
            .writer
            .flush()
            .expect("garble: flush outpput table on abort");
        state.progress_bar.finish();
    }
}

pub async fn garble(
    circuit_file: &str,
    input_file: &str,
    output_file: &str,
    rng: &mut ChaCha20Rng,
) -> ([u8; 16], BitVec, Vec<[u8; 16]>, Vec<[u8; 16]>) {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    // TODO move this setup into `initialize`
    let labels: Vec<_> = (0..header.primary_inputs)
        .map(|_| {
            let mut label = [0u8; 16];
            rng.fill_bytes(&mut label);
            label
        })
        .collect();

    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta,
        primary_input_false_labels: &labels,
    };

    let task_info = GarbleTask::new(config, PathBuf::from(output_file));

    // Execute the garbling loop.
    //
    // The output from this is the garbler output labels.
    let output = process_task(&task_info, &mut reader)
        .await
        .expect("garble: process task");

    println!("\n✓ Garbled circuit written to {}", output_file);

    // Read inputs and encode them
    let input_values_bits = read_inputs(input_file, header.primary_inputs as usize);
    let input_wires: Vec<u64> = (2..=header.primary_inputs + 1).collect();
    let mut input_labels = vec![[0u8; 16]; input_wires.len()];
    output
        .instance
        .get_selected_labels(&input_wires, &input_values_bits, &mut input_labels);

    (
        delta,
        input_values_bits,
        input_labels,
        output.garbler_output_labels,
    )
}

pub async fn garble_discard(circuit_file: &str, rng: &mut ChaCha20Rng) -> Vec<[u8; 16]> {
    let mut reader = ReaderV5c::open(circuit_file).unwrap();

    let header = *reader.header();
    let total_gates = header.total_gates();

    let engine = Engine::new();

    let labels: Vec<_> = (0..header.primary_inputs)
        .map(|_| {
            let mut label = [0u8; 16];
            rng.fill_bytes(&mut label);
            label
        })
        .collect();

    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let config = GarblingInstanceConfig {
        scratch_space: header.scratch_space as u32,
        delta,
        primary_input_false_labels: &labels,
    };

    let mut garb_instance = engine.new_garbling_instance(config);

    let mut block_idx = 0;
    let mut total_gates_processed = 0u64;
    let pb = ProgressBar::new(total_gates);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("🦃 [{bar:50.cyan/blue}] {percent:>3}% | {msg} | {elapsed_precise}")
            .unwrap()
            .progress_chars("█░"),
    );
    let start = Instant::now();
    while let Some(chunk) = reader.next_blocks_chunk().await.unwrap() {
        for block in chunk.blocks_iter() {
            let gates_in_block = get_block_num_gates(total_gates, block_idx);
            block_idx += 1;
            for i in 0..gates_in_block {
                let gate = block.gates[i];
                let gate_type = block.gate_type(i);
                match gate_type {
                    GateType::AND => {
                        garb_instance.feed_and_gate(
                            gate.in1 as usize,
                            gate.in2 as usize,
                            gate.out as usize,
                        );
                    }
                    GateType::XOR => garb_instance.feed_xor_gate(
                        gate.in1 as usize,
                        gate.in2 as usize,
                        gate.out as usize,
                    ),
                }
            }

            total_gates_processed += gates_in_block as u64;
            pb.inc(gates_in_block as u64);
        }

        let elapsed = start.elapsed();
        if elapsed.as_secs_f64() > 0.0 {
            let rate_m = (total_gates_processed as f64 / elapsed.as_secs_f64()) / 1_000_000.0;
            let processed_b = total_gates_processed as f64 / 1_000_000_000.0;
            let total_b = total_gates as f64 / 1_000_000_000.0;
            pb.set_message(format!(
                "{:.2}B / {:.2}B gates @ {:.0} M/s",
                processed_b, total_b, rate_m
            ));
        }
    }

    pb.finish();

    let output_wires = reader
        .outputs()
        .iter()
        .map(|w| *w as u64)
        .collect::<Vec<_>>();
    let mut garbler_output_labels = vec![[0u8; 16]; output_wires.len()];
    let output_values = BitVec::repeat(false, output_wires.len());
    garb_instance.get_selected_labels(&output_wires, &output_values, &mut garbler_output_labels);

    garbler_output_labels
}

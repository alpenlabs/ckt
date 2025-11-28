use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_runner_types::{CircuitTask, GateBlock};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, Read};
use std::time::Instant;

/// Read input bits from a text file containing 0s and 1s
pub fn read_inputs(input_file: &str, expected_num_inputs: usize) -> BitVec {
    let mut input_string = String::new();
    let file = File::open(input_file)
        .unwrap_or_else(|_| panic!("Failed to open input file: {}", input_file));
    let mut reader = BufReader::new(file);
    reader.read_to_string(&mut input_string).unwrap();

    let input_string = input_string.trim();

    assert_eq!(
        input_string.len(),
        expected_num_inputs,
        "Input file has {} bits but circuit expects {}",
        input_string.len(),
        expected_num_inputs
    );

    let mut input_values_bits = BitVec::repeat(false, expected_num_inputs);
    for (idx, char) in input_string.chars().enumerate() {
        match char {
            '0' => input_values_bits.set(idx, false),
            '1' => input_values_bits.set(idx, true),
            _ => panic!("Invalid input character '{}' at position {}", char, idx),
        }
    }

    input_values_bits
}

/// Wrapper that adds progress bar reporting to a CircuitTask implementation.
pub struct ProgressBarTask<T> {
    inner: T,
}

impl<T> ProgressBarTask<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

/// State wrapper that tracks progress bar state alongside the inner task state.
pub struct ProgressBarState<S> {
    inner_state: S,
    progress_bar: ProgressBar,
    start: Instant,
    total_gates: u64,
    total_gates_processed: u64,
}

impl<T: CircuitTask> CircuitTask for ProgressBarTask<T> {
    type Error = T::Error;
    type State = ProgressBarState<T::State>;
    type Output = T::Output;

    fn initialize(&self, header: &HeaderV5c) -> Result<Self::State, Self::Error> {
        let inner_state = self.inner.initialize(header)?;

        let total_gates = header.total_gates();
        let pb = ProgressBar::new(total_gates);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("🦃 [{bar:50.cyan/blue}] {percent:>3}% | {msg} | {elapsed_precise}")
                .unwrap()
                .progress_chars("█░"),
        );
        let start = Instant::now();

        Ok(ProgressBarState {
            inner_state,
            progress_bar: pb,
            start,
            total_gates,
            total_gates_processed: 0,
        })
    }

    fn on_block(&self, state: &mut Self::State, block: &GateBlock<'_>) -> Result<(), Self::Error> {
        self.inner.on_block(&mut state.inner_state, block)?;

        state.total_gates_processed += block.num_gates() as u64;
        state.progress_bar.inc(block.num_gates() as u64);

        Ok(())
    }

    fn on_after_chunk(&self, state: &mut Self::State) -> Result<(), Self::Error> {
        self.inner.on_after_chunk(&mut state.inner_state)?;

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
        state: Self::State,
        output_wire_idxs: &[u64],
    ) -> Result<Self::Output, Self::Error> {
        state.progress_bar.finish();
        self.inner.finish(state.inner_state, output_wire_idxs)
    }

    fn on_abort(&self, state: Self::State) {
        state.progress_bar.finish();
        self.inner.on_abort(state.inner_state);
    }
}

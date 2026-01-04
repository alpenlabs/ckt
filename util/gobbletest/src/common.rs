use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_gobble::{ByteLabel, Label, TranslationMaterial, Ciphertext};
use ckt_runner_types::{CircuitTask, GateBlock};
use indicatif::{ProgressBar, ProgressStyle};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
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

/// Read input bytes from a text file (space-separated or one per line)
/// Example: "0 255 42" or "0\n255\n42"
pub fn read_inputs_bytes(input_file: &str, expected_num_bytes: usize) -> Vec<u8> {
    let mut input_string = String::new();
    let file = File::open(input_file)
        .unwrap_or_else(|_| panic!("Failed to open input file: {}", input_file));
    let mut reader = BufReader::new(file);
    reader.read_to_string(&mut input_string).unwrap();

    let input_string = input_string.trim();
    
    // Parse bytes - support both space-separated and newline-separated
    let bytes: Vec<u8> = input_string
        .split_whitespace()
        .map(|s| {
            s.parse::<u8>()
                .unwrap_or_else(|_| panic!("Invalid byte value: {}", s))
        })
        .collect();

    assert_eq!(
        bytes.len(),
        expected_num_bytes,
        "Input file has {} bytes but expected {}",
        bytes.len(),
        expected_num_bytes
    );

    bytes
}

/// Generate byte labels using RNG (for testing).
/// In practice, these may come from an outer protocol with specific correlations.
pub fn generate_byte_labels(
    num_bytes: usize,
    rng: &mut ChaCha20Rng,
) -> Vec<ByteLabel> {
    let mut byte_labels_vec = Vec::new();
    for _ in 0..num_bytes {
        let mut byte_label_array = [Label::from([0u8; 16]); 256];
        for i in 0..256 {
            let mut label_bytes = [0u8; 16];
            rng.fill_bytes(&mut label_bytes);
            byte_label_array[i] = Label::from(label_bytes);
        }
        byte_labels_vec.push(ByteLabel::new(byte_label_array));
    }
    byte_labels_vec
}

/// Write translation material to a file.
/// Format: Sequential write for each byte_position (0..num_bytes):
///   For each byte_value (0..255):
///     For each bit_position (0..7):
///       Write 16 bytes (ciphertext)
pub fn write_translation_material(
    translation_file: &str,
    translation_material: &[TranslationMaterial],
) {
    let mut writer = BufWriter::new(File::create(translation_file).unwrap());
    for material in translation_material {
        for byte_value in 0..256 {
            for bit_position in 0..8 {
                let ct_bytes: [u8; 16] = material[byte_value][bit_position].into();
                writer
                    .write_all(&ct_bytes)
                    .expect("Failed to write translation material");
            }
        }
    }
    writer
        .flush()
        .expect("Failed to flush translation material");
}

/// Read translation material from a file.
/// Format: Sequential read for each byte_position (0..num_bytes):
///   For each byte_value (0..255):
///     For each bit_position (0..7):
///       Read 16 bytes (ciphertext)
pub fn read_translation_material(
    translation_file: &str,
    num_bytes: usize,
) -> Vec<TranslationMaterial> {
    let mut reader = BufReader::new(File::open(translation_file).unwrap());
    let mut translation_material = Vec::new();

    for _ in 0..num_bytes {
        let mut material = [[Ciphertext::from([0u8; 16]); 8]; 256];
        for byte_value in 0..256 {
            for bit_position in 0..8 {
                let mut ct_bytes = [0u8; 16];
                reader
                    .read_exact(&mut ct_bytes)
                    .expect("Failed to read translation material");
                material[byte_value][bit_position] = Ciphertext::from(ct_bytes);
            }
        }
        translation_material.push(material);
    }
    translation_material
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
    type InitInput = T::InitInput;
    type State = ProgressBarState<T::State>;
    type Output = T::Output;

    fn initialize(
        &self,
        header: &HeaderV5c,
        init_input: Self::InitInput,
    ) -> Result<Self::State, Self::Error> {
        let inner_state = self.inner.initialize(header, init_input)?;

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

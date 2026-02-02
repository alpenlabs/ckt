use bitvec::vec::BitVec;
use ckt_fmtv5_types::v5::c::HeaderV5c;
use ckt_gobble::{ByteLabel, InputTranslationMaterial, Label, OutputTranslationMaterial};
use ckt_runner_types::{CircuitTask, GateBlock};
use indicatif::{ProgressBar, ProgressStyle};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Instant;

/// Read input bits from a text file containing 0s and 1s
pub(crate) fn read_inputs(input_file: &str, expected_num_inputs: usize) -> BitVec {
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

/// Convert bits to bytes (LSB first within each byte)
pub(crate) fn bits_to_bytes(bits: &BitVec, num_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes];
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    bytes
}

/// Generate random byte labels (256 labels per byte position)
pub(crate) fn generate_byte_labels(num_bytes: usize, rng: &mut ChaCha20Rng) -> Vec<ByteLabel> {
    let mut byte_labels = Vec::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        let mut labels = [Label::default(); 256];
        for label in &mut labels {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes);
            *label = Label::from(bytes);
        }
        byte_labels.push(ByteLabel::new(labels));
    }
    byte_labels
}

/// Write translation material to a file
pub(crate) fn write_input_translation_material(
    path: &str,
    materials: &[InputTranslationMaterial],
) {
    let file = File::create(path).expect("Failed to create translation file");
    let mut writer = BufWriter::new(file);

    for material in materials {
        for row in material {
            for ct in row {
                let bytes: [u8; 16] = (*ct).into();
                writer
                    .write_all(&bytes)
                    .expect("Failed to write ciphertext");
            }
        }
    }

    writer.flush().expect("Failed to flush translation file");
}

/// Read translation material from a file
pub(crate) fn read_input_translation_material(
    path: &str,
    num_bytes: usize,
) -> Vec<InputTranslationMaterial> {
    let file = File::open(path).expect("Failed to open translation file");
    let mut reader = BufReader::new(file);

    let mut materials = Vec::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        let mut material = [[ckt_gobble::Ciphertext::default(); 8]; 256];
        for row in &mut material {
            for ct in row {
                let mut bytes = [0u8; 16];
                reader
                    .read_exact(&mut bytes)
                    .expect("Failed to read ciphertext");
                *ct = ckt_gobble::Ciphertext::from(bytes);
            }
        }
        materials.push(material);
    }

    materials
}

/// Write output translation material to a file
pub(crate) fn write_output_translation_material(
    path: &str,
    material: &OutputTranslationMaterial,
) {
    let file = File::create(path).expect("Failed to create output translation file");
    let mut writer = BufWriter::new(file);

    // Write number of outputs first (for reading back)
    let num_outputs = material.len() as u64;
    writer
        .write_all(&num_outputs.to_le_bytes())
        .expect("Failed to write num outputs");

    // Write each 32-byte ciphertext
    for ciphertext in material {
        writer
            .write_all(ciphertext)
            .expect("Failed to write output ciphertext");
    }

    writer
        .flush()
        .expect("Failed to flush output translation file");
}

/// Read output translation material from a file
pub(crate) fn read_output_translation_material(path: &str) -> OutputTranslationMaterial {
    let file = File::open(path).expect("Failed to open output translation file");
    let mut reader = BufReader::new(file);

    // Read number of outputs
    let mut num_bytes = [0u8; 8];
    reader
        .read_exact(&mut num_bytes)
        .expect("Failed to read num outputs");
    let num_outputs = u64::from_le_bytes(num_bytes) as usize;

    // Read each 32-byte ciphertext
    let mut material = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        let mut ciphertext = [0u8; 32];
        reader
            .read_exact(&mut ciphertext)
            .expect("Failed to read output ciphertext");
        material.push(ciphertext);
    }

    material
}

/// Wrapper that adds progress bar reporting to a CircuitTask implementation.
pub(crate) struct ProgressBarTask<T> {
    inner: T,
}

impl<T> ProgressBarTask<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

/// State wrapper that tracks progress bar state alongside the inner task state.
pub(crate) struct ProgressBarState<S> {
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

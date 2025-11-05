//! exec test

use bitvec::vec::BitVec;
use ckt::v5::b::reader::CircuitReaderV5b;
use indicatif::ProgressBar;
use monoio::fs::File;

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5b::open("g16.5b.ckt").unwrap();
    let header = reader.header();
    let mut state = BitVec::<usize>::new();
    state.resize(header.scratch_space as usize, false);
    {
        let file = File::open("inputs.txt").await.unwrap();
        let num_bytes = file.metadata().await.unwrap().len();
        let (res, bytes) = file.read_exact_at(vec![0; num_bytes as usize], 0).await;
        res.unwrap();
        let string = String::from_utf8(bytes).unwrap();
        assert_eq!(string.chars().count(), header.primary_inputs as usize);
        for (char_idx, char) in string.chars().enumerate() {
            let idx = char_idx as usize + 2;
            match char {
                '0' => state.set(idx, false),
                '1' => state.set(idx, true),
                _ => panic!("Invalid input character at pos {}", char_idx),
            }
        }
    };
    let pb = ProgressBar::new(header.and_gates + header.xor_gates);

    while let Some(level) = reader.next_level().await.unwrap() {
        let gates_in_lvl = level.and_gates.len() + level.xor_gates.len();
        for gate in level.and_gates {
            let in1 = resolve_in(&mut state, gate.in1);
            let in2 = resolve_in(&mut state, gate.in2);
            state.set(gate.out as usize, in1 & in2);
        }
        for gate in level.xor_gates {
            let in1 = resolve_in(&mut state, gate.in1);
            let in2 = resolve_in(&mut state, gate.in2);
            state.set(gate.out as usize, in1 ^ in2);
        }
        pb.inc(gates_in_lvl as u64);
    }

    pb.finish_with_message("Finished");

    let out = state[reader.outputs()[0] as usize];
    println!("Output: {}", out);
}

fn resolve_in(state: &mut BitVec, idx: u32) -> bool {
    match idx {
        0 => false,
        1 => true,
        idx => state[idx as usize],
    }
}

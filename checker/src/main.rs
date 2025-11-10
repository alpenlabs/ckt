//! asdas

use ckt::v5::{a::reader::CircuitReaderV5a, b::reader::CircuitReaderV5b};
use indicatif::ProgressBar;
// use roaring::{RoaringBitmap, RoaringTreemap};

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/Users/user/g16.ckt").unwrap();

    dbg!(reader.header().total_gates());

    let output = reader.outputs()[0];
    dbg!(reader.outputs());

    let mut max_creds = 0;

    let pb = ProgressBar::new(reader.header().total_gates());
    loop {
        let block = match reader.next_block_soa().await.unwrap() {
            Some(block) => block,
            None => break,
        };
        for i in 0..block.gates_in_block {
            if block.out[i] == output {
                println!(
                    "{:?} {} {} -> {}",
                    block.gate_types[i], block.in1[i], block.in2[i], block.out[i]
                );
            }
        }
        pb.inc(block.gates_in_block as u64);
    }
    pb.finish();

    // let mut reader = CircuitReaderV5b::open("/Users/user/g16.5b.ckt").unwrap();

    // dbg!(reader.header().total_gates());

    // let output = reader.outputs()[0];

    // dbg!(reader.outputs());

    // let mut max_creds = 0;

    // let pb = ProgressBar::new(reader.header().total_gates());
    // loop {
    //     let block = match reader.next_level().await.unwrap() {
    //         Some(block) => block,
    //         None => break,
    //     };

    //     let total = block.and_gates.len() + block.xor_gates.len();

    //     for gate in block.and_gates {
    //         if gate.out == output {
    //             println!("AND {} {} -> {}", gate.in1, gate.in2, gate.out);
    //         }
    //     }

    //     for gate in block.xor_gates {
    //         if gate.out == output {
    //             println!("XOR {} {} -> {}", gate.in1, gate.in2, gate.out);
    //         }
    //     }
    //     pb.inc(total as u64);
    // }
    // pb.finish();
}

//! asdas

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use ckt::v5::a::reader::CircuitReaderV5a;
use indicatif::ProgressBar;
use roaring::{RoaringBitmap, RoaringTreemap};

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/home/user/dev/alpen/g16/g16/g16.ckt").unwrap();
    let now = Instant::now();
    let mut gates = 0;
    let mut seen_outputs = RoaringTreemap::new();
    let mut max_seen = 0;
    let pb = ProgressBar::new(reader.header().total_gates());
    loop {
        let block = match reader.next_block_soa().await.unwrap() {
            Some(block) => block,
            None => break,
        };
        gates += block.gates_in_block;
        pb.inc(block.gates_in_block as u64);
        for i in 0..block.gates_in_block {
            if seen_outputs.contains(block.out[i]) {
                println!("Duplicate output found: {}", block.out[i]);
            }
            seen_outputs.insert(block.out[i]);
            max_seen = max_seen.max(block.out[i]);
        }
    }
    let gates_per_second = gates as f64 / now.elapsed().as_millis() as f64 * 1000.0;
    println!("Gates read: {}", gates);
    println!("Gates per second: {:.2}", gates_per_second);
    println!("Max seen output: {}", max_seen);
}

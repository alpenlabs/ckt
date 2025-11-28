//! asdas

use ckt_fmtv5_types::v5::a::reader::CircuitReaderV5a;
use indicatif::ProgressBar;
// use roaring::{RoaringBitmap, RoaringTreemap};

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/Users/user/g16.ckt").unwrap();

    const START: u64 = 0;
    const NUM: usize = 100000;
    let range = START..START + NUM as u64;
    let mut claimed: [u32; NUM] = [0; NUM];
    let mut actual: [u32; NUM] = [0; NUM];

    let mut max_creds = 0;

    let pb = ProgressBar::new(reader.header().total_gates());
    loop {
        let block = match reader.next_block_soa().await.unwrap() {
            Some(block) => block,
            None => break,
        };
        for i in 0..block.gates_in_block {
            if range.contains(&block.out[i]) {
                let idx = block.out[i] as usize % NUM;
                claimed[idx] = block.credits[i];
            }

            if range.contains(&block.in1[i]) {
                let idx = block.in1[i] as usize % NUM;
                actual[idx] += 1;
            }

            if range.contains(&block.in2[i]) {
                let idx = block.in2[i] as usize % NUM;
                actual[idx] += 1;
            }
            max_creds = max_creds.max(block.credits[i]);
        }
        pb.inc(block.gates_in_block as u64);
    }
    pb.finish();

    dbg!(max_creds);

    let mut mismatches = Vec::new();
    for i in 0..NUM {
        if claimed[i] != actual[i] {
            let wire_id = START + i as u64;
            mismatches.push((wire_id, claimed[i], actual[i]));
        }
    }

    if mismatches.is_empty() {
        println!("✓ All gates match! Claimed credits equal actual usage.");
    } else {
        println!("\n✗ Found {} mismatches:\n", mismatches.len());
        println!(
            "{:<12} {:<12} {:<12} {:<12}",
            "Wire ID", "Claimed", "Actual", "Difference"
        );
        println!("{}", "-".repeat(52));
        for (wire_id, claimed_val, actual_val) in &mismatches {
            let diff = *actual_val as i64 - *claimed_val as i64;
            println!(
                "{:<12} {:<12} {:<12} {:+<12}",
                wire_id, claimed_val, actual_val, diff
            );
        }
        println!("\nTotal mismatches: {}/{}", mismatches.len(), NUM);
    }
}

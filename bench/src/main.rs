use std::time::{Duration, Instant};

use ckt::v5::a::reader::CircuitReaderV5a;

#[monoio::main]
async fn main() {
    let mut reader = CircuitReaderV5a::open("/home/user/dev/alpen/g16/g16/g16.ckt").unwrap();
    let now = Instant::now();
    let mut gates = 0;
    let dur = Duration::from_secs(10);
    loop {
        let block = reader.next_block_soa().await.unwrap().unwrap();
        gates += block.gates_in_block;
        if now.elapsed() > dur {
            break;
        }
    }
    let gates_per_second = gates as f64 / dur.as_millis() as f64 * 1000.0;
    println!("Gates read: {}", gates);
    println!("Gates per second: {:.2}", gates_per_second);
}

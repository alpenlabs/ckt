//! asdas

use blake3;
use std::time::Instant;

use ckt::{
    GateType,
    v5::c::{Block, GATES_PER_BLOCK, reader::ReaderV5c},
};
use ckt_engine::{aarch64::GarblingInstance, engine::run_double_buffer_all_workers_identical};
use cynosure::hints::{cold_and_empty, prefetch_read_data, unlikely};
use indicatif::ProgressBar;
// use roaring::{RoaringBitmap, RoaringTreemap};

#[monoio::main]
async fn main() {
    run_double_buffer_all_workers_identical("/Users/user/g16.5c.ckt", 1)
        .await
        .unwrap();
}

//! asdas

use blake3;
use std::time::Instant;

use ckt::{
    GateType,
    v5::c::{Block, GATES_PER_BLOCK, reader::ReaderV5c},
};
use ckt_engine::{aarch64::GarblingInstance, engine::master_thread};
use cynosure::hints::{cold_and_empty, prefetch_read_data, unlikely};
use indicatif::ProgressBar;
// use roaring::{RoaringBitmap, RoaringTreemap};

#[monoio::main]
async fn main() {
    master_thread().await;
}

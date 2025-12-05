use ckt_fmtv5_types::v5::c::get_block_num_gates;
use ckt_runner_types::{CircuitReader, CircuitTask, GateBlock};

/// Processes a circuit task by reading blocks from a [`CircuitReader`].
pub async fn process_task<T: CircuitTask, R: CircuitReader>(
    task_info: &T,
    init_input: T::InitInput,
    reader: &mut R,
) -> anyhow::Result<T::Output> {
    // Initialize the task and run through the circuit.
    let mut task_state = task_info.initialize(reader.header(), init_input)?;
    if let Err(e) = process_task_inner(task_info, &mut task_state, reader).await {
        task_info.on_abort(task_state);
        return Err(e);
    }

    // Produce the output using the output indexes.
    let output_wires = reader
        .outputs()
        .iter()
        .map(|w| *w as u64)
        .collect::<Vec<_>>();
    let task_output = task_info.finish(task_state, &output_wires)?;

    Ok(task_output)
}

async fn process_task_inner<T: CircuitTask, R: CircuitReader>(
    task_info: &T,
    task_state: &mut T::State,
    reader: &mut R,
) -> anyhow::Result<()> {
    let total_gates = reader.header().total_gates();

    // Iterate over every chunk, keeping track of where we are.
    let mut cur_block_idx = 0;
    while let Some(chunk) = reader.next_chunk().await? {
        // Iterate over each block in the chunk and pass it to the task to do something with it.
        for block in chunk.blocks_iter() {
            let gates_in_block = get_block_num_gates(total_gates, cur_block_idx);
            cur_block_idx += 1;

            let safe_block = GateBlock::new(block, gates_in_block);
            task_info.on_block(task_state, &safe_block)?;
        }

        task_info.on_after_chunk(task_state)?;
    }

    Ok(())
}

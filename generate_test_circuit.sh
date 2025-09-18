#!/bin/bash

# Generate test Bristol circuit
# Usage: ./generate_test_circuit.sh [num_gates] [primary_inputs] [output_file]

set -e

# Default values
NUM_GATES=${1:-1000}
PRIMARY_INPUTS=${2:-100}
OUTPUT_FILE=${3:-""}

# Validate inputs
if [ "$NUM_GATES" -lt 1 ]; then
    echo "Error: Number of gates must be at least 1" >&2
    exit 1
fi

if [ "$PRIMARY_INPUTS" -lt 2 ]; then
    echo "Error: Need at least 2 primary inputs" >&2
    exit 1
fi

# Function to generate circuit
generate_circuit() {
    local next_wire=$PRIMARY_INPUTS
    local available_wires=()

    # Initialize available wires with primary inputs
    for ((i=0; i<PRIMARY_INPUTS; i++)); do
        available_wires+=($i)
    done

    # Generate gates
    for ((gate=0; gate<NUM_GATES; gate++)); do
        # Randomly select two input wires from available wires
        local num_available=${#available_wires[@]}

        # Make sure we have at least 2 wires available
        if [ "$num_available" -lt 2 ]; then
            # If not enough wires, reuse primary inputs
            local in1=$((RANDOM % PRIMARY_INPUTS))
            local in2=$((RANDOM % PRIMARY_INPUTS))
            while [ "$in1" -eq "$in2" ]; do
                in2=$((RANDOM % PRIMARY_INPUTS))
            done
        else
            # Select two different indices
            local idx1=$((RANDOM % num_available))
            local idx2=$((RANDOM % num_available))
            while [ "$idx1" -eq "$idx2" ]; do
                idx2=$((RANDOM % num_available))
            done

            local in1=${available_wires[$idx1]}
            local in2=${available_wires[$idx2]}
        fi

        # Output wire
        local out=$next_wire
        ((next_wire++))

        # Randomly choose gate type (50/50 XOR/AND)
        local gate_type
        if [ $((RANDOM % 2)) -eq 0 ]; then
            gate_type="XOR"
        else
            gate_type="AND"
        fi

        # Output gate
        echo "2 1 $in1 $in2 $out $gate_type"

        # Add output wire to available wires
        available_wires+=($out)

        # Keep available wires list from growing too large (memory optimization)
        # Keep only the last 1000 wires available
        if [ "${#available_wires[@]}" -gt 1000 ]; then
            available_wires=("${available_wires[@]: -1000}")
        fi
    done
}

# Output to file or stdout
if [ -n "$OUTPUT_FILE" ]; then
    echo "Generating circuit with $NUM_GATES gates and $PRIMARY_INPUTS primary inputs to $OUTPUT_FILE..." >&2
    generate_circuit > "$OUTPUT_FILE"
    echo "Done! Generated $NUM_GATES gates." >&2
else
    generate_circuit
fi

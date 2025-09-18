use ckt::{
    GateType,
    v1::{
        CompactGate, GateBatch,
        reader::{CircuitReader, read_header, read_header_seekable},
        writer::CircuitWriter,
    },
};
use std::io::Cursor;

#[test]
fn test_compact_gate_serialization() {
    let gate = CompactGate {
        input1: 0x12345678,
        input2: 0x9ABCDEF0,
        output: 0x11223344,
    };

    let bytes = gate.to_bytes();
    let restored = CompactGate::from_bytes(&bytes);

    assert_eq!(gate.input1, restored.input1);
    assert_eq!(gate.input2, restored.input2);
    assert_eq!(gate.output, restored.output);
}

#[test]
fn test_gate_batch_operations() {
    let mut batch = GateBatch::new();

    // Set some gates
    let gate1 = CompactGate {
        input1: 10,
        input2: 20,
        output: 30,
    };
    let gate2 = CompactGate {
        input1: 40,
        input2: 50,
        output: 60,
    };

    batch.set_gate(0, gate1, GateType::XOR); // XOR
    batch.set_gate(1, gate2, GateType::AND); // AND

    // Test retrieval
    let (retrieved_gate1, gate_type1) = batch.get_gate(0);
    assert_eq!(retrieved_gate1.input1, 10);
    assert_eq!(retrieved_gate1.input2, 20);
    assert_eq!(retrieved_gate1.output, 30);
    assert_eq!(gate_type1, GateType::XOR);

    let (retrieved_gate2, gate_type2) = batch.get_gate(1);
    assert_eq!(retrieved_gate2.input1, 40);
    assert_eq!(retrieved_gate2.input2, 50);
    assert_eq!(retrieved_gate2.output, 60);
    assert_eq!(gate_type2, GateType::AND);
}

#[test]
fn test_batch_serialization() {
    let mut batch = GateBatch::new();

    batch.set_gate(
        0,
        CompactGate {
            input1: 100,
            input2: 200,
            output: 300,
        },
        GateType::XOR,
    );
    batch.set_gate(
        1,
        CompactGate {
            input1: 400,
            input2: 500,
            output: 600,
        },
        GateType::AND,
    );

    let bytes = batch.to_bytes();
    assert_eq!(bytes.len(), GateBatch::SIZE);

    let restored = GateBatch::from_bytes(&bytes);

    let (gate0, gate_type0) = restored.get_gate(0);
    assert_eq!(gate0.input1, 100);
    assert_eq!(gate0.input2, 200);
    assert_eq!(gate0.output, 300);
    assert_eq!(gate_type0, GateType::XOR);

    let (gate1, gate_type1) = restored.get_gate(1);
    assert_eq!(gate1.input1, 400);
    assert_eq!(gate1.input2, 500);
    assert_eq!(gate1.output, 600);
    assert_eq!(gate_type1, GateType::AND);
}

#[test]
fn test_generic_read_write_with_memory_buffer() {
    // Create an in-memory buffer for writing
    let buffer = Cursor::new(Vec::new());

    // Write some gates using CircuitWriter
    let buffer = {
        let mut writer = CircuitWriter::new(buffer).unwrap();

        // Write some gates
        writer
            .write_gate(CompactGate::new(100, 200, 300), GateType::XOR)
            .unwrap();
        writer
            .write_gate(CompactGate::new(400, 500, 600), GateType::AND)
            .unwrap();
        writer
            .write_gate(CompactGate::new(700, 800, 900), GateType::XOR)
            .unwrap();
        writer
            .write_gate(CompactGate::new(1000, 1100, 1200), GateType::AND)
            .unwrap();

        // Finish writing and get the buffer back
        let (buffer, total_written) = writer.finish().unwrap();
        assert_eq!(total_written, 4);

        buffer
    };

    // Read back using CircuitReader with a cursor
    {
        let mut cursor = buffer.clone();
        cursor.set_position(0);

        // First, check the header
        let header = read_header(&mut cursor).unwrap();
        assert_eq!(header.xor_gates, 2);
        assert_eq!(header.and_gates, 2);

        // Reset and create reader
        cursor.set_position(0);
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(cursor, buffer_len).unwrap();

        let (batch, count) = reader.next_batch_ref().unwrap().unwrap();
        assert_eq!(count, 4);

        // Read and verify gates
        let (gate1, type1) = batch.get_gate(0);
        assert_eq!(gate1.input1, 100);
        assert_eq!(gate1.input2, 200);
        assert_eq!(gate1.output, 300);
        assert_eq!(type1, GateType::XOR);

        let (gate2, type2) = batch.get_gate(1);
        assert_eq!(gate2.input1, 400);
        assert_eq!(gate2.input2, 500);
        assert_eq!(gate2.output, 600);
        assert_eq!(type2, GateType::AND);

        let (gate3, type3) = batch.get_gate(2);
        assert_eq!(gate3.input1, 700);
        assert_eq!(gate3.input2, 800);
        assert_eq!(gate3.output, 900);
        assert_eq!(type3, GateType::XOR);

        let (gate4, type4) = batch.get_gate(3);
        assert_eq!(gate4.input1, 1000);
        assert_eq!(gate4.input2, 1100);
        assert_eq!(gate4.output, 1200);
        assert_eq!(type4, GateType::AND);

        // Should be at end (reader knows from header there are only 4 gates)
        assert_eq!(reader.gates_read(), 4);
    }
}

#[test]
fn test_batch_edge_cases() {
    let mut batch = GateBatch::new();

    // Test all 8 gates in a batch
    for i in 0..8 {
        batch.set_gate(
            i,
            CompactGate {
                input1: i as u32 * 10,
                input2: i as u32 * 10 + 1,
                output: i as u32 * 10 + 2,
            },
            if i % 2 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            },
        );
    }

    // Verify all gates
    for i in 0..8 {
        let (gate, gate_type) = batch.get_gate(i);
        assert_eq!(gate.input1, i as u32 * 10);
        assert_eq!(gate.input2, i as u32 * 10 + 1);
        assert_eq!(gate.output, i as u32 * 10 + 2);
        assert_eq!(
            gate_type,
            if i % 2 == 0 {
                GateType::XOR
            } else {
                GateType::AND
            }
        );
    }

    // Test gate count
    assert_eq!(batch.gate_count(), 8);
}

#[test]
fn test_gate_type_packing() {
    let mut batch = GateBatch::new();

    // Set specific pattern of gate types
    batch.set_gate(
        0,
        CompactGate {
            input1: 0,
            input2: 0,
            output: 0,
        },
        GateType::XOR,
    );
    batch.set_gate(
        1,
        CompactGate {
            input1: 1,
            input2: 1,
            output: 1,
        },
        GateType::AND,
    );
    batch.set_gate(
        2,
        CompactGate {
            input1: 2,
            input2: 2,
            output: 2,
        },
        GateType::AND,
    );
    batch.set_gate(
        3,
        CompactGate {
            input1: 3,
            input2: 3,
            output: 3,
        },
        GateType::XOR,
    );

    // Check the packed byte value
    // Bit pattern: ...00110 (LSB first, 0=XOR, 1=AND)
    assert_eq!(batch.gate_types & 0x0F, 0b0110);
}

#[test]
fn test_partial_batch_handling() {
    use std::io::Cursor;

    // Create a circuit with 10 gates (1 full batch + 2 gates)
    let mut buffer = Cursor::new(Vec::new());
    {
        let mut writer = CircuitWriter::new(buffer).unwrap();

        for i in 0..10 {
            writer
                .write_gate(
                    CompactGate::new(i * 3, i * 3 + 1, i * 3 + 2),
                    if i % 2 == 0 {
                        GateType::XOR
                    } else {
                        GateType::AND
                    },
                )
                .unwrap();
        }

        let (buf, total) = writer.finish().unwrap();
        assert_eq!(total, 10);
        buffer = buf;
    }

    // Read back and verify
    {
        buffer.set_position(0);
        let header = read_header(&mut buffer).unwrap();
        assert_eq!(header.xor_gates, 5);
        assert_eq!(header.and_gates, 5);

        buffer.set_position(0);
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(buffer, buffer_len).unwrap();

        let mut count = 0;
        while let Some((batch, gates_in_batch)) = reader.next_batch().unwrap() {
            for i in 0..gates_in_batch {
                let (gate, _) = batch.get_gate(i);
                assert_eq!(gate.input1, count * 3);
                assert_eq!(gate.input2, count * 3 + 1);
                assert_eq!(gate.output, count * 3 + 2);
                count += 1;
            }
        }
        // Should read exactly 10 gates (as specified in header)
        assert_eq!(count, 10);
    }
}

#[test]
fn test_empty_circuit() {
    use std::io::Cursor;

    let mut buffer = Cursor::new(Vec::new());
    {
        let writer = CircuitWriter::new(buffer).unwrap();
        let (buf, total) = writer.finish().unwrap();
        assert_eq!(total, 0);
        buffer = buf;
    }

    {
        buffer.set_position(0);
        let header = read_header(&mut buffer).unwrap();
        assert_eq!(header.xor_gates, 0);
        assert_eq!(header.and_gates, 0);

        buffer.set_position(0);
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(buffer, buffer_len).unwrap();
        assert!(reader.next_batch().unwrap().is_none());
    }
}

#[test]
fn test_large_circuit_streaming() {
    use std::io::Cursor;

    const GATE_COUNT: u32 = 100_000;
    let mut buffer = Cursor::new(Vec::new());

    // Write a large circuit
    {
        let mut writer = CircuitWriter::new(buffer).unwrap();

        for i in 0..GATE_COUNT {
            writer
                .write_gate(CompactGate::new(i, i + 1, i + 2), GateType::XOR)
                .unwrap();
        }

        let (buf, total) = writer.finish().unwrap();
        assert_eq!(total, GATE_COUNT as usize);
        buffer = buf;
    }

    // Read back with streaming
    {
        buffer.set_position(0);
        let header = read_header(&mut buffer).unwrap();
        assert_eq!(header.xor_gates, GATE_COUNT);
        assert_eq!(header.and_gates, 0);

        buffer.set_position(0);
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(buffer, buffer_len).unwrap();

        let mut count = 0;
        while let Some((batch, gates_in_batch)) = reader.next_batch().unwrap() {
            for i in 0..gates_in_batch {
                let (gate, gate_type) = batch.get_gate(i);
                assert_eq!(gate.input1, count);
                assert_eq!(gate.input2, count + 1);
                assert_eq!(gate.output, count + 2);
                assert_eq!(gate_type, GateType::XOR);
                count += 1;
            }
        }
        assert_eq!(count, GATE_COUNT);
    }
}

#[test]
fn test_gate_type_consistency() {
    // Verify that XOR is 0 and AND is 1 in the bit representation
    let mut batch = GateBatch::new();

    // Set first gate as XOR
    batch.set_gate(
        0,
        CompactGate {
            input1: 0,
            input2: 0,
            output: 0,
        },
        GateType::XOR,
    );
    assert_eq!(batch.gate_types & 1, 0);

    // Set first gate as AND
    batch.set_gate(
        0,
        CompactGate {
            input1: 0,
            input2: 0,
            output: 0,
        },
        GateType::AND,
    );
    assert_eq!(batch.gate_types & 1, 1);
}

#[test]
#[should_panic(expected = "Gate index must be 0-7")]
fn test_batch_index_out_of_bounds() {
    let mut batch = GateBatch::new();
    batch.set_gate(
        8,
        CompactGate {
            input1: 0,
            input2: 0,
            output: 0,
        },
        GateType::XOR,
    );
}

#[test]
fn test_batch_byte_representation() {
    let mut batch = GateBatch::new();

    // Create a specific pattern
    batch.set_gate(
        0,
        CompactGate {
            input1: 0x01020304,
            input2: 0x05060708,
            output: 0x090A0B0C,
        },
        GateType::AND,
    );

    let bytes = batch.to_bytes();

    // Check first gate bytes (little endian)
    assert_eq!(bytes[0..4], [0x04, 0x03, 0x02, 0x01]); // input1
    assert_eq!(bytes[4..8], [0x08, 0x07, 0x06, 0x05]); // input2
    assert_eq!(bytes[8..12], [0x0C, 0x0B, 0x0A, 0x09]); // output

    // Check gate types byte
    assert_eq!(bytes[96], 0x01); // First bit set for AND gate
}

#[test]
fn test_reader_with_exact_buffer_boundaries() {
    use std::io::Cursor;

    // Create a circuit with exactly BATCHES_PER_READ * 8 gates
    // This tests the buffer refill logic
    const BATCHES: u32 = 20000;
    const GATE_COUNT: u32 = BATCHES * 8;

    let mut buffer = Cursor::new(Vec::new());
    {
        let mut writer = CircuitWriter::new(buffer).unwrap();

        for i in 0..GATE_COUNT {
            writer
                .write_gate(CompactGate::new(i, i, i), GateType::XOR)
                .unwrap();
        }

        let (buf, _) = writer.finish().unwrap();
        buffer = buf;
    }

    {
        buffer.set_position(0);
        let header = read_header(&mut buffer).unwrap();
        assert_eq!(header.xor_gates, GATE_COUNT);
        assert_eq!(header.and_gates, 0);

        buffer.set_position(0);
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(buffer, buffer_len).unwrap();

        let mut count = 0;
        while let Some((_, gates_in_batch)) = reader.next_batch().unwrap() {
            count += gates_in_batch;
        }
        assert_eq!(count, GATE_COUNT as usize);
    }
}

#[test]
fn test_seekable_header_reading() {
    use std::io::Cursor;

    // Create a circuit with known gate count
    const EXPECTED_GATES: u32 = 42;
    let mut buffer = Cursor::new(Vec::new());

    {
        let mut writer = CircuitWriter::new(buffer).unwrap();

        for i in 0..EXPECTED_GATES {
            writer
                .write_gate(CompactGate::new(i * 2, i * 2 + 1, i * 3), GateType::XOR)
                .unwrap();
        }

        let (buf, total) = writer.finish().unwrap();
        assert_eq!(total, EXPECTED_GATES as usize);
        buffer = buf;
    }

    // Test reading header from seekable stream
    {
        // Cursor is at end after finish(), seek to beginning
        buffer.set_position(0);

        let header = read_header_seekable(&mut buffer).unwrap();
        // We write 42 gates, which becomes 48 (6 full batches)
        // But header tracks actual gates written
        assert_eq!(header.xor_gates, EXPECTED_GATES);
        assert_eq!(header.and_gates, 0);

        // Verify cursor was preserved at start position
        assert_eq!(buffer.position(), 0);

        // Now read the circuit normally
        let buffer_len = buffer.get_ref().len();
        let mut reader = CircuitReader::new(buffer, buffer_len).unwrap();
        let mut count = 0;
        while let Some((batch, gates_in_batch)) = reader.next_batch().unwrap() {
            for i in 0..gates_in_batch {
                let (gate, _) = batch.get_gate(i);
                // Verify expected gates
                assert_eq!(gate.input1, count * 2);
                assert_eq!(gate.input2, count * 2 + 1);
                assert_eq!(gate.output, count * 3);
                count += 1;
            }
        }
        // Should read exactly 42 gates (as specified in header)
        assert_eq!(count, EXPECTED_GATES);
    }
}

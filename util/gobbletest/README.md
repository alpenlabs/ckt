# Gobbletest

A testing utility for garbled circuit generation, evaluation, and end-to-end verification.

## Overview

`gobbletest` provides two main modes for testing garbled circuits:

1. **Garble mode**: Tests circuit garbling in isolation
2. **E2E mode**: Runs complete end-to-end tests (exec → garble → eval)

## Building

```bash
cd util/gobbletest
cargo build --release
```

The binary will be located at `../../target/release/gobbletest`.

```bash
cd ../../target/release
```

## Usage

### Garble Mode

Tests the garbling of a circuit and outputs the garbler's output labels.

```bash
./gobbletest garble <circuit>
```

**Arguments:**
- `<circuit>`: Path to the circuit file

**Example:**
```bash
./gobbletest garble my_circuit.ckt
```

### E2E Mode

Runs a complete end-to-end test that:
1. Executes the circuit in cleartext to get expected outputs
2. Garbles the circuit
3. Evaluates the garbled circuit
4. Verifies that evaluator outputs match cleartext execution
5. Verifies output label consistency

```bash
./gobbletest e2e <circuit> <inputs> [garbled_circuit_path]
```

**Arguments:**
- `<circuit>`: Path to the circuit file
- `<inputs>`: Path to the input file
- `[garbled_circuit_path]` (optional): Path where the garbled circuit binary should be saved
  - If not provided, defaults to `gc.bin` in the current directory
  - Useful for offloading large garbled circuits to external storage (e.g., hard drive)

**Examples:**

Basic usage (saves garbled circuit to `gc.bin`):
```bash
./gobbletest e2e my_circuit.ckt inputs.txt
```

Custom garbled circuit location:
```bash
./gobbletest e2e my_circuit.ckt inputs.txt /mnt/external/garbled.bin
```

Save to a specific directory:
```bash
./gobbletest e2e my_circuit.ckt inputs.txt /tmp/my_garbled_circuit.bin
```

## E2E Test Output

The e2e mode provides detailed output for each step:

```
🦃 Running end-to-end test: exec → garble → eval

📊 Step 1: Executing circuit in cleartext...
[cleartext execution output]

🔒 Step 2: Garbling circuit...
[garbling output]

🔓 Step 3: Evaluating garbled circuit...
[evaluation output]

✅ Step 4: Verifying correctness...

✓ Evaluator outputs match cleartext execution
✓ All output labels are consistent

🎉 All tests passed!
```

## Exit Codes

- `0`: All tests passed
- `1`: Test failure or invalid arguments

## Notes

- All random number generation uses a fixed seed (`[0u8; 32]`) for reproducibility
- The garbled circuit binary can be quite large for complex circuits, hence the option to specify a custom storage location
- For very large circuits, consider using a path on a drive with sufficient space

## Cross-Architecture Testing with Rosetta 2

On ARM Macs with Rosetta 2 installed, you can test the x86_64 implementation to verify it compiles and runs correctly.

**Install the x86_64 target:**
```bash
rustup target add x86_64-apple-darwin
```

**Build for x86_64:**
```bash
cd util/gobbletest
cargo build --release --target x86_64-apple-darwin
```

The binary will be located at `../../target/x86_64-apple-darwin/release/gobbletest`.

**Run tests:**
```bash
# From project root
./target/x86_64-apple-darwin/release/gobbletest garble my_circuit.ckt
./target/x86_64-apple-darwin/release/gobbletest e2e my_circuit.ckt inputs.txt
```

Rosetta 2 will automatically emulate the x86_64 binary. Performance will be slower than native ARM execution, but this allows verification that the x86_64 implementation works correctly on Intel hardware.


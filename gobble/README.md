# Gobble

A high-performance Rust library for privacy-free garbled circuit generation, evaluation, and execution, designed to be compatible with CKT circuit format.

## Overview

`gobble` implements efficient garbled circuit operations using architecture-specific SIMD instructions. It provides three fundamental operations:

1. **Garbling**: Transform a boolean circuit into a garbled circuit, consisting of 1 ciphertext per AND gate in the circuit 
2. **Evaluation**: Evaluate a garbled circuit using input labels and values to obtain output labels
3. **Execution**: Execute a circuit in cleartext for testing and verification

## Architecture

The library uses a trait-based architecture to support multiple CPU architectures. The `x86_64` implementation uses AES-NI instructions for hardware-accelerated AES encryption, while the `aarch64` implementation uses ARM NEON crypto extensions. The `Engine` type alias automatically selects the appropriate implementation for your platform at compile time.

## Features

### Cryptographic Primitives

- **Privacy-Free Half-Gate Garbling**: Implements the Zahur-Rosulek-Evans half-gate optimization, which reduces the size of garbled AND gates to just 1 ciphertexts in the privacy-free setting (compared to 4 in the classical Yao approach) and XOR gates are free
- **Fixed-Key AES**: Uses 2 fixed key AES calls to implement a tweakble circular correlation robust (TCCR) hash function for performance, which is standard practice in garbled circuit implementations and is proved secure in the ideal permutation model

### Performance Optimizations

- Architecture-specific SIMD instructions provide efficient 128-bit operations for wire labels and ciphertexts
- Minimal allocations through pre-allocated scratch space that matches the circuit's live wire requirements
- Efficient wire label storage using direct memory addressing into the scratch space

## Core Traits

### `GobbleEngine`

The main entry point that creates garbling, evaluation, and execution instances. It provides factory methods for instantiating the three types of circuit instances with their respective configurations.

### `GarblingInstance`

Handles the generation of garbled circuits. It accepts XOR and AND gates by feeding them their input and output wire addresses. XOR gates are free (no ciphertext), while AND gates produce a single ciphertext that is transmitted to the evaluator. The instance also provides methods to extract selected labels for specific wires based on their boolean values. This is used for encoding input labels, later used for evaluation in an authenticated manner. 

### `EvaluationInstance`

Handles the evaluation of garbled circuits using input labels and cleartext boolean values (privacy-free). It processes XOR and AND gates using only the wire labels. For AND gates, it uses the provided ciphertext and the point-and-permute bit to determine which output label to compute. The instance tracks both labels and their corresponding semantic boolean values for verification purposes.

### `ExecutionInstance`

Executes circuits in cleartext using actual boolean values. This is primarily used for testing and verification, allowing comparison between garbled circuit evaluation results and plaintext execution results.

## Memory Model

The library uses a `scratch_space` memory model where each circuit specifies a maximum number of live wires that can exist simultaneously. Wire identifiers are direct indices into the scratch space array, enabling constant-time lookups. Wires `0` and `1` are reserved for constants, and primary inputs start at wire `2`. The circuit compiler ensures efficient wire reuse to minimize memory footprint. This design provides both cache-friendly access patterns and minimal memory usage by storing only live wires.

## Configuration Types

The library defines three configuration structures:

**`GarblingInstanceConfig`** specifies the `scratch_space` size, the global `delta` offset (which must remain secret from the evaluator), and the false labels for primary inputs. The true labels are computed by XORing the false labels with `delta`.

**`EvaluationInstanceConfig`** specifies the `scratch_space` size and the selected labels for primary inputs along with their semantic boolean values for tracking purposes.

**`ExecutionInstanceConfig`** specifies the `scratch_space` size and the input boolean values for cleartext execution.

## Benchmarking

The crate includes a comprehensive benchmark suite using `criterion`. Benchmarks cover individual XOR and AND gate operations, mixed gate sequences, and low-level primitive operations. 

## Testing

The test suite validates AES encryption against reference implementations from the `aes` crate, ensures correctness of garbling and evaluation operations, and verifies proper label encoding and decoding. All cryptographic operations follow standard garbled circuit constructions documented in academic literature.

## Safety

This crate uses unsafe code for SIMD intrinsics and type transmutation between architecture-specific SIMD types and byte arrays.

## Security Considerations

**Delta Secrecy**: The garbler must keep the `delta` value completely secret from the evaluator. If the evaluator learns `delta`, they can compute both labels for any wire and thus break authenticity.

**Single Use**: Garbled circuits are inherently single-use constructions. Reusing a garbled circuit with different inputs completely breaks security as it reveals the global offset `delta`.

## Integration

The `gobble` crate is designed to integrate with the broader circuit ecosystem. It works with the `ckt` parent crate for circuit format.

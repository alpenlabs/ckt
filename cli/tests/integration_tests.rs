use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, tempdir};

/// Helper to create a test Bristol file
fn create_bristol_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

/// Helper to get the ckt binary
fn ckt_cmd() -> Command {
    Command::cargo_bin("ckt").unwrap()
}

#[test]
fn test_help_command() {
    ckt_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Circuit format converter"));
}

#[test]
fn test_version_command() {
    ckt_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ckt"));
}

#[test]
fn test_convert_basic() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let output_path = output_dir.path().join("output.ckt");

    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&output_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Converting"))
        .stdout(predicate::str::contains("Total gates: 3"));

    // Verify output file exists
    assert!(output_path.exists());

    // Verify output file has reasonable size
    let ckt_size = fs::metadata(&output_path).unwrap().len();
    assert!(ckt_size > 0);
}

#[test]
fn test_convert_with_compression_level() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let output_path = output_dir.path().join("output.ckt");

    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&output_path)
        .arg("-l")
        .arg("22") // Maximum compression
        .assert()
        .success();

    assert!(output_path.exists());
}

#[test]
fn test_verify_bristol_file() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 2 3 4 AND\n2 1 4 5 6 XOR\n";
    let bristol_file = create_bristol_file(bristol_content);

    ckt_cmd()
        .arg("verify")
        .arg(bristol_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total gates: 3"))
        .stdout(predicate::str::contains("XOR gates: 2"))
        .stdout(predicate::str::contains("AND gates: 1"));
}

#[test]
fn test_verify_bristol_file_detailed() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 2 3 4 AND\n";
    let bristol_file = create_bristol_file(bristol_content);

    ckt_cmd()
        .arg("verify")
        .arg(bristol_file.path())
        .arg("--detailed")
        .assert()
        .success()
        .stdout(predicate::str::contains("Detailed Statistics"))
        .stdout(predicate::str::contains("Gate type entropy"));
}

#[test]
fn test_verify_ckt_file() {
    // First create a CKT file
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("test.ckt");

    // Convert to CKT
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Verify CKT file
    ckt_cmd()
        .arg("verify")
        .arg(&ckt_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Total gates: 2"))
        .stdout(predicate::str::contains("XOR gates: 1"))
        .stdout(predicate::str::contains("AND gates: 1"));
}

#[test]
fn test_info_command() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file = create_bristol_file(bristol_content);

    ckt_cmd()
        .arg("info")
        .arg(bristol_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Format: Bristol"))
        .stdout(predicate::str::contains("Size:"));
}

#[test]
fn test_info_ckt_file() {
    // First create a CKT file
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("test.ckt");

    // Convert to CKT
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Get info
    ckt_cmd()
        .arg("info")
        .arg(&ckt_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Format: CKT"))
        .stdout(predicate::str::contains("Gates: 2"))
        .stdout(predicate::str::contains("Bytes per gate"));
}

#[test]
fn test_compare_identical_files() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file1 = create_bristol_file(bristol_content);
    let bristol_file2 = create_bristol_file(bristol_content);

    ckt_cmd()
        .arg("compare")
        .arg(bristol_file1.path())
        .arg(bristol_file2.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("✓ Same number of gates"))
        .stdout(predicate::str::contains("✓ Same gate type distribution"));
}

#[test]
fn test_compare_different_files() {
    let bristol_content1 = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_content2 = "2 1 0 1 2 XOR\n2 1 3 4 5 XOR\n2 1 6 7 8 AND\n";
    let bristol_file1 = create_bristol_file(bristol_content1);
    let bristol_file2 = create_bristol_file(bristol_content2);

    ckt_cmd()
        .arg("compare")
        .arg(bristol_file1.path())
        .arg(bristol_file2.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("✗ Gate count differs"))
        .stdout(predicate::str::contains(
            "✗ Different gate type distribution",
        ));
}

#[test]
fn test_compare_bristol_and_ckt() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("test.ckt");

    // Convert to CKT
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Compare Bristol and CKT (should be identical in content)
    ckt_cmd()
        .arg("compare")
        .arg(bristol_file.path())
        .arg(&ckt_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("✓ Same number of gates"))
        .stdout(predicate::str::contains("✓ Same gate type distribution"));
}

#[test]
fn test_extract_round_trip() {
    let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
    let bristol_file = create_bristol_file(bristol_content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("test.ckt");
    let extracted_path = output_dir.path().join("extracted.bristol");

    // Convert to CKT
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Extract back to Bristol
    ckt_cmd()
        .arg("extract")
        .arg(&ckt_path)
        .arg("-o")
        .arg(&extracted_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracting"));

    // Verify extracted content
    let extracted_content = fs::read_to_string(&extracted_path).unwrap();
    assert_eq!(extracted_content.trim(), bristol_content.trim());
}

#[test]
fn test_invalid_bristol_format() {
    let invalid_content = "invalid bristol format\n2 1 0 1 XOR\n"; // Missing output wire
    let bristol_file = create_bristol_file(invalid_content);

    ckt_cmd()
        .arg("verify")
        .arg(bristol_file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid Bristol gate line"));
}

#[test]
fn test_unsupported_gate_type() {
    let invalid_content = "2 1 0 1 2 OR\n"; // OR gate not supported
    let bristol_file = create_bristol_file(invalid_content);

    ckt_cmd()
        .arg("verify")
        .arg(bristol_file.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported gate type"));
}

#[test]
fn test_empty_bristol_file() {
    let empty_file = create_bristol_file("");

    ckt_cmd()
        .arg("verify")
        .arg(empty_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total gates: 0"));
}

#[test]
fn test_bristol_with_empty_lines() {
    let content = "2 1 0 1 2 XOR\n\n2 1 3 4 5 AND\n\n\n2 1 6 7 8 XOR\n";
    let bristol_file = create_bristol_file(content);

    ckt_cmd()
        .arg("verify")
        .arg(bristol_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total gates: 3"));
}

#[test]
fn test_nonexistent_file() {
    ckt_cmd()
        .arg("verify")
        .arg("/nonexistent/file.bristol")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No such file or directory"));
}

#[test]
fn test_default_output_naming() {
    let bristol_content = "2 1 0 1 2 XOR\n";
    let bristol_file = create_bristol_file(bristol_content);

    // Copy to a temp dir with a specific name
    let work_dir = tempdir().unwrap();
    let input_path = work_dir.path().join("circuit.bristol");
    fs::copy(bristol_file.path(), &input_path).unwrap();

    // Run convert without -o flag
    ckt_cmd()
        .current_dir(work_dir.path())
        .arg("convert")
        .arg("circuit.bristol")
        .assert()
        .success();

    // Check that circuit.ckt was created
    let expected_output = work_dir.path().join("circuit.ckt");
    assert!(expected_output.exists());
}

#[test]
fn test_large_circuit_simulation() {
    // Create a "large" circuit (1000 gates)
    let mut content = String::new();
    for i in 0..1000 {
        let gate_type = if i % 2 == 0 { "XOR" } else { "AND" };
        content.push_str(&format!(
            "2 1 {} {} {} {}\n",
            i * 3,
            i * 3 + 1,
            i * 3 + 2,
            gate_type
        ));
    }

    let bristol_file = create_bristol_file(&content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("large.ckt");

    // Convert
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Verify converted file
    ckt_cmd()
        .arg("verify")
        .arg(&ckt_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Total gates: 1_000"));
}

#[test]
fn test_compression_effectiveness() {
    // Create a circuit with 100 gates
    let mut content = String::new();
    for i in 0..100 {
        content.push_str(&format!("2 1 {} {} {} XOR\n", i * 3, i * 3 + 1, i * 3 + 2));
    }

    let bristol_file = create_bristol_file(&content);
    let output_dir = tempdir().unwrap();
    let ckt_path = output_dir.path().join("compressed.ckt");

    // Convert
    ckt_cmd()
        .arg("convert")
        .arg(bristol_file.path())
        .arg("-o")
        .arg(&ckt_path)
        .assert()
        .success();

    // Check compression ratio
    let bristol_size = fs::metadata(bristol_file.path()).unwrap().len();
    let ckt_size = fs::metadata(&ckt_path).unwrap().len();

    // CKT should be significantly smaller
    assert!(
        ckt_size < bristol_size / 2,
        "CKT size ({ckt_size}) should be less than half of Bristol size ({bristol_size})"
    );
}

// Helper function to add to Cargo.toml for tests
// [dev-dependencies]
// assert_cmd = "2.0"
// predicates = "3.0"
// tempfile = "3.0"

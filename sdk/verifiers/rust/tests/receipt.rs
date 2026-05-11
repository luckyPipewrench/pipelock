mod common;

use pipelock_verifier_rs::receipt::run_receipt;
use serde_json::Value;
use std::fs;
use std::process::Command;

#[test]
fn valid_single_receipt_verifies_with_shared_key() {
    let root = common::repo_root();
    let key: Value = serde_json::from_str(
        &fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).unwrap(),
    )
    .unwrap();
    let report = run_receipt(
        root.join("sdk/conformance/testdata/valid-single.json")
            .to_str()
            .unwrap(),
        key["public_key_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.error);
}

#[test]
fn invalid_signature_is_rejected() {
    let root = common::repo_root();
    let key: Value = serde_json::from_str(
        &fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).unwrap(),
    )
    .unwrap();
    let report = run_receipt(
        root.join("sdk/conformance/testdata/invalid-signature.json")
            .to_str()
            .unwrap(),
        key["public_key_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert!(!report.valid);
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or("")
            .contains("signature verification failed")
    );
}

#[test]
fn cli_accepts_key_equals_value() {
    let root = common::repo_root();
    let key: Value = serde_json::from_str(
        &fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .arg("receipt")
        .arg(root.join("sdk/conformance/testdata/valid-single.json"))
        .arg(format!("--key={}", key["public_key_hex"].as_str().unwrap()))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"valid\": true"));
}

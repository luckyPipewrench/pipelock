mod common;

use base64::Engine;
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
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("signature verification failed"));
}

#[test]
fn duplicate_key_rejected_before_metadata_population() {
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-dup-{}.json",
        std::process::id()
    ));
    fs::write(
        &path,
        r#"{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","verdict":"allow","verdict":"block","target":"https://e.example","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"}"#,
    )
    .unwrap();
    let report = run_receipt(path.to_str().unwrap(), "").unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("duplicate object key"));
    assert_eq!(report.verdict, None);
}

#[test]
fn armored_public_key_file_accepts_crlf_line_endings() {
    let root = common::repo_root();
    let key: Value = serde_json::from_str(
        &fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).unwrap(),
    )
    .unwrap();
    let key_hex = key["public_key_hex"].as_str().unwrap();
    let key_bytes = hex::decode(key_hex).unwrap();
    let key_path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-key-{}.pub",
        std::process::id()
    ));
    fs::write(
        &key_path,
        format!(
            "pipelock-ed25519-public-v1\r\n{}\r\n",
            base64::engine::general_purpose::STANDARD.encode(key_bytes)
        ),
    )
    .unwrap();
    let report = run_receipt(
        root.join("sdk/conformance/testdata/valid-single.json")
            .to_str()
            .unwrap(),
        key_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.error);
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

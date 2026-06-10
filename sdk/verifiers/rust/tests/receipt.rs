mod common;

use base64::Engine;
use pipelock_verifier_rs::receipt::run_receipt;
use serde_json::Value;
use std::fs;
use std::process::Command;

const V2_GOLDEN_PUBLIC_KEY: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const V2_GOLDEN_POLICY_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
        false,
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
        false,
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
    let report = run_receipt(path.to_str().unwrap(), "", false).unwrap();
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
        false,
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

#[test]
fn valid_spanned_v2_receipt_verifies_with_shared_key() {
    let root = common::repo_root();
    let report = run_receipt(
        root.join("internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json")
            .to_str()
            .unwrap(),
        V2_GOLDEN_PUBLIC_KEY,
    false,
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.error);
    assert_eq!(
        report.action_id.as_deref(),
        Some("01F8MECHZX3TBDSZ7XRADM79ZS")
    );
    assert_eq!(report.verdict.as_deref(), Some("block"));
    assert_eq!(report.transport.as_deref(), Some("forward"));
    assert_eq!(report.signer_key.as_deref(), Some(V2_GOLDEN_PUBLIC_KEY));
    assert_eq!(report.policy_hash.as_deref(), Some(V2_GOLDEN_POLICY_HASH));
}

#[test]
fn valid_plain_v2_receipt_verifies_with_shared_key() {
    let root = common::repo_root();
    let report = run_receipt(
        root.join("internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json")
            .to_str()
            .unwrap(),
        V2_GOLDEN_PUBLIC_KEY,
        false,
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.error);
    assert_eq!(report.policy_hash.as_deref(), Some(V2_GOLDEN_POLICY_HASH));
}

#[test]
fn missing_v2_policy_hash_is_rejected() {
    let root = common::repo_root();
    let source =
        root.join("internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json");
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt.as_object_mut().unwrap().remove("policy_hash");
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-missing-policy-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("policy_hash"));
}

#[test]
fn reserved_defer_v2_payload_kind_is_rejected() {
    let root = common::repo_root();
    let source =
        root.join("internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json");
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["payload_kind"] = Value::String("defer_opened".to_string());
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-defer-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("known but not implemented"));
}

#[test]
fn tampered_spanned_v2_receipt_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["payload"]["source_spans"][0]["rule_id"] =
        Value::String("aws_access_key_tampered".to_string());
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-tamper-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("signature verification failed"));
}

#[test]
fn unknown_spanned_v2_field_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["payload"]["source_spans"][0]["raw_match"] = Value::String("lowentropy".to_string());
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-unknown-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("unknown field raw_match"));
}

#[test]
fn empty_dlp_normalized_suffix_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["payload"]["source_spans"][0]["normalized_view"] =
        Value::String("dlp_normalized:".to_string());
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-empty-view-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("normalized_view is invalid"));
}

#[test]
fn unsupported_canonicalization_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["canonicalization"]["jcs_profile"] = Value::String("rfc8785".to_string());
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-bad-canon-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("canonicalization.jcs_profile is invalid"));
}

#[test]
fn missing_source_spans_crit_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["crit"] = serde_json::json!(["canonicalization"]);
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-missing-crit-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("crit must include source_spans"));
}

#[test]
fn unknown_crit_is_rejected() {
    let root = common::repo_root();
    let source = root.join(
        "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
    );
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["crit"] = serde_json::json!(["canonicalization", "source_spans", "future_extension"]);
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-unknown-crit-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("crit has unknown field future_extension"));
}

#[test]
fn source_spans_crit_on_plain_payload_is_rejected() {
    let root = common::repo_root();
    let source =
        root.join("internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json");
    let mut receipt: Value = serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    receipt["crit"] = serde_json::json!(["canonicalization", "source_spans"]);
    let path = std::env::temp_dir().join(format!(
        "pipelock-rust-verifier-v2-plain-span-crit-{}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_string(&receipt).unwrap()).unwrap();
    let report = run_receipt(path.to_str().unwrap(), V2_GOLDEN_PUBLIC_KEY, false).unwrap();
    let _ = fs::remove_file(path);
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("crit source_spans is invalid for proxy_decision"));
}

#[test]
fn spanned_v2_receipt_does_not_expose_low_entropy_oracle_key() {
    let root = common::repo_root();
    let receipt: Value = serde_json::from_str(
        &fs::read_to_string(root.join(
            "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let span = &receipt["payload"]["source_spans"][0];
    assert_eq!(span["match_hash_alg"].as_str(), Some("hmac-sha256"));
    assert!(span["match_hash"]
        .as_str()
        .unwrap_or("")
        .starts_with("hmac-sha256:"));
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains("golden-span-mac-key"));
}

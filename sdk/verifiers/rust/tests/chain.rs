mod common;

use ed25519_dalek::{Signer, SigningKey};
use pipelock_verifier_rs::canonical::{canonicalize_action_record, canonicalize_jcs_value};
use pipelock_verifier_rs::chain::{
    compute_session_open_genesis, receipt_hash, verify_chain, verify_chain_with_options,
};
use pipelock_verifier_rs::recorder::extract_receipts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const V2_GOLDEN_PUBLIC_KEY: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const V2_PRIVATE_SEED_HEX: &str = concat!(
    "9d61b19d", "effd5a60", "ba844af4", "92ec2cc4", "4449c569", "7b326919", "703bac03", "1cae7f60"
);

#[test]
fn valid_go_generated_chain_verifies() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let result = verify_chain(&receipts, "");
    assert!(!result.valid);
    assert!(result.error.unwrap_or_default().contains("UNPINNED"));
}

#[test]
fn valid_go_generated_chain_allows_explicit_unpinned_structural_verification() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
    assert_eq!(
        result.root_hash,
        "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a"
    );
}

#[test]
fn legacy_go_generated_chain_verifies_with_pinned_key() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
}

#[test]
fn g1_go_generated_chain_verifies_with_pinned_key() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-valid-chain.jsonl")).unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
}

#[test]
fn g1_restart_chain_verifies_with_prior_tail_fields() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-restart-chain.jsonl")).unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 5);
    assert_eq!(result.final_seq, 4);
    assert_eq!(
        receipts[2]["action_record"]["session_control"]["open"]["prior_chain_seq"],
        json!(1)
    );
    assert!(
        !receipts[2]["action_record"]["session_control"]["open"]["prior_chain_head"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
}

#[test]
fn g1_restart_close_receipt_count_mismatch_is_rejected() {
    let root = common::repo_root();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-restart-chain.jsonl")).unwrap();
    let key = conformance_key();
    receipts[4]["action_record"]["session_control"]["close"]["receipt_count"] = json!(3);
    sign_action_receipt_with_conformance_key(&mut receipts[4]);

    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_close receipt_count mismatch"));
}

#[test]
fn g1_genesis_vectors_match_go() {
    let root = common::repo_root();
    let vectors: Value = serde_json::from_str(
        &fs::read_to_string(root.join("sdk/conformance/testdata/g1-genesis-vectors.json"))
            .expect("read g1 vectors"),
    )
    .expect("parse g1 vectors");
    let vectors = vectors.as_array().expect("vector array");
    assert!(vectors.len() >= 5);
    for vector in vectors {
        let got = compute_session_open_genesis(&vector["open"]);
        assert_eq!(got, vector["expected"].as_str().expect("expected"));
    }
}

#[test]
fn g1_broken_genesis_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-broken-genesis.jsonl")).unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_open genesis hash mismatch"));
}

#[test]
fn g1_legacy_session_open_on_genesis_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-legacy-open-genesis.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_open on legacy genesis"));
}

#[test]
fn g1_inconsistent_heartbeat_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-inconsistent-heartbeat.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(3));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("heartbeat chain_head mismatch"));
}

#[test]
fn g1_inconsistent_close_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-inconsistent-close.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(4));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_close root_hash mismatch"));
}

#[test]
fn g1_ambiguous_session_control_fixture_is_rejected() {
    let root = common::repo_root();
    let key = conformance_key();
    for name in [
        "g1-ambiguous-session-control.jsonl",
        "g1-ambiguous-open-close.jsonl",
        "g1-ambiguous-heartbeat-close.jsonl",
    ] {
        let receipts = extract_receipts(&root.join("sdk/conformance/testdata").join(name)).unwrap();
        let result = verify_chain(&receipts, &key);
        assert!(!result.valid, "{name} unexpectedly verified");
        assert!(result
            .error
            .unwrap_or_default()
            .contains("session_control must carry exactly one payload"));
    }
}

#[test]
fn g1_rotated_close_count_valid_fixture_verifies() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-rotated-close-count-valid.jsonl"))
            .unwrap();
    let result = verify_chain(&receipts, &conformance_trusted_keys());
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 6);
    assert_eq!(result.final_seq, 2);
}

#[test]
fn g1_rotated_close_count_invalid_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts = extract_receipts(
        &root.join("sdk/conformance/testdata/g1-rotated-close-count-invalid.jsonl"),
    )
    .unwrap();
    let result = verify_chain(&receipts, &conformance_trusted_keys());
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_close receipt_count mismatch"));
}

#[test]
fn g1_plain_action_after_close_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-plain-after-close.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("record observed after session_close"));
}

#[test]
fn g1_empty_run_nonce_after_close_fixture_verifies() {
    let root = common::repo_root();
    let receipts = extract_receipts(
        &root.join("sdk/conformance/testdata/g1-empty-run-nonce-after-close.jsonl"),
    )
    .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn g1_heartbeat_after_close_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-heartbeat-after-close.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("record observed after session_close"));
}

#[test]
fn g1_close_without_open_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-close-without-open.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("first receipt is not a matching session_open"));
}

#[test]
fn g1_new_session_after_close_fixture_verifies() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-new-session-after-close.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(result.valid, "{:?}", result.error);
}

#[test]
fn g1_reopen_closed_run_fixture_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-reopen-closed-run.jsonl"))
            .unwrap();
    let key = conformance_key();
    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert!(result
        .error
        .unwrap_or_default()
        .contains("duplicate session_open for run_nonce"));
}

#[test]
fn g1_genesis_chain_open_seq_mismatch_is_rejected_before_signature_check() {
    let root = common::repo_root();
    let key = conformance_key();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-valid-chain.jsonl")).unwrap();
    receipts[0]["action_record"]["session_control"]["open"]["chain_open_seq"] = json!(1);
    sign_action_receipt_with_conformance_key(&mut receipts[0]);

    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_open chain_open_seq does not match receipt chain_seq"));
}

#[test]
fn g1_genesis_prior_chain_tail_is_rejected_before_signature_check() {
    let root = common::repo_root();
    let key = conformance_key();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-valid-chain.jsonl")).unwrap();
    receipts[0]["action_record"]["session_control"]["open"]["prior_chain_head"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    receipts[0]["action_record"]["session_control"]["open"]["prior_chain_seq"] = json!(9);
    sign_action_receipt_with_conformance_key(&mut receipts[0]);

    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("bound genesis session_open must not carry prior chain tail"));
}

#[test]
fn g1_session_control_missing_record_run_nonce_is_rejected_with_valid_signature() {
    let root = common::repo_root();
    let key = conformance_key();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/g1-valid-chain.jsonl")).unwrap();
    if let Some(Value::Object(action_record)) = receipts[3].get_mut("action_record") {
        action_record.remove("run_nonce");
    }
    sign_action_receipt_with_conformance_key(&mut receipts[3]);

    let result = verify_chain(&receipts, &key);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(3));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("session_control receipt missing run_nonce"));
}

#[test]
fn g1_signed_field_tampering_is_rejected() {
    let root = common::repo_root();
    let key = conformance_key();
    type TamperCase = (&'static str, fn(&mut Vec<Value>));
    let cases: &[TamperCase] = &[
        ("session_open_posture_signer_key_id", |receipts| {
            receipts[0]["action_record"]["session_control"]["open"]["posture_signer_key_id"] =
                json!("posture-key-tampered");
        }),
        ("decision_phase", |receipts| {
            receipts[1]["action_record"]["decision_phase"] = json!("outcome");
        }),
        ("heartbeat_beat", |receipts| {
            receipts[3]["action_record"]["session_control"]["heartbeat"]["beat"] = json!(2);
        }),
        ("heartbeat_fsync_errors_gated", |receipts| {
            receipts[3]["action_record"]["session_control"]["heartbeat"]["fsync_errors_gated"] =
                json!(99);
        }),
        ("close_root_hash", |receipts| {
            receipts[4]["action_record"]["session_control"]["close"]["root_hash"] =
                json!("tampered-root");
        }),
        ("close_durability_blocks", |receipts| {
            receipts[4]["action_record"]["session_control"]["close"]["durability_blocks"] =
                json!(99);
        }),
    ];
    for (name, mutate) in cases {
        let mut receipts =
            extract_receipts(&root.join("sdk/conformance/testdata/g1-valid-chain.jsonl")).unwrap();
        mutate(&mut receipts);
        let result = verify_chain(&receipts, &key);
        assert!(!result.valid, "{name} unexpectedly verified");
        assert!(
            result.error.unwrap_or_default().contains("signature"),
            "{name} should fail closed on signature mismatch"
        );
    }
}

#[test]
fn broken_chain_prev_hash_is_rejected() {
    let root = common::repo_root();
    let receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/broken-chain.jsonl")).unwrap();
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(3));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("chain_prev_hash mismatch"));
}

fn conformance_key() -> String {
    let root = common::repo_root();
    let data =
        fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).expect("read key");
    let value: Value = serde_json::from_str(&data).expect("parse key");
    value["public_key_hex"]
        .as_str()
        .expect("public_key_hex")
        .to_string()
}

fn conformance_trusted_keys() -> String {
    let root = common::repo_root();
    let data =
        fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).expect("read key");
    let value: Value = serde_json::from_str(&data).expect("parse key");
    format!(
        "{},{}",
        value["public_key_hex"].as_str().expect("public_key_hex"),
        value["rotated_public_key_hex"]
            .as_str()
            .expect("rotated_public_key_hex")
    )
}

#[test]
fn missing_chain_seq_is_rejected_before_signature_check() {
    let root = common::repo_root();
    let mut receipts =
        extract_receipts(&root.join("sdk/conformance/testdata/valid-chain.jsonl")).unwrap();
    if let Some(Value::Object(action_record)) = receipts[0].get_mut("action_record") {
        action_record.remove("chain_seq");
    }
    let result = verify_chain_with_options(&receipts, "", true);
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(0));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("missing or invalid chain_seq"));
}

#[test]
fn evidence_v2_multi_receipt_chain_verifies() {
    let receipts = build_evidence_chain(2);
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.receipt_count, 2);
    assert_eq!(result.final_seq, 1);
}

#[test]
fn evidence_v2_tampered_chain_fails_closed() {
    let mut receipts = build_evidence_chain(2);
    receipts[1]["chain_prev_hash"] = json!("sha256:0");
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(!result.valid);
    let error = result.error.unwrap_or_default();
    assert!(error.contains("signature") || error.contains("chain_prev_hash"));
}

#[test]
fn evidence_v2_truncated_middle_receipt_fails_closed() {
    let mut receipts = build_evidence_chain(3);
    receipts.remove(1);
    let result = verify_chain(&receipts, V2_GOLDEN_PUBLIC_KEY);
    assert!(!result.valid);
    let error = result.error.unwrap_or_default();
    assert!(error.contains("signature") || error.contains("seq gap"));
}

#[test]
fn recorder_extraction_rejects_duplicate_keys_inside_receipt_detail() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "pipelock-rs-verifier-{}-{suffix}.jsonl",
        std::process::id()
    ));
    let line = r#"{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"action_receipt","transport":"https","summary":"","detail":{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","target":"https://e.example","verdict":"allow","verdict":"block","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"},"prev_hash":"genesis","hash":"h"}"#;
    fs::write(&path, format!("{line}\n")).expect("write JSONL");
    let err = extract_receipts(&path).expect_err("duplicate key should reject");
    let _ = fs::remove_file(&path);
    assert!(err.to_string().contains("duplicate object key"));
}

fn build_evidence_chain(count: usize) -> Vec<Value> {
    let root = common::repo_root();
    let base: Value =
        serde_json::from_str(
            &fs::read_to_string(root.join(
                "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json",
            ))
            .expect("read v2 fixture"),
        )
        .expect("parse v2 fixture");
    let mut receipts = Vec::new();
    let mut prev_hash = "genesis".to_string();
    for i in 0..count {
        let mut receipt = base.clone();
        receipt["event_id"] = json!(format!("01F8MECHZX3TBDSZ7XRADM79V{i}"));
        receipt["chain_seq"] = json!(i);
        receipt["chain_prev_hash"] = json!(prev_hash);
        sign_evidence_receipt(&mut receipt);
        prev_hash = receipt_hash(&receipt);
        receipts.push(receipt);
    }
    receipts
}

fn sign_evidence_receipt(receipt: &mut Value) {
    let signer_key_id = receipt["signature"]["signer_key_id"]
        .as_str()
        .unwrap_or("receipt-signing-test")
        .to_string();
    let mut clone = receipt.clone();
    clone["signature"] = json!({
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": ""
    });
    let seed: [u8; 32] = hex::decode(V2_PRIVATE_SEED_HEX)
        .expect("decode seed")
        .try_into()
        .expect("seed length");
    let key = SigningKey::from_bytes(&seed);
    let signature = key.sign(&canonicalize_jcs_value(&clone).expect("canonicalize receipt"));
    receipt["signature"] = json!({
        "signer_key_id": signer_key_id,
        "key_purpose": "receipt-signing",
        "algorithm": "ed25519",
        "signature": format!("ed25519:{}", hex::encode(signature.to_bytes()))
    });
}

fn sign_action_receipt_with_conformance_key(receipt: &mut Value) {
    let root = common::repo_root();
    let data =
        fs::read_to_string(root.join("sdk/conformance/testdata/test-key.json")).expect("read key");
    let value: Value = serde_json::from_str(&data).expect("parse key");
    let seed: [u8; 32] = hex::decode(value["seed_hex"].as_str().expect("seed_hex"))
        .expect("decode seed")
        .try_into()
        .expect("seed length");
    let key = SigningKey::from_bytes(&seed);
    let digest = Sha256::digest(canonicalize_action_record(&receipt["action_record"]));
    let signature = key.sign(&digest);
    receipt["signature"] = json!(format!("ed25519:{}", hex::encode(signature.to_bytes())));
    receipt["signer_key"] = value["public_key_hex"].clone();
}

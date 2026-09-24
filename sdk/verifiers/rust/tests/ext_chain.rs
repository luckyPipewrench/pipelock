// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::chain::{receipt_hash, verify_chain};
use pipelock_verifier_rs::rawjson::{go_raw_message_bytes, object_member_span, EXT_SOURCE_KEY};
use pipelock_verifier_rs::recorder::{extract_receipts, extract_receipts_from_session_dir};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// Root hash the Go reference verifier reports for g1-ext-chain.jsonl. Every
// verifier pins the same value, so a divergence in ext link bytes fails here.
const EXT_CHAIN_ROOT_HASH: &str =
    "19805bc704923ef6a602abdfa3dc4982134997a69e3fff7a627b3f1805511d1b";

fn testdata(name: &str) -> PathBuf {
    common::repo_root()
        .join("sdk/conformance/testdata")
        .join(name)
}

fn key_hex() -> String {
    let key: Value =
        serde_json::from_str(&fs::read_to_string(testdata("test-key.json")).unwrap()).unwrap();
    key["public_key_hex"].as_str().unwrap().to_string()
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> TempDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "pipelock-rs-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

#[test]
fn ext_chain_vector_verifies_with_go_root_hash() {
    let receipts = extract_receipts(&testdata("g1-ext-chain.jsonl")).unwrap();
    assert_eq!(receipts.len(), 5);
    let result = verify_chain(&receipts, &key_hex());
    assert!(result.valid, "{:?}", result.error);
    assert_eq!(result.root_hash, EXT_CHAIN_ROOT_HASH);
}

#[test]
fn ext_bytes_edited_after_linking_break_chain_at_seq_one() {
    let receipts = extract_receipts(&testdata("g1-ext-tampered-invalid.jsonl")).unwrap();
    let result = verify_chain(&receipts, &key_hex());
    assert!(!result.valid);
    assert_eq!(result.broken_at_seq, Some(1));
    assert!(result
        .error
        .unwrap_or_default()
        .contains("chain_prev_hash mismatch"));
}

#[test]
fn removing_or_changing_ext_in_memory_breaks_link() {
    let mut removed = extract_receipts(&testdata("g1-ext-chain.jsonl")).unwrap();
    removed[0].as_object_mut().unwrap().remove("ext");
    assert!(!verify_chain(&removed, &key_hex()).valid);

    let mut changed = extract_receipts(&testdata("g1-ext-chain.jsonl")).unwrap();
    changed[0]["ext"]["posture_proof_availability"] = json!("readable");
    assert!(!verify_chain(&changed, &key_hex()).valid);

    // A forged source entry that does not describe the parsed ext is ignored.
    let mut forged = extract_receipts(&testdata("g1-ext-chain.jsonl")).unwrap();
    let original = forged[0][EXT_SOURCE_KEY].clone();
    forged[0]["ext"] = json!({"posture_proof_availability": "readable"});
    forged[0][EXT_SOURCE_KEY] = original;
    assert!(!verify_chain(&forged, &key_hex()).valid);
}

#[test]
fn receipt_hash_covers_explicit_null_ext() {
    let receipts = extract_receipts(&testdata("g1-ext-chain.jsonl")).unwrap();
    let with_null = receipts[2].clone();
    assert_eq!(with_null["ext"], Value::Null);
    let mut without = with_null.clone();
    without.as_object_mut().unwrap().remove("ext");
    assert_ne!(receipt_hash(&with_null), receipt_hash(&without));
}

#[test]
fn go_raw_message_bytes_compacts_and_html_escapes() {
    let line_sep = '\u{2028}';
    let esc_a = concat!("\\", "u0041");
    let raw = format!("{{ \"10\" : [ 1.0 , 1E+2 ] ,\t\"a\" : \"<&> {esc_a}\\/ {line_sep}\" }}");
    assert_eq!(
        go_raw_message_bytes(&raw),
        format!("{{\"10\":[1.0,1E+2],\"a\":\"\\u003c\\u0026\\u003e {esc_a}\\/ \\u2028\"}}")
    );
    let line = r#"{"detail" : {"ext" : { "x" : "}" } , "version":1}}"#;
    let (detail_start, _) = object_member_span(line, 0, "detail").unwrap();
    let (start, end) = object_member_span(line, detail_start, "ext").unwrap();
    assert_eq!(&line[start..end], r#"{ "x" : "}" }"#);
}

#[test]
fn interleaved_evidence_receipts_are_skipped_like_go_receipt_chain_mode() {
    let dir = temp_dir("ext-mixed");
    let text = fs::read_to_string(testdata("g1-ext-chain.jsonl")).unwrap();
    let lines: Vec<&str> = text.trim_end().split('\n').collect();
    let evidence: Value =
        serde_json::from_str(
            &fs::read_to_string(common::repo_root().join(
                "internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json",
            ))
            .unwrap(),
        )
        .unwrap();
    let evidence_line = serde_json::to_string(&json!({
        "v": 2,
        "seq": 99,
        "ts": "2026-04-15T12:00:00Z",
        "session_id": "conformance-session",
        "type": "evidence_receipt",
        "transport": "fetch",
        "summary": "evidence",
        "detail": evidence,
        "prev_hash": "genesis",
        "hash": "0",
    }))
    .unwrap();
    let mut mixed = vec![lines[0], evidence_line.as_str()];
    mixed.extend_from_slice(&lines[1..3]);
    mixed.push(evidence_line.as_str());
    mixed.extend_from_slice(&lines[3..]);
    let file = dir.0.join("evidence-mixed-0.jsonl");
    fs::write(&file, format!("{}\n", mixed.join("\n"))).unwrap();
    for receipts in [
        extract_receipts(&file).unwrap(),
        extract_receipts_from_session_dir(&dir.0, "mixed").unwrap(),
    ] {
        assert_eq!(receipts.len(), 5);
        let result = verify_chain(&receipts, &key_hex());
        assert!(result.valid, "{:?}", result.error);
        assert_eq!(result.root_hash, EXT_CHAIN_ROOT_HASH);
    }

    let only = dir.0.join("evidence-only-0.jsonl");
    fs::write(&only, format!("{evidence_line}\n")).unwrap();
    let receipts = extract_receipts(&only).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["record_type"], "evidence_receipt_v2");
}

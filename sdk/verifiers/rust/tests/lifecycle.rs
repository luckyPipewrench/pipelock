// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::lifecycle::analyze_lifecycle;
use pipelock_verifier_rs::types::{ChainResult, Receipt};
use serde::Deserialize;
use serde_json::json;
use std::fs;

#[derive(Deserialize)]
struct Expected {
    status: String,
    reason: String,
}

#[derive(Deserialize)]
struct LifecycleVector {
    name: String,
    receipts: Vec<Receipt>,
    chain_result: LifecycleChain,
    expected: Expected,
}

#[derive(Deserialize)]
struct LifecycleVectorFile {
    generated_by: String,
    vectors: Vec<LifecycleVector>,
}

#[derive(Deserialize, Default)]
struct LifecycleChain {
    valid: bool,
    #[serde(default)]
    integrity_verified: bool,
    #[serde(default)]
    failure_kind: Option<String>,
}

#[test]
fn lifecycle_verdict_vectors_match_go() {
    let file: LifecycleVectorFile = serde_json::from_str(
        &fs::read_to_string(
            common::repo_root().join("sdk/conformance/testdata/lifecycle-verdict-vectors.json"),
        )
        .expect("read lifecycle verdict vectors"),
    )
    .expect("parse lifecycle verdict vectors");
    assert!(file.generated_by.starts_with("go test "));
    assert!(!file.vectors.is_empty(), "lifecycle vector file is empty");
    for vector in file.vectors {
        let chain = ChainResult {
            valid: vector.chain_result.valid,
            integrity_verified: vector.chain_result.integrity_verified,
            failure_kind: vector.chain_result.failure_kind,
            receipt_count: vector.receipts.len(),
            final_seq: vector.receipts.len().saturating_sub(1) as u64,
            root_hash: "test-root".to_string(),
            error: None,
            broken_at_seq: None,
        };
        let actual = analyze_lifecycle(&vector.receipts, &chain);
        assert_eq!(
            actual.status, vector.expected.status,
            "{} status",
            vector.name
        );
        assert_eq!(
            actual.reason, vector.expected.reason,
            "{} reason",
            vector.name
        );
    }
}

#[test]
fn missing_durability_fields_remain_unknown_instead_of_resetting_counters() {
    let receipts = vec![
        json!({"action_record":{"run_nonce":"run-missing-durability","session_control":{"kind":"session_open","open":{"run_nonce":"run-missing-durability","open_nonce":"open"}}}}),
        json!({"action_record":{"run_nonce":"run-missing-durability","session_control":{"kind":"heartbeat","heartbeat":{"run_nonce":"run-missing-durability","open_nonce":"open","beat":1,"fsync_errors_gated":2,"durability_blocks":2}}}}),
        json!({"action_record":{"run_nonce":"run-missing-durability","session_control":{"kind":"heartbeat","heartbeat":{"run_nonce":"run-missing-durability","open_nonce":"open","beat":2}}}}),
        json!({"action_record":{"run_nonce":"run-missing-durability","session_control":{"kind":"session_close","close":{"run_nonce":"run-missing-durability","open_nonce":"open"}}}}),
    ];
    let chain = ChainResult {
        valid: true,
        integrity_verified: false,
        failure_kind: None,
        receipt_count: receipts.len(),
        final_seq: 3,
        root_hash: "test-root".to_string(),
        error: None,
        broken_at_seq: None,
    };

    assert_eq!(
        analyze_lifecycle(&receipts, &chain),
        pipelock_verifier_rs::lifecycle::LifecycleReport {
            status: "LIMITED".to_string(),
            reason: "bounded_closed".to_string(),
        }
    );
}

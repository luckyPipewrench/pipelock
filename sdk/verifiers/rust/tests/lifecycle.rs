// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::lifecycle::analyze_lifecycle;
use pipelock_verifier_rs::types::{ChainResult, Receipt};
use serde::Deserialize;
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

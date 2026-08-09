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
    expected: Expected,
}

#[test]
fn lifecycle_verdict_vectors_match_go() {
    let vectors: Vec<LifecycleVector> = serde_json::from_str(
        &fs::read_to_string(
            common::repo_root().join("sdk/conformance/testdata/lifecycle-verdict-vectors.json"),
        )
        .expect("read lifecycle verdict vectors"),
    )
    .expect("parse lifecycle verdict vectors");
    let chain = ChainResult {
        valid: true,
        receipt_count: 3,
        final_seq: 2,
        root_hash: "test-root".to_string(),
        error: None,
        broken_at_seq: None,
    };
    for vector in vectors {
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

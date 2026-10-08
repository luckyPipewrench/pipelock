// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use pipelock_verifier_rs::line_space::trim_go_space;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    line: String,
    expected: String,
}
#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
}

#[test]
fn shared_go_evidence_line_whitespace_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/testdata/receipt-line-whitespace.json"
    );
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(fixture.vectors.len(), 93);
    for vector in fixture.vectors {
        let trimmed = trim_go_space(&vector.line);
        let outcome = if trimmed.is_empty() {
            "skip"
        } else if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
            "parse"
        } else {
            "reject"
        };
        assert_eq!(outcome, vector.expected, "{}", vector.name);
    }
}

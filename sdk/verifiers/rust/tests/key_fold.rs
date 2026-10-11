// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

use pipelock_verifier_rs::util::reject_duplicate_keys;

#[test]
fn json_key_fold_shared_parity() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../conformance/testdata/json-key-folding.json"
    ))
    .unwrap();
    for group in fixture["groups"].as_array().unwrap() {
        let chars: Vec<char> = group.as_str().unwrap().chars().collect();
        for c in &chars[1..] {
            let raw = format!("{{\"{}\":1,\"{}\":2}}", chars[0], c);
            assert!(reject_duplicate_keys(&raw).is_err(), "{raw}");
        }
    }
    for entry in fixture["cases"].as_array().unwrap() {
        let raw = entry["raw"].as_str().unwrap();
        assert_eq!(
            reject_duplicate_keys(raw).is_ok(),
            entry["valid"].as_bool().unwrap(),
            "{}",
            entry["name"]
        );
    }
}

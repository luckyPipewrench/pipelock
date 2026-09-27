// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Written by the Go conformance test from `internal/recorder` itself, so the
//! port is held to Go's `ComputeHash` and `VerifyChain` rather than to a
//! reading of them.

mod common;

use pipelock_verifier_rs::recorder_chain::{recorder_entry_hash, verify_recorder_chain};
use serde_json::Value;
use std::fs;

fn fixture() -> Value {
    let path = common::repo_root().join("sdk/conformance/testdata/recorder-hash/vectors.json");
    serde_json::from_str(&fs::read_to_string(path).expect("read vectors")).expect("parse vectors")
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().expect("string field").to_string()
}

#[test]
fn recorder_entry_hash_matches_go_compute_hash_for_every_vector() {
    let fx = fixture();
    let hashes = fx["hashes"].as_array().expect("hashes");
    assert!(hashes.len() >= 15);
    for v in hashes {
        assert_eq!(
            recorder_entry_hash(&text(v, "line")).as_deref(),
            Ok(text(v, "hash").as_str()),
            "{}",
            text(v, "name")
        );
    }
}

#[test]
fn recorder_entry_hash_refuses_every_line_go_refuses() {
    let fx = fixture();
    let rejects = fx["rejects"].as_array().expect("rejects");
    assert!(rejects.len() >= 8);
    for v in rejects {
        assert!(
            recorder_entry_hash(&text(v, "line")).is_err(),
            "{}",
            text(v, "name")
        );
    }
}

#[test]
fn recorder_chain_verdicts_and_messages_match_go_verify_chain() {
    let fx = fixture();
    let mut broken = 0;
    for c in fx["chains"].as_array().expect("chains") {
        let lines: Vec<String> = c["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|l| l.as_str().expect("line").to_string())
            .collect();
        let want = text(c, "error");
        assert_eq!(
            verify_recorder_chain(&lines).unwrap_or_default(),
            want,
            "{}",
            text(c, "name")
        );
        if !want.is_empty() {
            broken += 1;
        }
    }
    assert!(broken >= 4);
}

#[test]
fn a_one_character_edit_to_a_sealed_line_breaks_the_chain() {
    let fx = fixture();
    let valid = fx["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .find(|c| text(c, "error").is_empty() && c["lines"].as_array().unwrap().len() >= 3)
        .expect("a valid three-entry chain");
    let mut lines: Vec<String> = valid["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    let edited = lines[1].replacen("\"summary\":\"b\"", "\"summary\":\"B\"", 1);
    assert_ne!(edited, lines[1], "fixture shape changed");
    lines[1] = edited;
    assert!(verify_recorder_chain(&lines)
        .unwrap_or_default()
        .contains("hash mismatch"));
}

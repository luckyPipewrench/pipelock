// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! A rotation endorsement signed by Go whose session_id needs every escape
//! encoding/json applies. The Rust digest must rebuild Go's bytes exactly.

mod common;

use pipelock_verifier_rs::rotation::{load_rotation_endorsement_file, verify_rotation_endorsement};
use std::fs;
use std::path::PathBuf;

fn fixture() -> PathBuf {
    common::repo_root().join("sdk/conformance/testdata/go-json-escapes/endorsement.json")
}

#[test]
fn a_go_signed_endorsement_whose_session_id_needs_every_escape_verifies() {
    let endorsement = load_rotation_endorsement_file(&fixture()).expect("load");
    verify_rotation_endorsement(&endorsement).expect("verify");

    // Same characters, one fewer: the digest changes, so the signature fails.
    let raw = fs::read_to_string(fixture()).expect("read");
    let changed = raw.replacen(r"run\b\f", r"run\b", 1);
    assert_ne!(changed, raw, "fixture shape changed");
    let dir = std::env::temp_dir().join(format!(
        "go-json-escapes-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("mkdir");
    let edited = dir.join("endorsement.json");
    fs::write(&edited, changed).expect("write");
    let result = load_rotation_endorsement_file(&edited)
        .and_then(|e| verify_rotation_endorsement(&e).map(|()| e));
    let _ = fs::remove_dir_all(&dir);
    let err = result.expect_err("edited endorsement must not verify");
    assert!(
        err.to_string().contains("signature verification failed"),
        "{err}"
    );
}

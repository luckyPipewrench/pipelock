// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Every current run writes an ActionReceipt v1 chain and an EvidenceReceipt
//! v2 chain into the same files. These tests hold the CLI to verifying both,
//! and the explicit-session reader to Go's parsed session membership.

mod common;

use pipelock_verifier_rs::recorder::extract_receipts_from_session_dir;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// The run whose action chain the tampered-predecessor variant forges.
const SESSION: &str = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe";

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let dir = std::fs::canonicalize(std::env::temp_dir())
        .expect("canonical temp dir")
        .join(format!(
            "mixed-chains-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
    fs::create_dir_all(&dir).expect("mkdir");
    TempDir(dir)
}

fn fixtures() -> PathBuf {
    common::repo_root().join("sdk/conformance/testdata/run-chains")
}

fn key() -> String {
    fs::read_to_string(fixtures().join("signer-key.hex"))
        .expect("key")
        .trim()
        .to_string()
}

fn run_file(dir: &Path) -> PathBuf {
    dir.join(format!("evidence-{SESSION}-0.jsonl"))
}

fn run_cli(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .args(args)
        .output()
        .expect("run verifier");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
    )
}

fn copy_dir(src: &Path, dst: &Path) {
    for entry in fs::read_dir(src).expect("read fixture") {
        let entry = entry.expect("entry");
        fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy");
    }
}

/// Copies the valid fixture and edits one field of the run's last
/// EvidenceReceipt v2, leaving its action chain untouched.
fn v2_tampered(dir: &Path) {
    copy_dir(&fixtures().join("valid"), dir);
    let text = fs::read_to_string(run_file(dir)).expect("read run");
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let last = lines
        .iter()
        .rposition(|l| l.contains(r#""type":"evidence_receipt""#))
        .expect("evidence receipt line");
    assert_eq!(
        lines[last].matches(r#""actor":"pipelock""#).count(),
        1,
        "fixture shape changed"
    );
    lines[last] = lines[last].replacen(r#""actor":"pipelock""#, r#""actor":"pipelocx""#, 1);
    fs::write(run_file(dir), lines.join("\n")).expect("write run");
}

#[test]
fn a_session_holding_both_chains_is_valid_only_when_both_verify() {
    let tampered = temp_dir("v2");
    v2_tampered(&tampered.0);
    let key = key();
    let cases: [(&str, PathBuf, &str); 3] = [
        ("valid", fixtures().join("valid"), ""),
        (
            "v1-forged",
            fixtures().join("tampered-predecessor"),
            "action receipt chain: ",
        ),
        ("v2-forged", tampered.0.clone(), "evidence receipt chain: "),
    ];
    for (name, dir, want_err) in &cases {
        let dir_s = dir.to_str().expect("path");
        let file = run_file(dir);
        let file_s = file.to_str().expect("path");
        let modes: [(&str, Vec<&str>); 2] = [
            (
                "explicit-session",
                vec!["chain", dir_s, "--dir", "--session-id", SESSION],
            ),
            ("file", vec!["chain", file_s]),
        ];
        for (mode, mut args) in modes {
            args.extend(["--key", key.as_str(), "--json"]);
            let (code, stdout) = run_cli(&args);
            let parsed: Value = serde_json::from_str(&stdout).expect("json report");
            // A named run reports its own chain inside the base report.
            let report = match parsed["chains"].as_array() {
                Some(chains) => chains
                    .iter()
                    .find(|c| c["session"] == SESSION)
                    .cloned()
                    .expect("named run line"),
                None => parsed.clone(),
            };
            if want_err.is_empty() {
                assert_eq!(code, 0, "{name}/{mode}: {stdout}");
                assert_eq!(report["valid"], true);
                assert!(report.get("error").is_none(), "{name}/{mode}: {stdout}");
            } else {
                assert_eq!(code, 1, "{name}/{mode}: {stdout}");
                assert_eq!(report["valid"], false);
                let err = report["error"].as_str().unwrap_or("");
                assert!(
                    err.contains(want_err),
                    "{name}/{mode}: error {err:?} should name {want_err:?}"
                );
            }
        }
        let (code, stdout) = run_cli(&["chain", dir_s, "--dir", "--key", &key, "--json"]);
        let report: Value = serde_json::from_str(&stdout).expect("json report");
        let line = report["chains"]
            .as_array()
            .expect("chains")
            .iter()
            .find(|c| c["session"] == SESSION)
            .expect("run line");
        assert_eq!(line["valid"], want_err.is_empty(), "{name}/directory line");
        assert_eq!(
            code,
            if want_err.is_empty() { 0 } else { 1 },
            "{name}/directory exit"
        );
    }
}

#[test]
fn an_unpinned_mixed_session_reports_the_banner_once() {
    let file = run_file(&fixtures().join("valid"));
    let file_s = file.to_str().expect("path");
    let (code, stdout) = run_cli(&["chain", file_s, "--json"]);
    assert_eq!(code, 1);
    let report: Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["unpinned"], true);
    let err = report["error"].as_str().unwrap_or("");
    assert!(!err.contains("receipt chain:"), "{err}");
    let (code, stdout) = run_cli(&["chain", file_s, "--allow-unpinned"]);
    assert_eq!(code, 0, "{stdout}");
}

/// For session S the name evidence-S-evil-0.jsonl belongs to session S-evil
/// under Go's parsed-equality rule, so it must not be read into S's chain even
/// though it starts with "evidence-S-". The -evil file holds S's entries, so
/// the base pass refuses it by entry session_id, and a named run fails on any
/// finding in its base while its own chain stays valid.
#[test]
fn an_explicit_session_does_not_read_a_prefix_sibling_sessions_files() {
    let dir = temp_dir("prefix");
    let dir_s = dir.0.to_str().expect("path").to_string();
    let key = key();
    fs::copy(run_file(&fixtures().join("valid")), run_file(&dir.0)).expect("copy");
    let (code, stdout) = run_cli(&[
        "chain",
        &dir_s,
        "--dir",
        "--session-id",
        SESSION,
        "--key",
        &key,
    ]);
    assert_eq!(code, 0, "positive control: {stdout}");
    let alone = extract_receipts_from_session_dir(&dir.0, SESSION)
        .expect("extract")
        .len();
    assert!(alone > 0);

    fs::copy(
        run_file(&fixtures().join("tampered-predecessor")),
        dir.0.join(format!("evidence-{SESSION}-evil-0.jsonl")),
    )
    .expect("copy sibling");
    let (code, stdout) = run_cli(&[
        "chain",
        &dir_s,
        "--dir",
        "--session-id",
        SESSION,
        "--key",
        &key,
        "--json",
    ]);
    assert_eq!(code, 1, "{stdout}");
    let report: Value = serde_json::from_str(&stdout).expect("json report");
    let chains: Vec<(String, bool, u64)> = report["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .map(|c| {
            (
                c["session"].as_str().unwrap_or_default().to_string(),
                c["valid"].as_bool().unwrap_or_default(),
                c["action_receipts"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(chains, vec![(SESSION.to_string(), true, alone as u64)]);
    let findings = report["continuity"]["findings"]
        .as_array()
        .expect("findings");
    assert_eq!(findings.len(), 1, "{stdout}");
    assert_eq!(findings[0]["kind"], "corrupt_chain");
    assert_eq!(findings[0]["session"], format!("{SESSION}-evil"));
    assert!(findings[0]["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("does not match requested session"));
    assert_eq!(
        extract_receipts_from_session_dir(&dir.0, SESSION)
            .expect("extract")
            .len(),
        alone
    );
}

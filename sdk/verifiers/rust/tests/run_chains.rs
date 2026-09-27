// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Real evidence directories written by pipelock runs (see
//! sdk/conformance/testdata/run-chains/README.md). Every variant's expected
//! verdict is generated from the Go reference, so these tests hold the Rust
//! verifier to Go's verdict on each one.

mod common;

use pipelock_verifier_rs::chain_set::{verify_base, BaseVerifyOptions};
use pipelock_verifier_rs::rotation::load_rotation_endorsement_file;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// Found from the recorder entry hash chain, which only the Go verifiers check.
const VARIANTS: [&str; 9] = [
    "valid",
    "tampered-predecessor",
    "tampered-successor",
    "link-edited",
    "link-deleted",
    "double-successor",
    "link-wrong-tail",
    "link-appended",
    "key-rotated",
];

struct Case {
    variant: &'static str,
    expect_file: &'static str,
    both_keys: bool,
    endorse: bool,
}

fn cases() -> Vec<Case> {
    let mut out: Vec<Case> = VARIANTS
        .iter()
        .map(|variant| Case {
            variant,
            expect_file: "expect.json",
            both_keys: false,
            endorse: false,
        })
        .collect();
    out.push(Case {
        variant: "key-rotated",
        expect_file: "expect-both-keys.json",
        both_keys: true,
        endorse: false,
    });
    out.push(Case {
        variant: "key-rotated",
        expect_file: "expect-endorsed.json",
        both_keys: false,
        endorse: true,
    });
    out
}

fn fixtures() -> PathBuf {
    common::repo_root().join("sdk/conformance/testdata/run-chains")
}

fn read_trimmed(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .trim()
        .to_string()
}

fn key() -> String {
    read_trimmed(&fixtures().join("signer-key.hex"))
}

fn endorsement_path(case: &Case) -> PathBuf {
    fixtures()
        .join(case.variant)
        .join("rotation-endorsement.json")
}

fn options(case: &Case) -> BaseVerifyOptions {
    let mut trusted_keys = vec![key()];
    if case.both_keys {
        trusted_keys.push(read_trimmed(&fixtures().join("rotated-signer-key.hex")));
    }
    let endorsements = if case.endorse {
        vec![load_rotation_endorsement_file(&endorsement_path(case)).expect("endorsement")]
    } else {
        Vec::new()
    };
    BaseVerifyOptions {
        trusted_keys,
        endorsements,
    }
}

fn expect(case: &Case) -> Value {
    serde_json::from_str(&read_trimmed(
        &fixtures().join(case.variant).join(case.expect_file),
    ))
    .expect("expect json")
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .args(args)
        .output()
        .expect("run verifier");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn run_chain_fixtures_match_go_reference() {
    for case in cases() {
        let name = format!("{}/{}", case.variant, case.expect_file);
        let exp = expect(&case);
        let report = verify_base(&fixtures().join(case.variant), "proxy", &options(&case))
            .unwrap_or_else(|err| panic!("{name}: {err}"));

        let chains: Vec<Value> = report
            .chains
            .iter()
            .map(|c| serde_json::json!({"session": c.session, "valid": c.valid}))
            .collect();
        assert_eq!(Value::Array(chains), exp["chains"], "{name}: chains");

        let linked: Vec<Value> = report
            .chains
            .iter()
            .filter_map(|c| {
                c.link.as_ref().map(|l| {
                    serde_json::json!({
                        "session": c.session,
                        "predecessor_session": l.predecessor_session,
                        "predecessor_tail_seq": l.predecessor_tail_seq,
                        "trust": c.link_trust,
                    })
                })
            })
            .collect();
        assert_eq!(Value::Array(linked), exp["linked"], "{name}: linked");
        assert_eq!(
            serde_json::json!(report.unlinked()),
            exp["unlinked"],
            "{name}: unlinked"
        );

        let mut got: Vec<(String, String)> = report
            .findings
            .iter()
            .map(|f| (f.kind.clone(), f.session.clone()))
            .collect();
        got.sort();
        let want: Vec<(String, String)> = exp["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|f| {
                (
                    f["kind"].as_str().unwrap_or_default().to_string(),
                    f["session"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}: findings");
        assert_eq!(report.healthy(), want.is_empty(), "{name}: healthy");
    }
}

#[test]
fn run_chain_cli_reaches_go_verdict() {
    for case in cases() {
        let name = format!("{}/{}", case.variant, case.expect_file);
        let exp = expect(&case);
        let dir = fixtures().join(case.variant);
        let key = key();
        let rotated = fs::read_to_string(fixtures().join("rotated-signer-key.hex"))
            .expect("rotated key")
            .trim()
            .to_string();
        let endorsement = endorsement_path(&case);
        let mut args = vec![
            "chain",
            dir.to_str().expect("utf8 path"),
            "--dir",
            "--key",
            key.as_str(),
            "--json",
        ];
        // --key repeats, as the Go reference's does, to pin a trusted key set.
        if case.both_keys {
            args.extend(["--key", rotated.as_str()]);
        }
        if case.endorse {
            args.push("--rotation-endorsement");
            args.push(endorsement.to_str().expect("utf8 path"));
        }
        let (code, stdout, stderr) = run_cli(&args);
        let want_valid = exp["valid"].as_bool().expect("valid");
        assert_eq!(code, if want_valid { 0 } else { 1 }, "{name}: {stderr}");
        let report: Value = serde_json::from_str(&stdout).expect("json report");
        assert_eq!(report["valid"], Value::Bool(want_valid), "{name}");
        assert_eq!(report["base"], "proxy", "{name}");
        assert_eq!(
            report["continuity"]["unlinked"], exp["unlinked"],
            "{name}: unlinked"
        );
        let sessions: Vec<Value> = report["chains"]
            .as_array()
            .expect("chains")
            .iter()
            .map(|c| c["session"].clone())
            .collect();
        let want_sessions: Vec<Value> = exp["chains"]
            .as_array()
            .expect("chains")
            .iter()
            .map(|c| c["session"].clone())
            .collect();
        assert_eq!(sessions, want_sessions, "{name}: sessions");
        let finding_pairs = |v: &Value| -> Vec<(String, String)> {
            let mut out: Vec<(String, String)> = v
                .as_array()
                .expect("findings")
                .iter()
                .map(|f| {
                    (
                        f["kind"].as_str().unwrap_or_default().to_string(),
                        f["session"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            out.sort();
            out
        };
        assert_eq!(
            finding_pairs(&report["continuity"]["findings"]),
            finding_pairs(&exp["findings"]),
            "{name}: findings"
        );
    }
}

#[test]
fn run_chain_cli_human_output_lists_linked_and_unlinked_runs() {
    let dir = fixtures().join("valid");
    let key = key();
    let (code, stdout, stderr) = run_cli(&[
        "chain",
        dir.to_str().expect("utf8 path"),
        "--dir",
        "--key",
        &key,
    ]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("RESTART CONTINUITY OK: base \"proxy\": 2 chain(s), 1 linked, 1 unlinked")
    );
    assert!(stdout.contains("(same_key)"));
    assert!(stdout.contains("  result:     VALID"));
}

#[test]
fn run_chain_cli_with_wrong_key_fails_every_run() {
    let dir = fixtures().join("valid");
    let wrong = "11".repeat(32);
    let (code, stdout, _) = run_cli(&[
        "chain",
        dir.to_str().expect("utf8 path"),
        "--dir",
        "--key",
        &wrong,
        "--json",
    ]);
    assert_eq!(code, 1);
    let report: Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(report["valid"], false);
    for chain in report["chains"].as_array().expect("chains") {
        assert_eq!(chain["valid"], false);
    }
}

/// A named run verifies that run's chain and still runs the whole-base pass,
/// as the Go reference does, so its report carries the base's continuity.
#[test]
fn explicit_session_id_verifies_that_run_and_checks_its_base() {
    let dir = fixtures().join("valid");
    let key = key();
    let exp = expect(&cases()[0]);
    let session = exp["chains"][0]["session"].as_str().expect("session");
    let (code, stdout, stderr) = run_cli(&[
        "chain",
        dir.to_str().expect("utf8 path"),
        "--dir",
        "--key",
        &key,
        "--session-id",
        session,
        "--json",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("json");
    let chains = report["chains"].as_array().expect("chains");
    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0]["session"], session);
    assert_eq!(
        chains[0]["path"],
        format!("{} (session {session})", dir.display())
    );
    assert_eq!(chains[0]["valid"], true);
    assert_eq!(report["valid"], true);
    assert_eq!(
        report["continuity"]["chain_count"].as_u64(),
        Some(exp["chains"].as_array().expect("chains").len() as u64)
    );
    assert_eq!(report["continuity"]["healthy"], true);

    // The legacy base session named explicitly has no shards here, so its
    // chain has no receipts.
    let (code, stdout, stderr) = run_cli(&[
        "chain",
        dir.to_str().expect("utf8 path"),
        "--dir",
        "--key",
        &key,
        "--session-id=proxy",
        "--json",
    ]);
    assert_eq!(code, 1);
    let report: Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(report["chains"][0]["error"], "no receipts in chain");
    assert!(
        stderr.starts_with("verification failed: ") && stderr.contains("proxy"),
        "{stderr}"
    );
}

// Each malformed link below must be rejected as an invalid link, never
// silently skipped (which would read as an honest unlinked restart).
#[test]
fn malformed_link_files_are_findings_not_skipped() {
    let valid = fixtures().join("valid");
    let link_name = fs::read_dir(&valid)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|n| n.starts_with("chain-link-"))
        .expect("link file");
    let original = read_trimmed(&valid.join(&link_name));
    let obj: serde_json::Map<String, Value> = serde_json::from_str(&original).expect("link object");
    let with = |key: &str, value: Value| {
        let mut o = obj.clone();
        o.insert(key.to_string(), value);
        Value::Object(o).to_string()
    };
    let upper_key = obj["successor_signer_key"]
        .as_str()
        .expect("key")
        .to_uppercase();
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "duplicate key",
            original.replacen('{', "{\"version\":1,", 1),
            "duplicate",
        ),
        (
            "case-folded alias",
            with("Version", Value::from(1)),
            "aliases \"version\"",
        ),
        (
            "unknown field",
            with("extra", Value::Bool(true)),
            "unknown field \"extra\"",
        ),
        ("trailing tokens", format!("{original} {{}}"), "trailing"),
        (
            "version 2",
            with("version", Value::from(2)),
            "unsupported chain link version",
        ),
        (
            "uppercase key hex",
            with("successor_signer_key", Value::from(upper_key)),
            "successor_signer_key is invalid",
        ),
        (
            "non-canonical linked_at",
            with("linked_at", Value::from("2026-09-27T17:12:14.500Z0")),
            "linked_at",
        ),
        ("not an object", "[]".to_string(), "not a JSON object"),
    ];
    let opts = BaseVerifyOptions {
        trusted_keys: vec![key()],
        endorsements: Vec::new(),
    };
    for (name, body, detail) in cases {
        let dir = tempdir(name);
        for entry in fs::read_dir(&valid)
            .expect("read dir")
            .filter_map(|e| e.ok())
        {
            fs::copy(entry.path(), dir.join(entry.file_name())).expect("copy");
        }
        fs::write(dir.join(&link_name), body).expect("write link");
        let report = verify_base(&dir, "proxy", &opts).expect("verify");
        let finding = report
            .findings
            .iter()
            .find(|f| f.kind == "invalid_link")
            .unwrap_or_else(|| panic!("{name}: want invalid_link, got {:?}", report.findings));
        assert!(
            finding.detail.contains(detail),
            "{name}: detail {:?} lacks {detail:?}",
            finding.detail
        );
        assert!(
            report.chains.iter().all(|c| c.link.is_none()),
            "{name}: a rejected link must not attach"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }
    // Positive control: the unmodified link attaches with no finding.
    let control = verify_base(&valid, "proxy", &opts).expect("verify");
    assert!(control.findings.is_empty());
    assert_eq!(
        control.chains.iter().filter(|c| c.link.is_some()).count(),
        1
    );
}

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "run-chains-{}-{}-{}",
        tag.replace(' ', "-"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("mkdir");
    dir
}

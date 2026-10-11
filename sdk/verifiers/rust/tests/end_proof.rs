// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;
use serde_json::Value;
use std::fs;
use std::process::Command;

#[test]
fn chain_endpoint_parity() {
    let root = common::repo_root().join("sdk/conformance/testdata/end-proof");
    let fixture: Value =
        serde_json::from_slice(&fs::read(root.join("expect.json")).unwrap()).unwrap();
    for cell in fixture["cases"].as_array().unwrap() {
        for json in [false, true] {
            let mut args = vec![
                "chain".to_string(),
                root.join(cell["file"].as_str().unwrap())
                    .to_string_lossy()
                    .into_owned(),
                "--key".into(),
                fixture["key"].as_str().unwrap().into(),
            ];
            args.extend(
                cell["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string()),
            );
            if json {
                args.push("--json".into());
            }
            let result = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
                .args(args)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert_eq!(
                result.status.code().unwrap() as i64,
                cell["exit"].as_i64().unwrap(),
                "{}: {stdout} {stderr}",
                cell["name"]
            );
            if json {
                let report: Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(report["status"], cell["status"]);
                assert_eq!(report["end_proof"]["proven"], cell["proven"]);
                assert_eq!(report["scope"], "receipt_chain");
                assert_eq!(
                    report["integrity"],
                    if cell["exit"] == 1 {
                        "invalid"
                    } else {
                        "valid"
                    }
                );
            } else {
                assert!(format!("{stdout}{stderr}").contains(cell["status"].as_str().unwrap()));
            }
        }
    }
}

#[test]
fn prefix_preserves_signer_trust_warning() {
    let path = common::repo_root().join("sdk/conformance/testdata/end-proof/truncated.jsonl");
    let result = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .arg("chain")
        .arg(path)
        .arg("--allow-unpinned")
        .arg("--allow-prefix")
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&result.stdout);
    assert_eq!(result.status.code(), Some(0), "{output}");
    assert!(output.contains("VALID PREFIX, END UNPROVEN"), "{output}");
    assert!(output.contains("UNPINNED"), "{output}");
}

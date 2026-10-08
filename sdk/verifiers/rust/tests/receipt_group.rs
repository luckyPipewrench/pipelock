// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use pipelock_verifier_rs::receipt_group::verify_receipt_group;
use serde_json::Value;
use std::fs;
use std::process::Command;

const FIXTURE: &[u8] = include_bytes!("fixtures/receipt-groups.zip");
const ATTACK_FIXTURE_PARTS: [&[u8]; 7] = [
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part00"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part01"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part02"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part03"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part04"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part05"),
    include_bytes!("../../fixtures/receipt-groups-attacks.zip.part06"),
];
const MATRIX_FIXTURE: &[u8] = include_bytes!("fixtures/receipt-groups-matrix.zip.gz");

fn attack_fixture() -> Vec<u8> {
    ATTACK_FIXTURE_PARTS.concat()
}

#[test]
fn shared_native_ael_matrix() {
    let cases_root = fixture_from("cases", MATRIX_FIXTURE);
    let matrix: Value = serde_json::from_slice(
        &fs::read(cases_root.parent().unwrap().join("matrix.json")).unwrap(),
    )
    .unwrap();
    let cases = matrix.as_array().unwrap();
    assert_eq!(cases.len(), 119);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let group_id = case["group_id"].as_str().unwrap();
        let keys = case["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let want = case["expected"].as_str().unwrap();
        let report = verify_receipt_group(&cases_root.join(name), group_id, &keys);
        assert_eq!(report.verdict, want, "{name}: {report:?}");
        if name == "predecessor__signed-close-head-disagrees" {
            assert!(
                report
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("closed predecessor"),
                "{report:?}"
            );
        }
        if name == "predecessor__intact__present" {
            assert!(report
                .error
                .as_deref()
                .unwrap_or("")
                .contains("GROUP_INCOMPLETE"));
        }
    }
    let controls: Value = serde_json::from_slice(
        &fs::read(cases_root.parent().unwrap().join("controls.json")).unwrap(),
    )
    .unwrap();
    let controls = controls.as_array().unwrap();
    assert_eq!(controls.len(), 1);
    for case in controls {
        let name = case["name"].as_str().unwrap();
        let group_id = case["group_id"].as_str().unwrap();
        let keys = case["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let report = verify_receipt_group(
            &cases_root.parent().unwrap().join("controls").join(name),
            group_id,
            &keys,
        );
        assert_eq!(
            report.verdict,
            case["expected"].as_str().unwrap(),
            "{name}: {report:?}"
        );
    }
}

#[test]
fn torn_group_gate_without_opening_never_falls_back_to_legacy_directory() {
    let dir = fixture_from("cases/shard__torn-gate-missing-open", MATRIX_FIXTURE);
    let output = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .args(["chain", dir.to_str().unwrap(), "--dir", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"]
        .as_str()
        .unwrap_or("")
        .contains("GROUP_INVALID"));
}

fn fixture(name: &str) -> std::path::PathBuf {
    fixture_from(name, FIXTURE)
}

fn fixture_from(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "pipelock-rust-group-{}-{stamp}-{name}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let archive = root.join("receipt-groups.zip");
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let compressed = root.join("receipt-groups.zip.gz");
        fs::write(&compressed, bytes).unwrap();
        let output = Command::new("gzip")
            .arg("-cd")
            .arg(&compressed)
            .output()
            .expect("gzip must be installed for shared matrix tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(&archive, output.stdout).unwrap();
    } else {
        fs::write(&archive, bytes).unwrap();
    }
    let status = Command::new("unzip")
        .arg("-qq")
        .arg("-o")
        .arg(&archive)
        .arg("-d")
        .arg(&root)
        .output()
        .expect("unzip must be installed for Rust verifier fixture tests");
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    root.join(name)
}

#[test]
fn shared_attack_vectors_reject_predecessor_and_successor() {
    for name in ["forged-untrusted", "flipped-signature", "lying-chain-head"] {
        let dir = fixture_from(name, &attack_fixture());
        let (successor, keys) = trust(&dir);
        let predecessor = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .find(|name| {
                name.starts_with("receipt-group-")
                    && name.ends_with("-open.json")
                    && !name.contains(&successor)
            })
            .unwrap();
        let predecessor =
            predecessor["receipt-group-".len()..predecessor.len() - "-open.json".len()].to_string();
        for id in [&predecessor, &successor] {
            let report = verify_receipt_group(&dir, id, &keys);
            assert_eq!(report.verdict, "GROUP_INVALID", "{name} {id}: {report:?}");
        }
    }
    for name in ["extra-unowned-ael", "empty-unowned-ael"] {
        let dir = fixture_from(name, &attack_fixture());
        let (id, keys) = trust(&dir);
        let report = verify_receipt_group(&dir, &id, &keys);
        assert_eq!(report.verdict, "GROUP_INVALID", "{report:?}");
        assert!(report
            .error
            .unwrap_or_default()
            .contains("no signed session owner"));
    }
    for name in [
        "self-signed-owner",
        "damaged-recorder-owner",
        "damaged-recorder-trusted-owner",
        "damaged-legacy-ael",
        "damaged-neighbor-ael",
        "missing-legacy-ael",
        "missing-neighbor-ael",
        "damaged-legacy-incomplete",
    ] {
        let dir = fixture_from(name, &attack_fixture());
        let (id, keys) = trust(&dir);
        let report = verify_receipt_group(&dir, &id, &keys);
        assert_eq!(report.verdict, "GROUP_INVALID", "{name}: {report:?}");
    }
    for scenario in ["damaged-neighbor-ael", "missing-neighbor-ael"] {
        let dir = fixture_from(scenario, &attack_fixture());
        let (_, keys) = trust(&dir);
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("receipt-group-") && name.ends_with("-open.json") {
                let id = &name["receipt-group-".len()..name.len() - "-open.json".len()];
                let report = verify_receipt_group(&dir, id, &keys);
                assert_eq!(
                    report.verdict, "GROUP_INVALID",
                    "{scenario}/{id}: {report:?}"
                );
            }
        }
    }
    let dir = fixture_from("trusted-legacy-owner", &attack_fixture());
    let (id, keys) = trust(&dir);
    let report = verify_receipt_group(&dir, &id, &keys);
    assert_eq!(report.verdict, "GROUP_VALID", "{report:?}");
    let dir = fixture_from("large-legacy-ael", &attack_fixture());
    let (id, keys) = trust(&dir);
    let report = verify_receipt_group(&dir, &id, &keys);
    assert_eq!(report.verdict, "GROUP_VALID", "{report:?}");
}

#[test]
fn recovery_seal_survives_shard_count_change() {
    let dir = fixture_from("recovery-count-change", &attack_fixture());
    let (id, keys) = trust(&dir);
    let report = verify_receipt_group(&dir, &id, &keys);
    assert_eq!(report.verdict, "GROUP_VALID", "{report:?}");
    assert_eq!(report.shard_count, 3);
}

#[test]
fn shared_duplicate_successors_are_invalid() {
    let dir = fixture_from("duplicate-successor", &attack_fixture());
    let (_, keys) = trust(&dir);
    let ids: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("receipt-group-") && name.ends_with("-open.json"))
        .map(|name| name["receipt-group-".len()..name.len() - "-open.json".len()].to_string())
        .collect();
    assert_eq!(ids.len(), 3);
    for id in ids {
        let report = verify_receipt_group(&dir, &id, &keys);
        assert_eq!(report.verdict, "GROUP_INVALID", "{id}: {report:?}");
    }
}

fn trust(dir: &std::path::Path) -> (String, Vec<String>) {
    let v: Value = serde_json::from_slice(&fs::read(dir.join("trust.json")).unwrap()).unwrap();
    (
        v["group_id"].as_str().unwrap().to_string(),
        v["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect(),
    )
}

#[test]
fn go_produced_groups_verify_with_native_ael() {
    let dir = fixture("group-valid");
    let (id, keys) = trust(&dir);
    let report = verify_receipt_group(&dir, &id, &keys);
    assert_eq!(report.verdict, "GROUP_VALID", "{report:?}");
}

#[test]
fn successor_and_recovery_transition_verification() {
    for name in ["group-successor", "group-recovery-successor"] {
        let dir = fixture(name);
        let (id, keys) = trust(&dir);
        let report = verify_receipt_group(&dir, &id, &keys);
        assert_eq!(report.verdict, "GROUP_VALID", "{name}: {report:?}");
    }
}

#[test]
fn group_fail_closed_mutation_cases() {
    // Missing close is incomplete only after all surviving shards have been
    // checked; malformed signed state and untrusted keys are invalid.
    let dir = fixture("group-valid");
    let (id, keys) = trust(&dir);
    fs::remove_file(dir.join(format!("receipt-group-{id}-close.json"))).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INCOMPLETE"
    );

    let dir = fixture("group-valid");
    let (id, keys) = trust(&dir);
    let shard = fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("evidence-"))
        .unwrap()
        .path();
    fs::remove_file(shard).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-valid");
    let (id, keys) = trust(&dir);
    let ael = fs::read_dir(dir.join("ael"))
        .unwrap()
        .filter_map(Result::ok)
        .next()
        .unwrap()
        .path()
        .join("recorders/pipelock.jsonl");
    let mut bytes = fs::read(&ael).unwrap();
    let dot = bytes.iter().position(|b| *b == b'.').unwrap();
    bytes[dot + 1] = if bytes[dot + 1] == b'A' { b'B' } else { b'A' };
    fs::write(ael, bytes).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-successor");
    let (id, keys) = trust(&dir);
    let transition = dir.join(format!("receipt-group-{id}-transition.json"));
    let mut raw = fs::read(&transition).unwrap();
    let marker = b"\"signature\":\"ed25519:";
    let n = raw.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    raw[n] = if raw[n] == b'0' { b'1' } else { b'0' };
    fs::write(transition, raw).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-successor");
    let (id, keys) = trust(&dir);
    let predecessor_open = fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("receipt-group-")
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-open.json")
                && !p.file_name().unwrap().to_string_lossy().contains(&id)
        })
        .unwrap();
    let predecessor: Value = serde_json::from_slice(&fs::read(&predecessor_open).unwrap()).unwrap();
    let predecessor_session = predecessor["shards"][0]["session_id"].as_str().unwrap();
    fs::remove_file(dir.join(format!("evidence-{predecessor_session}-0.jsonl"))).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-recovery-successor");
    let (id, keys) = trust(&dir);
    let seal = dir.join("chain-link-proxy.run.3b8d089a7edb3af25bc20214ae5baa50.json");
    let mut raw = fs::read(&seal).unwrap();
    let marker = b"\"signature\":\"ed25519:";
    let n = raw.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    raw[n] = if raw[n] == b'0' { b'1' } else { b'0' };
    fs::write(seal, raw).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-recovery-successor");
    let (id, keys) = trust(&dir);
    let seal = dir.join("chain-link-proxy.run.3b8d089a7edb3af25bc20214ae5baa50.json");
    fs::remove_file(seal).unwrap();
    assert_eq!(
        verify_receipt_group(&dir, &id, &keys).verdict,
        "GROUP_INVALID"
    );

    let dir = fixture("group-valid");
    let (id, _keys) = trust(&dir);
    assert_eq!(
        verify_receipt_group(&dir, &id, &[]).verdict,
        "GROUP_INVALID"
    );
}

#[test]
fn cli_group_mode_exits_nonzero_for_incomplete_group() {
    let dir = fixture("group-valid");
    let (id, keys) = trust(&dir);
    fs::remove_file(dir.join(format!("receipt-group-{id}-close.json"))).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"));
    command.args(["group", dir.to_str().unwrap(), "--group-id", &id, "--json"]);
    for key in &keys {
        command.args(["--key", key]);
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["verdict"], "GROUP_INCOMPLETE");
}

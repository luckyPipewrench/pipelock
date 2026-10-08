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
const V2_FIXTURE: &[u8] = include_bytes!("fixtures/receipt-groups-v2.zip");

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

/// An extracted fixture tree. The whole extraction root is removed when the
/// guard drops, including when the test panics, so a run never leaves its
/// extraction directories behind in the temporary directory.
struct Fixture {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl std::ops::Deref for Fixture {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.path
    }
}

impl AsRef<std::path::Path> for Fixture {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

fn fixture(name: &str) -> Fixture {
    fixture_from(name, FIXTURE)
}

fn fixture_from(name: &str, bytes: &[u8]) -> Fixture {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // Parallel tests can read the same clock value; a process-wide counter keeps
    // every extraction root unique.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "pipelock-rust-group-{}-{stamp}-{serial}-{}",
        std::process::id(),
        name.replace('/', "-")
    ));
    fs::create_dir_all(&root).unwrap();
    let guard_root = root.clone();
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
    Fixture {
        path: root.join(name),
        root: guard_root,
    }
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

const MUTATION_VECTORS: &str = include_str!("../../receipt-group-mutation-vectors.json");
const DUPLICATE_RUN_FIXTURE: &[u8] =
    include_bytes!("../../fixtures/receipt-group-duplicate-ael-run.zip");

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn apply_mutation(dir: &std::path::Path, op: &Value) {
    let target = dir.join(op["file"].as_str().unwrap());
    let arg = op["arg"].as_str().unwrap_or("");
    match op["op"].as_str().unwrap() {
        "create" => fs::write(&target, arg).unwrap(),
        "delete" => fs::remove_file(&target).unwrap(),
        kind => {
            let mut bytes = fs::read(&target).unwrap();
            match kind {
                "append" => {
                    for pair in arg.as_bytes().chunks(2) {
                        let digits = std::str::from_utf8(pair).unwrap();
                        bytes.push(u8::from_str_radix(digits, 16).unwrap());
                    }
                }
                "bom" => bytes.splice(0..0, [0xef, 0xbb, 0xbf]).for_each(drop),
                "empty" => bytes.clear(),
                "strip_final_newline" => {
                    assert_eq!(bytes.pop(), Some(b'\n'));
                }
                "truncate_half" => bytes.truncate(bytes.len() / 2),
                "drop_last_line" => {
                    while bytes.last() == Some(&b'\n') {
                        bytes.pop();
                    }
                    match bytes.iter().rposition(|b| *b == b'\n') {
                        Some(cut) => bytes.truncate(cut + 1),
                        None => {
                            bytes.clear();
                            bytes.push(b'\n');
                        }
                    }
                }
                other => panic!("unknown mutation {other}"),
            }
            fs::write(&target, bytes).unwrap();
        }
    }
}

// Every verdict in the vector file was produced by the Go CLI on the same
// mutated directory.
#[test]
fn shared_mutation_vectors_match_the_go_verdict() {
    let vectors: Value = serde_json::from_str(MUTATION_VECTORS).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 25);
    let cases_root = fixture_from("cases", MATRIX_FIXTURE);
    let scratch = cases_root.parent().unwrap().join("mutated");
    for item in vectors {
        let name = item["name"].as_str().unwrap();
        let dir = scratch.join(name);
        copy_tree(&cases_root.join(item["case"].as_str().unwrap()), &dir);
        for op in item["ops"].as_array().unwrap() {
            apply_mutation(&dir, op);
        }
        let keys = item["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let report = verify_receipt_group(&dir, item["group_id"].as_str().unwrap(), &keys);
        assert_eq!(
            report.verdict,
            item["expected"].as_str().unwrap(),
            "{name}: {report:?}"
        );
        if let Some(want) = item["error_contains"].as_str() {
            assert!(
                report.error.as_deref().unwrap_or("").contains(want),
                "{name}: {report:?}"
            );
        }
    }
}

// A closed group whose two shards both sign a session_open for one native AEL
// run. Asserting the message makes the test fail if the duplicate guard is
// removed, because the orphaned second run is then reported as unowned.
#[test]
fn duplicate_signed_native_ael_run_is_rejected_end_to_end() {
    let group = fixture_from("duplicate-ael-run", DUPLICATE_RUN_FIXTURE);
    let (id, keys) = trust(&group);
    let report = verify_receipt_group(&group, &id, &keys);
    assert_eq!(report.verdict, "GROUP_INVALID", "{report:?}");
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or("")
            .contains("duplicate signed native AEL run"),
        "{report:?}"
    );
}

// The production shape: groups written by the real server emitter path, with a
// v2 evidence receipt on every shard, a transition from a closed, crashed or
// torn-and-sealed predecessor, and tamper cases whose recorder hash chain (and
// checkpoint, seal and transition signatures) were recomputed, so only the
// signed content is wrong. Every verdict is the Go verifier's own.
#[test]
fn shared_v2_group_corpus_matches_the_go_verdict() {
    let cases_root = fixture_from("cases", V2_FIXTURE);
    let cases: Value =
        serde_json::from_slice(&fs::read(cases_root.parent().unwrap().join("cases.json")).unwrap())
            .unwrap();
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 60);
    for item in cases {
        let name = item["name"].as_str().unwrap();
        let keys = item["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let report = verify_receipt_group(
            &cases_root.join(name),
            item["group_id"].as_str().unwrap(),
            &keys,
        );
        assert_eq!(
            report.verdict,
            item["expected"].as_str().unwrap(),
            "{name}: {report:?}"
        );
    }
}

// A live writer holds a shared flock on its run's lifetime lock. Linking a
// crashed predecessor (unsealed or sealed) needs that lock gone: a held lock is
// a still-growing chain, and a missing lock file cannot prove the exit.
#[cfg(unix)]
#[test]
fn predecessor_with_a_held_writer_lock_is_invalid_until_released() {
    use std::os::fd::AsRawFd;
    let cases_root = fixture_from("cases", V2_FIXTURE);
    let cases: Value =
        serde_json::from_slice(&fs::read(cases_root.parent().unwrap().join("cases.json")).unwrap())
            .unwrap();
    for name in [
        "v2-successor-unsealed-predecessor",
        "v2-successor-sealed-predecessor",
    ] {
        let item = cases
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == name)
            .unwrap();
        let keys = item["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let dir = cases_root.join(name);
        let group_id = item["group_id"].as_str().unwrap();
        let free = verify_receipt_group(&dir, group_id, &keys);
        assert_eq!(free.verdict, "GROUP_VALID", "{name}: {free:?}");
        let mut held = Vec::new();
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
            if file_name.starts_with("writer-") && file_name.ends_with(".lock") {
                let file = fs::File::open(&path).unwrap();
                // SAFETY: the descriptor is owned by `file`, which outlives the lock.
                assert_eq!(
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
                    0
                );
                held.push(file);
            }
        }
        assert!(!held.is_empty(), "{name}: no writer locks to hold");
        let blocked = verify_receipt_group(&dir, group_id, &keys);
        assert_eq!(blocked.verdict, "GROUP_INVALID", "{name}: {blocked:?}");
        assert!(
            blocked
                .error
                .as_deref()
                .unwrap_or("")
                .contains("still present"),
            "{name}: {blocked:?}"
        );
        drop(held);
        let released = verify_receipt_group(&dir, group_id, &keys);
        assert_eq!(released.verdict, "GROUP_VALID", "{name}: {released:?}");
    }
}

// Go reads only the python copy, so a drifted copy elsewhere would silently
// exercise different bytes.
#[test]
fn shared_group_fixtures_are_byte_identical_across_language_directories() {
    let copies: [(&str, [&[u8]; 3]); 3] = [
        (
            "receipt-groups-matrix.zip.gz",
            [
                include_bytes!("../../python/tests/fixtures/receipt-groups-matrix.zip.gz"),
                include_bytes!("../../ts/tests/fixtures/receipt-groups-matrix.zip.gz"),
                include_bytes!("fixtures/receipt-groups-matrix.zip.gz"),
            ],
        ),
        (
            "receipt-groups.zip",
            [
                include_bytes!("../../python/tests/fixtures/receipt-groups.zip"),
                include_bytes!("../../ts/tests/fixtures/receipt-groups.zip"),
                include_bytes!("fixtures/receipt-groups.zip"),
            ],
        ),
        (
            "receipt-groups-v2.zip",
            [
                include_bytes!("../../python/tests/fixtures/receipt-groups-v2.zip"),
                include_bytes!("../../ts/tests/fixtures/receipt-groups-v2.zip"),
                include_bytes!("fixtures/receipt-groups-v2.zip"),
            ],
        ),
    ];
    for (name, [python, ts, rust]) in copies {
        assert!(python == ts, "{name}: ts copy differs from python copy");
        assert!(python == rust, "{name}: rust copy differs from python copy");
    }
}

// A recovery seal covers the final segment's unterminated tail; Go seals NUL
// padding after a fragment, NUL padding alone and a valid final record that
// lacks only its newline, so every verifier must accept them.
#[test]
fn shared_go_sealed_recovery_tail_kinds_verify() {
    const TAILS: &[u8] = include_bytes!("../../fixtures/receipt-group-recovery-tails.zip");
    let cases_root = fixture_from("cases", TAILS);
    let cases: Value =
        serde_json::from_slice(&fs::read(cases_root.parent().unwrap().join("cases.json")).unwrap())
            .unwrap();
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for item in cases {
        let name = item["name"].as_str().unwrap();
        let keys = item["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let report = verify_receipt_group(
            &cases_root.join(name),
            item["group_id"].as_str().unwrap(),
            &keys,
        );
        assert_eq!(
            report.verdict,
            item["expected"].as_str().unwrap(),
            "{name}: {report:?}"
        );
    }
}

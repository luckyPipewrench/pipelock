mod common;

use pipelock_verifier_rs::audit_packet::{verify_audit_packet, AuditPacketOptions};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PUBLIC_KEY: &str = "4655a7e605c12ebb00a46037881c33c5bca5eb74b45a02e8e7261a7ff5a21678";
const ROOT_HASH: &str = "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a";
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

#[test]
fn example_packet_validates_in_offline_mode() {
    let root = common::repo_root();
    let report = verify_audit_packet(
        root.join("sdk/audit-packet/example.json").to_str().unwrap(),
        &AuditPacketOptions {
            signer_key: String::new(),
            offline: true,
            allow_self_consistent_only: false,
            no_trust_required: false,
            expect_sha256: String::new(),
        },
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.schema_check, "pass");
    assert_eq!(report.chain_check, "skipped");
}

#[test]
fn audit_packet_verifies_end_to_end() {
    let packet_dir = write_packet(None);
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.schema_check, "pass");
    assert_eq!(report.chain_check, "pass");
    assert_eq!(report.cross_check, "pass");
}

#[test]
fn audit_packet_detects_totals_mismatch() {
    let packet_dir = write_packet(Some(|packet| {
        packet["summary"]["totals"]["allow"] = Value::from(4);
        packet["summary"]["totals"]["block"] = Value::from(1);
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert!(!report.valid);
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "totals[allow]"));
}

#[test]
fn audit_packet_detects_receipt_count_mismatch() {
    let packet_dir = write_packet(Some(|packet| {
        packet["summary"]["receipt_count"] = Value::from(6);
        packet["summary"]["totals"]["other"] = Value::from(1);
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "receipt_count"));
}

#[test]
fn audit_packet_detects_root_hash_mismatch() {
    let packet_dir = write_packet(Some(|packet| {
        packet["verifier"]["root_hash"] = Value::from("0".repeat(64));
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "root_hash"));
}

#[test]
fn audit_packet_detects_final_seq_mismatch() {
    let packet_dir = write_packet(Some(|packet| {
        packet["verifier"]["final_seq"] = Value::from(3);
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "final_seq"));
}

#[test]
fn audit_packet_detects_final_seq_zero_mismatch() {
    let packet_dir = write_packet(Some(|packet| {
        packet["verifier"]["final_seq"] = Value::from(0);
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "final_seq"));
}

#[test]
fn audit_packet_reports_chain_failure_reason() {
    let root = common::repo_root();
    let packet_dir = write_packet(None);
    fs::copy(
        root.join("sdk/conformance/testdata/broken-chain.jsonl"),
        packet_dir.join("evidence.jsonl"),
    )
    .unwrap();
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.chain_check, "fail");
    assert_eq!(report.cross_check, "skipped");
    assert!(has_error(&report.errors, "chain_prev_hash mismatch"));
}

#[test]
fn audit_packet_detects_verdict_vs_chain_disagreement() {
    let packet_dir = write_packet(Some(|packet| {
        packet["verifier"]["verdict"] = Value::from("invalid");
        packet["verifier"]["trusted"] = Value::from(false);
    }));
    let report = verify_audit_packet(packet_dir.to_str().unwrap(), &default_options()).unwrap();
    assert_eq!(report.cross_check, "fail");
    assert!(has_error(&report.errors, "verdict=invalid"));
}

#[test]
fn offline_skips_chain_verification() {
    let packet_dir = write_packet(Some(|packet| {
        packet["verifier"]["root_hash"] = Value::from("0".repeat(64));
    }));
    let report = verify_audit_packet(
        packet_dir.to_str().unwrap(),
        &AuditPacketOptions {
            offline: true,
            ..default_options()
        },
    )
    .unwrap();
    assert!(report.valid, "{:?}", report.errors);
    assert_eq!(report.chain_check, "skipped");
    assert_eq!(report.cross_check, "skipped");
}

fn base_packet() -> Value {
    json!({
        "schema_version": "pipelock.audit_packet.v0",
        "generated_at": "2026-05-10T00:00:00Z",
        "run": {
            "provider": "local",
            "agent_identity": "test-agent",
            "started_at": "2026-05-10T00:00:00Z"
        },
        "policy": {
            "policy_hashes": ["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        },
        "summary": {
            "receipt_count": 5,
            "totals": {
                "allow": 5,
                "block": 0,
                "warn": 0,
                "ask": 0,
                "strip": 0,
                "forward": 0,
                "redirect": 0,
                "other": 0
            }
        },
        "verifier": {
            "verdict": "valid",
            "trusted": true,
            "receipt_count": 5,
            "root_hash": ROOT_HASH,
            "final_seq": 4,
            "signer_key": PUBLIC_KEY
        },
        "posture": {
            "enforcement_mode": "local",
            "runner_os": "Linux",
            "raw_socket_status": "unknown",
            "docker_socket_status": "unknown",
            "dns_udp_status": "unknown",
            "browser_proxy_status": "unknown",
            "websocket_frame_scanning": "explicit_ws_proxy_path_required",
            "unsupported_paths": []
        },
        "artifacts": {
            "packet": "packet.json",
            "evidence": "evidence.jsonl",
            "verifier": "verifier.txt"
        }
    })
}

fn write_packet(mutator: Option<fn(&mut Value)>) -> PathBuf {
    let root = common::repo_root();
    let id = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("pipelock-rust-verifier-{id}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    let mut packet = base_packet();
    if let Some(mutator) = mutator {
        mutator(&mut packet);
    }
    fs::write(
        dir.join("packet.json"),
        format!("{}\n", serde_json::to_string_pretty(&packet).unwrap()),
    )
    .unwrap();
    fs::copy(
        root.join("sdk/conformance/testdata/valid-chain.jsonl"),
        dir.join("evidence.jsonl"),
    )
    .unwrap();
    fs::write(dir.join("verifier.txt"), "ok\n").unwrap();
    dir
}

fn default_options() -> AuditPacketOptions {
    AuditPacketOptions {
        signer_key: String::new(),
        offline: false,
        allow_self_consistent_only: false,
        no_trust_required: false,
        expect_sha256: String::new(),
    }
}

fn has_error(errors: &Option<Vec<String>>, needle: &str) -> bool {
    errors
        .as_ref()
        .is_some_and(|errors| errors.iter().any(|err| err.contains(needle)))
}

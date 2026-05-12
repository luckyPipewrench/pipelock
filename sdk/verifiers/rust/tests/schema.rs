mod common;

use pipelock_verifier_rs::schema::validate_audit_packet;
use serde_json::Value;
use std::fs;

#[test]
fn example_packet_validates() {
    let root = common::repo_root();
    let packet: Value =
        serde_json::from_str(&fs::read_to_string(root.join("sdk/audit-packet/example.json")).unwrap())
            .unwrap();
    let errors = validate_audit_packet(&packet);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn totals_sum_must_match_receipt_count() {
    let root = common::repo_root();
    let mut packet: Value =
        serde_json::from_str(&fs::read_to_string(root.join("sdk/audit-packet/example.json")).unwrap())
            .unwrap();
    packet["summary"]["totals"]["allow"] = Value::from(99);
    let errors = validate_audit_packet(&packet);
    assert!(errors.iter().any(|err| err.contains("totals sum")));
}

#[test]
fn trusted_requires_valid_verdict_and_signer_key() {
    let root = common::repo_root();
    let mut packet: Value =
        serde_json::from_str(&fs::read_to_string(root.join("sdk/audit-packet/example.json")).unwrap())
            .unwrap();
    packet["verifier"]["verdict"] = Value::from("invalid");
    packet["verifier"]["trusted"] = Value::from(true);
    packet["verifier"]["signer_key"] = Value::from("");
    let errors = validate_audit_packet(&packet);
    assert!(errors.iter().any(|err| err.contains("trusted=true requires verdict=valid")));
    assert!(errors.iter().any(|err| err.contains("trusted=true requires signer_key")));
}

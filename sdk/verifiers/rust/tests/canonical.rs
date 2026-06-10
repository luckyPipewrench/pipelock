#![recursion_limit = "256"]

use pipelock_verifier_rs::canonical::{canonicalize_action_record, canonicalize_receipt};
use pipelock_verifier_rs::signing::verify_receipt_with_options;
use serde_json::json;
use sha2::{Digest, Sha256};

fn full_receipt() -> serde_json::Value {
    json!({
        "version": 1,
        "action_record": {
            "version": 1,
            "action_id": "ts-full-0001",
            "action_type": "write",
            "timestamp": "2026-05-10T12:34:56.789Z",
            "principal": "org:test",
            "actor": "agent:test",
            "delegation_chain": ["root", "delegate"],
            "target": "https://example.com/<x>&y",
            "intent": "post data",
            "data_classes_in": ["secret", "prompt"],
            "data_classes_out": ["summary"],
            "side_effect_class": "external_write",
            "reversibility": "compensatable",
            "policy_hash": "sha256:abc",
            "verdict": "warn",
            "session_taint_level": "medium",
            "session_contaminated": true,
            "recent_taint_sources": [{
                "url": "https://source.example/a",
                "kind": "prompt",
                "level": 5,
                "timestamp": "2026-05-10T12:34:55Z",
                "receipt_id": "r1",
                "match_reason": "pattern"
            }],
            "session_task_id": "task-1",
            "session_task_label": "review",
            "authority_kind": "operator",
            "taint_decision": "ask",
            "taint_decision_reason": "tainted input",
            "task_override_applied": true,
            "contract_winning_source": "manifest",
            "contract_live_verdict": "warn",
            "contract_policy_sources": ["policy-a", "policy-b"],
            "contract_rule_id": "rule-1",
            "active_manifest_hash": "sha256:manifest",
            "contract_hash": "sha256:contract",
            "contract_selector_id": "selector-1",
            "contract_generation": 7,
            "transport": "https",
            "method": "POST",
            "layer": "dlp",
            "pattern": "token",
            "severity": "warning",
            "redaction": {
                "profile": "default",
                "provider": "openai",
                "parser": "json",
                "total_redactions": 2,
                "by_class": { "token": 1, "secret": 1 },
                "cache_boundary_kept": true
            },
            "request_id": "req-1",
            "chain_prev_hash": "genesis",
            "chain_seq": 0,
            "venue": "test-venue",
            "jurisdiction": "test-jurisdiction",
            "rulebook_id": "rulebook-v1",
            "remedy_class": "notify",
            "contestation_window": "24h",
            "precedent_refs": ["p1", "p2"]
        },
        "signature": "ed25519:dc7bdb6220e7dd261ca6a55f295ee0ca44c8dbb04c36a07940ee11730c2119dd1bae6e96ea6d465a7c6ba357119c2218a795b2eec17f424d6e070e03b9c9540c",
        "signer_key": "7de2d117b21faaa0f1d9d3d02fcba13838bef0c75caddf71de376f0bb837bfbc"
    })
}

fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[test]
fn canonical_action_record_matches_go_hash_for_all_current_fields() {
    let receipt = full_receipt();
    assert_eq!(
        sha256(&canonicalize_action_record(&receipt["action_record"])),
        "8d5805f40a979a44983971f1a1a5de677cfa173edc33d71146c586a12a1ff3e1"
    );
}

#[test]
fn canonical_receipt_envelope_matches_go_hash() {
    let receipt = full_receipt();
    assert_eq!(
        sha256(&canonicalize_receipt(&receipt)),
        "1b07dab8572e98c5f823cfdc449cbce6711d6ed626df500d739fd9ba9b630345"
    );
}

#[test]
fn full_field_receipt_signature_verifies() {
    let receipt = full_receipt();
    verify_receipt_with_options(&receipt, "", true).expect("signature verifies");
}

// A segment-genesis receipt after a signing-key rotation carries a
// key_transition marker that the Go signer includes in the canonical preimage
// (after chain_seq, before venue). The verifier MUST reproduce it byte-for-byte
// or a rotated receipt fails to verify. Pinned to the Go-produced hash.
#[test]
fn canonical_action_record_with_key_transition_matches_go_hash() {
    let record = json!({
        "version": 1,
        "action_id": "ts-kt-0001",
        "action_type": "read",
        "timestamp": "2026-05-10T12:34:56.789Z",
        "principal": "org:test",
        "actor": "agent:test",
        "target": "https://example.com/x",
        "side_effect_class": "external_read",
        "reversibility": "full",
        "policy_hash": "sha256:abc",
        "verdict": "allow",
        "transport": "fetch",
        "chain_prev_hash": "priortail",
        "chain_seq": 0,
        "key_transition": {
            "prior_signer_key": "7de2d117b21faaa0f1d9d3d02fcba13838bef0c75caddf71de376f0bb837bfbc",
            "prior_chain_seq": 41,
            "prior_chain_hash": "priortail"
        }
    });
    assert_eq!(
        sha256(&canonicalize_action_record(&record)),
        "e50a5512f6571afdd0196315580707451ec81e9637e9fb51d988bb6c175b1b40"
    );
}

#[test]
fn canonical_action_record_preserves_explicit_empty_key_transition() {
    let record = json!({
        "version": 1,
        "action_id": "ts-kt-empty",
        "action_type": "read",
        "timestamp": "2026-05-10T12:34:56.789Z",
        "principal": "org:test",
        "actor": "agent:test",
        "target": "https://example.com/x",
        "side_effect_class": "external_read",
        "reversibility": "full",
        "policy_hash": "sha256:abc",
        "verdict": "allow",
        "transport": "fetch",
        "chain_prev_hash": "priortail",
        "chain_seq": 0,
        "key_transition": {}
    });
    let canonical =
        String::from_utf8(canonicalize_action_record(&record)).expect("canonical UTF-8");
    assert!(
        canonical.contains(
            r#""key_transition":{"prior_signer_key":"","prior_chain_seq":0,"prior_chain_hash":""}"#
        ),
        "canonical bytes should preserve and normalize explicit empty key_transition: {canonical}"
    );
}

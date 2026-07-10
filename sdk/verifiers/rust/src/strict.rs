//! Strict v1-receipt schema validation (the EV2-FU-1 verifier contract).
//!
//! A signed v1 receipt and every signed object nested inside it
//! (`action_record`, `session_control` and its `open`/`heartbeat`/`close`
//! payloads, `key_transition`, `redaction`, `shield`, and each
//! `recent_taint_sources` element) may carry ONLY the fields the schema
//! defines. An unrecognized field is rejected fail-closed rather than
//! accept-and-ignored, because an ignored sidecar field lets a downstream
//! consumer trust content the signature never covered.
//!
//! The single deliberate exception is the top-level `ext` bag: an unsigned,
//! advisory forward-compat object that verification never consults. It is the
//! only tolerated unknown top-level surface; its contents are not schema-checked.
//!
//! This mirrors Go's `encoding/json` `DisallowUnknownFields` decode of the same
//! struct set so all reference verifiers reach an identical accept/reject
//! verdict. Only v1 receipts are validated here; the v2 `evidence_receipt_v2`
//! shape has its own path.

use crate::util::{Result, VerifierError};
use serde_json::Value;

const RECEIPT_KEYS: &[&str] = &["version", "action_record", "signature", "signer_key", "ext"];

const ACTION_RECORD_KEYS: &[&str] = &[
    "version",
    "action_id",
    "parent_action_id",
    "action_type",
    "timestamp",
    "principal",
    "actor",
    "delegation_chain",
    "target",
    "intent",
    "data_classes_in",
    "data_classes_out",
    "side_effect_class",
    "reversibility",
    "policy_hash",
    "verdict",
    "decision_phase",
    "defer_id",
    "resolution_policy",
    "resolution_source",
    "session_id",
    "session_id_original",
    "session_taint_level",
    "session_contaminated",
    "recent_taint_sources",
    "session_task_id",
    "session_task_label",
    "authority_kind",
    "taint_decision",
    "taint_decision_reason",
    "task_override_applied",
    "contract_winning_source",
    "contract_live_verdict",
    "contract_policy_sources",
    "contract_rule_id",
    "active_manifest_hash",
    "contract_hash",
    "contract_selector_id",
    "contract_generation",
    "transport",
    "method",
    "layer",
    "pattern",
    "severity",
    "redaction",
    "shield",
    "request_id",
    "chain_prev_hash",
    "chain_seq",
    "run_nonce",
    "key_transition",
    "session_control",
    "venue",
    "jurisdiction",
    "rulebook_id",
    "remedy_class",
    "contestation_window",
    "precedent_refs",
];

const SESSION_CONTROL_KEYS: &[&str] = &["kind", "open", "heartbeat", "close"];

const SESSION_OPEN_KEYS: &[&str] = &[
    "run_nonce",
    "open_nonce",
    "recorder_session",
    "policy_hash",
    "signer_key_epoch",
    "heartbeat_seconds",
    "chain_open_seq",
    "prior_chain_head",
    "prior_chain_seq",
    "genesis_hash",
    "genesis_anchor_head",
    "genesis_anchor_log",
    "posture_capsule_sha256",
    "posture_signer_key_id",
    "containment_nonce",
    "contained_uid",
];

const SESSION_HEARTBEAT_KEYS: &[&str] = &[
    "run_nonce",
    "open_nonce",
    "beat",
    "chain_head",
    "chain_seq_head",
    "heartbeat_time",
    "fsync_errors_gated",
    "durability_blocks",
];

const SESSION_CLOSE_KEYS: &[&str] = &[
    "run_nonce",
    "open_nonce",
    "final_seq",
    "root_hash",
    "receipt_count",
    "close_reason",
    "fsync_errors_gated",
    "durability_blocks",
];

const KEY_TRANSITION_KEYS: &[&str] = &["prior_signer_key", "prior_chain_seq", "prior_chain_hash"];

const REDACTION_KEYS: &[&str] = &[
    "profile",
    "provider",
    "parser",
    "total_redactions",
    "by_class",
    "cache_boundary_kept",
];

const SHIELD_KEYS: &[&str] = &[
    "pipeline",
    "total_rewrites",
    "extension_probes",
    "tracking_beacons",
    "agent_traps",
    "fingerprint_shim_injected",
    "svg_foreign_objects",
    "svg_event_handlers",
    "svg_external_references",
    "svg_hidden_text",
    "svg_animation_injections",
    "body_bytes",
    "scanned_bytes",
    "partial",
    "adaptive_signals_recorded",
    "adaptive_signal_max_per_body",
];

const TAINT_SOURCE_REF_KEYS: &[&str] = &[
    "url",
    "kind",
    "level",
    "timestamp",
    "receipt_id",
    "match_reason",
];

fn reject_unknown_keys(obj: &Value, allowed: &[&str], object_name: &str) -> Result<()> {
    let map = match obj.as_object() {
        Some(map) => map,
        None => return Ok(()),
    };
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(VerifierError::Invalid(format!(
                "unknown field {key:?} on signed v1 {object_name} object"
            )));
        }
    }
    Ok(())
}

fn validate_child(parent: &Value, field: &str, allowed: &[&str], name: &str) -> Result<()> {
    if let Some(child) = parent.get(field) {
        if child.is_object() {
            reject_unknown_keys(child, allowed, name)?;
        }
    }
    Ok(())
}

/// Validate a parsed v1 receipt against the strict schema. Tolerates a
/// top-level `ext` bag; rejects any other unrecognized field at any depth
/// within the signed objects. Non-object inputs are left to the caller's
/// other checks.
pub fn validate_v1_receipt(receipt: &Value) -> Result<()> {
    reject_unknown_keys(receipt, RECEIPT_KEYS, "receipt")?;

    if let Some(ar) = receipt.get("action_record") {
        reject_unknown_keys(ar, ACTION_RECORD_KEYS, "action_record")?;
        validate_child(ar, "redaction", REDACTION_KEYS, "redaction")?;
        validate_child(ar, "shield", SHIELD_KEYS, "shield")?;
        validate_child(ar, "key_transition", KEY_TRANSITION_KEYS, "key_transition")?;

        if let Some(sources) = ar.get("recent_taint_sources").and_then(Value::as_array) {
            for src in sources {
                reject_unknown_keys(src, TAINT_SOURCE_REF_KEYS, "taint_source")?;
            }
        }

        if let Some(sc) = ar.get("session_control") {
            reject_unknown_keys(sc, SESSION_CONTROL_KEYS, "session_control")?;
            validate_child(sc, "open", SESSION_OPEN_KEYS, "session_open")?;
            validate_child(sc, "heartbeat", SESSION_HEARTBEAT_KEYS, "session_heartbeat")?;
            validate_child(sc, "close", SESSION_CLOSE_KEYS, "session_close")?;
        }
    }
    Ok(())
}

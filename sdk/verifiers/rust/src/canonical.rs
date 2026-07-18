// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Number, Value};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy)]
enum NestedKind {
    ActionRecord,
    Redaction,
    Shield,
    TaintSource,
    KeyTransition,
    SessionControl,
    SessionOpen,
    SessionHeartbeat,
    SessionClose,
}

#[derive(Clone, Copy)]
struct FieldSpec {
    name: &'static str,
    omitempty: bool,
    nested: Option<NestedKind>,
}

const ACTION_RECORD_FIELDS: &[FieldSpec] = &[
    field("version", false),
    field("action_id", false),
    field("parent_action_id", true),
    field("action_type", false),
    field("timestamp", false),
    field("principal", false),
    field("actor", false),
    field("delegation_chain", false),
    field("target", false),
    field("intent", true),
    field("data_classes_in", true),
    field("data_classes_out", true),
    field("side_effect_class", false),
    field("reversibility", false),
    field("policy_hash", false),
    field("verdict", false),
    field("decision_phase", true),
    field("defer_id", true),
    field("resolution_policy", true),
    field("resolution_source", true),
    field("session_id", true),
    field("session_id_original", true),
    field("session_taint_level", true),
    field("session_contaminated", true),
    nested_field("recent_taint_sources", true, NestedKind::TaintSource),
    field("session_task_id", true),
    field("session_task_label", true),
    field("authority_kind", true),
    field("taint_decision", true),
    field("taint_decision_reason", true),
    field("task_override_applied", true),
    field("contract_winning_source", true),
    field("contract_live_verdict", true),
    field("contract_policy_sources", true),
    field("contract_rule_id", true),
    field("active_manifest_hash", true),
    field("contract_hash", true),
    field("contract_selector_id", true),
    field("contract_generation", true),
    field("transport", false),
    field("method", true),
    field("layer", true),
    field("pattern", true),
    field("severity", true),
    nested_field("redaction", true, NestedKind::Redaction),
    nested_field("shield", true, NestedKind::Shield),
    field("request_id", true),
    field("chain_prev_hash", false),
    field("chain_seq", false),
    field("run_nonce", true),
    nested_field("key_transition", true, NestedKind::KeyTransition),
    nested_field("session_control", true, NestedKind::SessionControl),
    field("venue", true),
    field("jurisdiction", true),
    field("rulebook_id", true),
    field("remedy_class", true),
    field("contestation_window", true),
    field("precedent_refs", true),
];

const RECEIPT_FIELDS: &[FieldSpec] = &[
    field("version", false),
    nested_field("action_record", false, NestedKind::ActionRecord),
    field("signature", false),
    field("signer_key", false),
];

const REDACTION_FIELDS: &[FieldSpec] = &[
    field("profile", true),
    field("provider", true),
    field("parser", true),
    field("total_redactions", true),
    field("by_class", true),
    field("cache_boundary_kept", true),
];

// SHIELD_FIELDS mirrors receipt.ShieldSummary in Go struct-declaration order.
// A shield-bearing receipt must reorder the nested shield object to this exact
// order or it recomputes a different signing hash than the Go signer produced.
const SHIELD_FIELDS: &[FieldSpec] = &[
    field("pipeline", true),
    field("total_rewrites", true),
    field("extension_probes", true),
    field("tracking_beacons", true),
    field("agent_traps", true),
    field("fingerprint_shim_injected", true),
    field("svg_foreign_objects", true),
    field("svg_event_handlers", true),
    field("svg_external_references", true),
    field("svg_hidden_text", true),
    field("svg_animation_injections", true),
    field("body_bytes", true),
    field("scanned_bytes", true),
    field("partial", true),
    field("adaptive_signals_recorded", true),
    field("adaptive_signal_max_per_body", true),
];

const TAINT_SOURCE_FIELDS: &[FieldSpec] = &[
    field("url", false),
    field("kind", false),
    field("level", false),
    field("timestamp", false),
    field("receipt_id", true),
    field("match_reason", true),
];

// KEY_TRANSITION_FIELDS mirrors receipt.KeyTransition in Go struct-declaration
// order. Stamped on a segment-genesis receipt after a signing-key rotation; the
// nested object MUST be reordered to this exact order or a rotated-segment
// receipt recomputes a different signing hash than the Go signer produced.
const KEY_TRANSITION_FIELDS: &[FieldSpec] = &[
    field("prior_signer_key", false),
    field("prior_chain_seq", false),
    field("prior_chain_hash", false),
];

const SESSION_CONTROL_FIELDS: &[FieldSpec] = &[
    field("kind", false),
    nested_field("open", true, NestedKind::SessionOpen),
    nested_field("heartbeat", true, NestedKind::SessionHeartbeat),
    nested_field("close", true, NestedKind::SessionClose),
];

const SESSION_OPEN_FIELDS: &[FieldSpec] = &[
    field("run_nonce", false),
    field("open_nonce", false),
    field("recorder_session", false),
    field("policy_hash", false),
    field("signer_key_epoch", false),
    field("heartbeat_seconds", false),
    field("chain_open_seq", false),
    field("prior_chain_head", true),
    field("prior_chain_seq", true),
    field("genesis_hash", true),
    field("genesis_anchor_head", true),
    field("genesis_anchor_log", true),
    field("posture_capsule_sha256", true),
    field("posture_signer_key_id", true),
    field("containment_nonce", true),
    field("contained_uid", true),
];

const SESSION_HEARTBEAT_FIELDS: &[FieldSpec] = &[
    field("run_nonce", false),
    field("open_nonce", false),
    field("beat", false),
    field("chain_head", false),
    field("chain_seq_head", false),
    field("heartbeat_time", false),
    field("fsync_errors_gated", false),
    field("durability_blocks", false),
];

const SESSION_CLOSE_FIELDS: &[FieldSpec] = &[
    field("run_nonce", false),
    field("open_nonce", false),
    field("final_seq", false),
    field("root_hash", false),
    field("receipt_count", false),
    field("close_reason", false),
    field("fsync_errors_gated", false),
    field("durability_blocks", false),
];

const fn field(name: &'static str, omitempty: bool) -> FieldSpec {
    FieldSpec {
        name,
        omitempty,
        nested: None,
    }
}

const fn nested_field(name: &'static str, omitempty: bool, nested: NestedKind) -> FieldSpec {
    FieldSpec {
        name,
        omitempty,
        nested: Some(nested),
    }
}

pub fn canonicalize_action_record(action_record: &Value) -> Vec<u8> {
    canonical_json_bytes(&order_struct(action_record, ACTION_RECORD_FIELDS))
}

pub fn canonicalize_receipt(receipt: &Value) -> Vec<u8> {
    canonical_json_bytes(&order_struct(receipt, RECEIPT_FIELDS))
}

pub fn canonical_json_string(value: &Value) -> String {
    go_html_escape(&serde_json::to_string(value).expect("serialize JSON value"))
}

pub fn canonicalize_jcs_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    canonicalize_jcs_into(&mut out, value)?;
    Ok(out.into_bytes())
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    canonical_json_string(value).into_bytes()
}

fn order_struct(value: &Value, fields: &[FieldSpec]) -> Value {
    let input = value.as_object();
    let mut out = Map::new();
    for spec in fields {
        let mut field_value = input.and_then(|object| object.get(spec.name)).cloned();
        if field_value.is_none() {
            if spec.omitempty {
                continue;
            }
            field_value = Some(zero_value(spec.name, spec.nested));
        }
        let mut field_value = field_value.expect("field value set");
        field_value = match spec.nested {
            Some(NestedKind::ActionRecord) if field_value.is_object() => {
                order_struct(&field_value, ACTION_RECORD_FIELDS)
            }
            Some(NestedKind::Redaction) if field_value.is_object() => {
                order_struct(&field_value, REDACTION_FIELDS)
            }
            Some(NestedKind::Shield) if field_value.is_object() => {
                order_struct(&field_value, SHIELD_FIELDS)
            }
            Some(NestedKind::TaintSource) if field_value.is_array() => Value::Array(
                field_value
                    .as_array()
                    .expect("checked array")
                    .iter()
                    .map(|item| {
                        if item.is_object() {
                            order_struct(item, TAINT_SOURCE_FIELDS)
                        } else {
                            item.clone()
                        }
                    })
                    .collect(),
            ),
            Some(NestedKind::KeyTransition) if field_value.is_object() => {
                order_struct(&field_value, KEY_TRANSITION_FIELDS)
            }
            Some(NestedKind::SessionControl) if field_value.is_object() => {
                order_struct(&field_value, SESSION_CONTROL_FIELDS)
            }
            Some(NestedKind::SessionOpen) if field_value.is_object() => {
                order_struct(&field_value, SESSION_OPEN_FIELDS)
            }
            Some(NestedKind::SessionHeartbeat) if field_value.is_object() => {
                order_struct(&field_value, SESSION_HEARTBEAT_FIELDS)
            }
            Some(NestedKind::SessionClose) if field_value.is_object() => {
                order_struct(&field_value, SESSION_CLOSE_FIELDS)
            }
            _ => normalize_maps(&field_value),
        };
        if spec.omitempty && is_go_zero(&field_value) {
            continue;
        }
        out.insert(spec.name.to_string(), field_value);
    }
    Value::Object(out)
}

fn zero_value(name: &str, nested: Option<NestedKind>) -> Value {
    if matches!(nested, Some(NestedKind::ActionRecord)) {
        return Value::Object(Map::new());
    }
    match name {
        "version" | "chain_seq" | "level" | "prior_chain_seq" | "heartbeat_seconds"
        | "chain_open_seq" | "beat" | "chain_seq_head" | "fsync_errors_gated"
        | "durability_blocks" | "final_seq" | "receipt_count" => Value::Number(Number::from(0)),
        "delegation_chain" => Value::Null,
        "timestamp" => Value::String("0001-01-01T00:00:00Z".to_string()),
        _ => Value::String(String::new()),
    }
}

fn is_go_zero(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(value) => !*value,
        Value::Number(value) => value.as_i64() == Some(0) || value.as_u64() == Some(0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
    }
}

fn normalize_maps(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(normalize_maps).collect()),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), normalize_maps(&object[key]));
            }
            Value::Object(out)
        }
        _ => value.clone(),
    }
}

fn canonicalize_jcs_into(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                out.push_str(&number.to_string());
            } else {
                return Err(format!("float not allowed in canonicalization: {number}"));
            }
        }
        Value::String(value) => out.push_str(&encode_jcs_string(value)),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonicalize_jcs_into(out, item)?;
            }
            out.push(']');
        }
        Value::Object(object) => {
            let mut pairs: Vec<(String, &Value)> = object
                .iter()
                .map(|(key, value)| (key.nfc().collect::<String>(), value))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for index in 1..pairs.len() {
                if pairs[index].0 == pairs[index - 1].0 {
                    return Err(format!("NFC collision on key {:?}", pairs[index].0));
                }
            }
            out.push('{');
            for (index, (key, value)) in pairs.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&encode_jcs_string(key));
                out.push(':');
                canonicalize_jcs_into(out, value)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn encode_jcs_string(s: &str) -> String {
    let normalized: String = s.nfc().collect();
    let mut out = String::with_capacity(normalized.len() + 2);
    out.push('"');
    for ch in normalized.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn go_html_escape(serialized: &str) -> String {
    let mut out = String::with_capacity(serialized.len());
    for ch in serialized.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(ch),
        }
    }
    out
}

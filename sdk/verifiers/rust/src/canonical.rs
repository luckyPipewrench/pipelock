use serde_json::{Map, Number, Value};

#[derive(Clone, Copy)]
enum NestedKind {
    ActionRecord,
    Redaction,
    TaintSource,
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
    field("request_id", true),
    field("chain_prev_hash", false),
    field("chain_seq", false),
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

const TAINT_SOURCE_FIELDS: &[FieldSpec] = &[
    field("url", false),
    field("kind", false),
    field("level", false),
    field("timestamp", false),
    field("receipt_id", true),
    field("match_reason", true),
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
        if spec.omitempty && is_go_zero(&field_value) {
            continue;
        }
        field_value = match spec.nested {
            Some(NestedKind::ActionRecord) if field_value.is_object() => {
                order_struct(&field_value, ACTION_RECORD_FIELDS)
            }
            Some(NestedKind::Redaction) if field_value.is_object() => {
                order_struct(&field_value, REDACTION_FIELDS)
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
            _ => normalize_maps(&field_value),
        };
        out.insert(spec.name.to_string(), field_value);
    }
    Value::Object(out)
}

fn zero_value(name: &str, nested: Option<NestedKind>) -> Value {
    if matches!(nested, Some(NestedKind::ActionRecord)) {
        return Value::Object(Map::new());
    }
    match name {
        "version" | "chain_seq" | "level" => Value::Number(Number::from(0)),
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

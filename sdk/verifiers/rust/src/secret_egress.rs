// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Fixture-only secret-egress decision v1 assertions. Successful validation
//! establishes shape, not policy eligibility, registry membership, producer
//! coverage, persistence, or permission to release bytes. Receipt signatures
//! authenticate these assertions separately; they do not prove their truth.

use serde_json::{Map, Value};
use std::net::IpAddr;

pub const PAYLOAD_KIND: &str = "secret_egress_decision_v1";
const MAX_DECISION_BYTES: usize = 16 * 1024;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REQUIRED_ENVELOPE_FIELDS: &[&str] = &[
    "record_type",
    "receipt_version",
    "payload_kind",
    "canonicalization",
    "crit",
    "event_id",
    "timestamp",
    "signature",
    "chain_seq",
    "chain_prev_hash",
    "policy_hash",
    "payload",
];
const OPTIONAL_ENVELOPE_FIELDS: &[&str] = &[
    "principal",
    "actor",
    "delegation_chain",
    "active_manifest_hash",
    "contract_hash",
    "selector_id",
    "contract_generation",
];

fn folded_key(key: &str, expected: &str) -> bool {
    // Go's Unicode simple-fold equivalents of the ASCII selector are included
    // so a case alias selects the strict guard and is then rejected.
    key.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{017f}' => 's',
            _ => c.to_ascii_lowercase(),
        })
        .eq(expected.chars())
}

fn selects_feature(key: &str, value: &Value) -> bool {
    (folded_key(key, "payload_kind") && value.as_str() == Some(PAYLOAD_KIND))
        || (folded_key(key, "crit")
            && value.as_array().is_some_and(|features| {
                features
                    .iter()
                    .any(|feature| feature.as_str() == Some(PAYLOAD_KIND))
            }))
}

pub(crate) fn selects_payload(receipt: &Value) -> bool {
    receipt.as_object().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, value)| selects_feature(key, value))
    })
}

/// Select from source members rather than a last-wins map. This is a guard
/// selector only: the ordinary parser still decides whether the JSON is valid.
pub(crate) fn selects_raw_payload(text: &str) -> bool {
    crate::rawjson::object_members(text, 0).is_some_and(|members| {
        members.iter().any(|(key, start, end)| {
            (folded_key(key, "payload_kind") || folded_key(key, "crit"))
                && serde_json::from_str::<Value>(&text[*start..*end])
                    .is_ok_and(|value| selects_feature(key, &value))
        })
    })
}

/// Preserve the new kind's wire constraints before numeric spelling, duplicate
/// selectors and nested decision source size can be lost. Other kinds retain
/// their existing parser semantics. `text` must be the parsed receipt's source.
pub(crate) fn validate_raw_receipt(receipt: &Value, text: &str) -> Result<(), String> {
    if !selects_raw_payload(text) {
        return Ok(());
    }
    let members = crate::rawjson::object_members(text, 0).ok_or("invalid receipt object")?;
    crate::util::reject_duplicate_keys(text).map_err(|err| err.to_string())?;
    validate_envelope_shape(receipt)?;
    let (timestamp_start, timestamp_end) =
        crate::rawjson::object_member_span(text, 0, "timestamp").ok_or("timestamp is missing")?;
    let timestamp_token = &text[timestamp_start..timestamp_end];
    // This candidate wire profile matches the producer and Go time.Time's
    // JSON decoder: the timestamp value itself is unescaped ASCII text.
    if !timestamp_token.is_ascii() || timestamp_token.contains('\\') {
        return Err("timestamp must use unescaped ASCII canonical UTC text".to_string());
    }
    for (field, minimum, maximum) in [
        ("receipt_version", 2, 2),
        ("chain_seq", 0, MAX_SAFE_INTEGER),
        ("contract_generation", 1, MAX_SAFE_INTEGER),
    ] {
        if let Some((_, start, end)) = members.iter().find(|(name, _, _)| name == field) {
            let raw = &text[*start..*end];
            if !canonical_unsigned(raw, minimum, maximum) {
                return Err(format!(
                    "{field} must use a canonical unsigned decimal integer token"
                ));
            }
        }
    }
    let (payload_start, _) = crate::rawjson::object_member_span(text, 0, "payload")
        .ok_or("secret-egress payload is missing")?;
    let (start, end) = crate::rawjson::object_member_span(text, payload_start, "decision")
        .ok_or("secret-egress decision is missing")?;
    if end - start > MAX_DECISION_BYTES {
        return Err("invalid evidence decision size".to_string());
    }
    let (start, end) = crate::rawjson::object_member_span(text, start, "version")
        .ok_or("decision version is missing")?;
    if &text[start..end] != "1" {
        return Err("decision version must use the integer token 1".to_string());
    }
    Ok(())
}

fn canonical_unsigned(raw: &str, minimum: u64, maximum: u64) -> bool {
    !raw.is_empty()
        && (raw == "0" || !raw.starts_with('0'))
        && raw.bytes().all(|b| b.is_ascii_digit())
        && raw
            .parse::<u64>()
            .is_ok_and(|n| (minimum..=maximum).contains(&n))
}

/// Enforce the new-kind envelope's exact, non-null JSON shape for parsed-value
/// callers too. Raw callers additionally use validate_raw_receipt, since a
/// parsed value cannot recover discarded numeric spelling or duplicate keys.
pub(crate) fn validate_envelope_shape(receipt: &Value) -> Result<(), String> {
    let envelope = object(
        receipt,
        REQUIRED_ENVELOPE_FIELDS,
        OPTIONAL_ENVELOPE_FIELDS,
        "receipt",
    )?;
    if string(envelope, "record_type")? != "evidence_receipt_v2"
        || string(envelope, "payload_kind")? != PAYLOAD_KIND
        || envelope["receipt_version"].as_u64() != Some(2)
    {
        return Err("invalid secret-egress envelope identity or version".to_string());
    }
    for field in ["event_id", "timestamp", "chain_prev_hash", "policy_hash"] {
        nonempty_string(envelope, field)?;
    }
    if !canonical_timestamp(string(envelope, "timestamp")?) {
        return Err("timestamp must be canonical UTC RFC3339Nano and not Go zero time".to_string());
    }
    for field in [
        "principal",
        "actor",
        "active_manifest_hash",
        "contract_hash",
        "selector_id",
    ] {
        if envelope.contains_key(field) {
            nonempty_string(envelope, field)?;
        }
    }
    if let Some(delegation) = envelope.get("delegation_chain") {
        let delegation = delegation
            .as_array()
            .ok_or("delegation_chain must be an array")?;
        if delegation.is_empty()
            || delegation
                .iter()
                .any(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Err("delegation_chain must contain nonempty strings".to_string());
        }
    }
    for (field, minimum) in [("chain_seq", 0), ("contract_generation", 1)] {
        if let Some(value) = envelope.get(field) {
            if !value
                .as_u64()
                .is_some_and(|n| (minimum..=MAX_SAFE_INTEGER).contains(&n))
            {
                return Err(format!(
                    "{field} is outside the canonical unsigned integer range"
                ));
            }
        }
    }
    let canonicalization = object(
        &envelope["canonicalization"],
        &[
            "jcs_profile",
            "jcs_version",
            "hash_alg",
            "sig_alg",
            "redaction_ruleset_id",
            "redaction_ruleset_version",
            "redaction_ruleset_hash",
        ],
        &[],
        "canonicalization",
    )?;
    for field in canonicalization.keys() {
        nonempty_string(canonicalization, field)?;
    }
    let signature = object(
        &envelope["signature"],
        &["signer_key_id", "key_purpose", "algorithm", "signature"],
        &[],
        "signature",
    )?;
    for field in signature.keys() {
        nonempty_string(signature, field)?;
    }
    let signature_hex = string(signature, "signature")?
        .strip_prefix("ed25519:")
        .ok_or("signature must use the ed25519 prefix")?;
    if signature_hex.len() != 128
        || !signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("signature must use exactly 128 lowercase ASCII hex digits".to_string());
    }
    let crit = envelope["crit"].as_array().ok_or("crit must be an array")?;
    if crit.len() != 2
        || !crit
            .iter()
            .any(|value| value.as_str() == Some("canonicalization"))
        || !crit
            .iter()
            .any(|value| value.as_str() == Some(PAYLOAD_KIND))
    {
        return Err(
            "crit must contain exactly canonicalization and secret_egress_decision_v1".to_string(),
        );
    }
    validate_payload(&envelope["payload"])
}

fn nonempty_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    let value = string(object, field)?;
    if value.is_empty() {
        return Err(format!("{field} must be a nonempty string"));
    }
    Ok(value)
}

fn canonical_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len()) || bytes.last() != Some(&b'Z') {
        return false;
    }
    for (i, byte) in bytes[..19].iter().enumerate() {
        let delimiter = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            _ => None,
        };
        if delimiter.map_or_else(|| !byte.is_ascii_digit(), |expected| *byte != expected) {
            return false;
        }
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes.len() < 22
            || bytes[bytes.len() - 2] == b'0'
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0_u32, |n, b| n * 10 + u32::from(b - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
        && value != "0001-01-01T00:00:00Z"
}

const REQUIRED_DECISION_FIELDS: &[&str] = &[
    "version",
    "action_id",
    "decision_id",
    "site_id",
    "plane",
    "transport",
    "location",
    "view",
    "boundary",
    "phase",
    "destination_kind",
    "pattern_class",
    "rule_id",
    "finding_disposition",
    "planned_byte_form",
    "authorization",
    "persistence_policy",
];

/// Validate the exact signed payload shape. A registry digest alone does not
/// establish that a decision belongs to that registry or that it is complete.
pub fn validate_payload(payload: &Value) -> Result<(), String> {
    let payload = object(payload, &["registry_hash", "decision"], &[], "payload")?;
    let digest = string(payload, "registry_hash")?;
    if !digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err("registry_hash must be sha256:<64 lowercase hex>".to_string());
    }
    validate_decision(&payload["decision"])
}

/// Validate a parsed decision. Raw JSON callers must reject duplicate object
/// keys before parsing and enforce the 16 KiB raw decision bound (the receipt
/// and chain readers do both). The exact key
/// sets reject aliases, unknown fields, missing fields, and explicit nulls.
pub fn validate_decision(decision: &Value) -> Result<(), String> {
    let d = object(
        decision,
        REQUIRED_DECISION_FIELDS,
        &[
            "outcome",
            "rewrite_fallback",
            "destination_ref",
            "destination_redaction",
        ],
        "decision",
    )?;
    if d["version"].as_u64() != Some(1) {
        return Err("unsupported evidence decision version".to_string());
    }
    let action_id = string(d, "action_id")?;
    let decision_id = string(d, "decision_id")?;
    if !uuid(action_id) || !uuid(decision_id) || action_id == decision_id {
        return Err("invalid or aliased action and decision IDs".to_string());
    }
    identifier(d, "site_id")?;
    if string(d, "plane")? != "proxy" {
        return Err("initial evidence contract covers only proxy sites".to_string());
    }
    let transport = string(d, "transport")?;
    let boundary = string(d, "boundary")?;
    let boundary_ok = match transport {
        "fetch" | "forward" | "intercept" | "reverse" => boundary == "upstream_request",
        "connect" => boundary == "tunnel_admission",
        "websocket" => matches!(boundary, "upstream_request" | "upstream_frame"),
        "mcp_stdio" | "mcp_http_listener" | "mcp_http_upstream" | "mcp_ws" => {
            matches!(boundary, "upstream_request" | "tool_dispatch")
        }
        _ => false,
    };
    if !boundary_ok {
        return Err("classification transport and boundary disagree".to_string());
    }
    member(
        d,
        "location",
        &[
            "url",
            "header",
            "body",
            "tool_arguments",
            "envelope",
            "frame",
        ],
    )?;
    member(
        d,
        "view",
        &[
            "original",
            "normalized",
            "post_transform",
            "reassembled",
            "authorization",
        ],
    )?;
    identifier(d, "rule_id")?;
    member(d, "pattern_class", &["core_floor", "configured"])?;
    let destination_kind = string(d, "destination_kind")?;
    match destination_kind {
        "network" if transport != "mcp_stdio" => {}
        "local_process" if transport == "mcp_stdio" => {}
        _ => return Err("invalid evidence destination kind or carrier".to_string()),
    }
    match (d.get("destination_ref"), d.get("destination_redaction")) {
        (Some(reference), None) => {
            let reference = reference
                .as_str()
                .ok_or("destination_ref must be a string")?;
            if (destination_kind == "network" && !canonical_host(reference))
                || (destination_kind == "local_process" && !valid_identifier(reference))
            {
                return Err("invalid evidence destination reference".to_string());
            }
        }
        (None, Some(redaction)) => {
            let redaction = object(redaction, &["reason"], &[], "destination_redaction")?;
            member(redaction, "reason", &["classified_sensitive"])?;
        }
        _ => return Err("exactly one destination reference or redaction is required".to_string()),
    }
    let planned = member(d, "planned_byte_form", &["none", "original", "transformed"])?;
    let expected_authority = match string(d, "finding_disposition")? {
        "block" if planned == "none" => "none",
        "redact" if planned != "original" => "none",
        "observe" => "none",
        "authorize" => "authorization",
        "exempt" => "exemption",
        _ => return Err("invalid finding disposition or planned byte form".to_string()),
    };
    let authority = object(
        &d["authorization"],
        &["kind"],
        &["ref", "origin"],
        "authorization",
    )?;
    if string(authority, "kind")? != expected_authority {
        return Err("finding and authorization kind disagree".to_string());
    }
    if expected_authority == "none" {
        if authority.contains_key("ref") || authority.contains_key("origin") {
            return Err("non-authorized finding has an authority reference or origin".to_string());
        }
    } else {
        identifier(authority, "ref")?;
        member(authority, "origin", &["builtin", "operator"])?;
    }
    if let Some(fallback) = d.get("rewrite_fallback") {
        let fallback = object(
            fallback,
            &["reason", "policy_ref", "policy_origin"],
            &[],
            "rewrite_fallback",
        )?;
        member(
            fallback,
            "reason",
            &[
                "unparseable_body",
                "no_safe_raw_span",
                "unsupported_encoding",
                "unsupported_shape",
                "opaque_arguments",
            ],
        )?;
        identifier(fallback, "policy_ref")?;
        member(fallback, "policy_origin", &["builtin", "operator"])?;
    }
    member(
        d,
        "persistence_policy",
        &["required_before_action", "best_effort"],
    )?;
    match string(d, "phase")? {
        "intent" if !d.contains_key("outcome") => {}
        "outcome" => {
            let outcome = d.get("outcome").ok_or("outcome observation is missing")?;
            let outcome = object(outcome, &["release", "byte_form"], &[], "outcome")?;
            let release = member(
                outcome,
                "release",
                &["none", "partial", "complete", "unknown"],
            )?;
            let byte_form = member(
                outcome,
                "byte_form",
                &["none", "original", "transformed", "unknown"],
            )?;
            if (release == "none") != (byte_form == "none") {
                return Err("observed release and byte form disagree".to_string());
            }
        }
        _ => return Err("invalid evidence phase or outcome pairing".to_string()),
    }
    // Do not compare observed release against planned bytes. A contradiction
    // is legitimate evidence of an enforcement failure, not malformed evidence.
    // Likewise, a core finding's nonblock handling alone is not invalid.
    Ok(())
}

/// Check that an outcome retains the selected intent's decision facts. This
/// does not authenticate either value, bind their envelopes, or prove that all
/// expected events are present. Contradictory observed release is preserved.
pub fn validate_outcome_of(outcome: &Value, intent: &Value) -> Result<(), String> {
    validate_decision(intent)?;
    validate_decision(outcome)?;
    if intent["phase"] != "intent" || outcome["phase"] != "outcome" {
        return Err("evidence pairing requires intent and outcome phases".to_string());
    }
    let mut selected = outcome.clone();
    let selected = selected.as_object_mut().expect("validated decision object");
    selected.insert("phase".to_string(), Value::String("intent".to_string()));
    selected.remove("outcome");
    if selected != intent.as_object().expect("validated decision object") {
        return Err("evidence outcome changed the selected decision".to_string());
    }
    Ok(())
}

fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    for key in object.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(format!("{label}: unknown field {key}"));
        }
    }
    for key in required {
        if !object.contains_key(*key) {
            return Err(format!("{label}: missing field {key}"));
        }
    }
    Ok(object)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a string"))
}

fn member<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<&'a str, String> {
    let value = string(object, field)?;
    if !allowed.contains(&value) {
        return Err(format!("invalid evidence {field}"));
    }
    Ok(value)
}

fn identifier(object: &Map<String, Value>, field: &str) -> Result<(), String> {
    if !valid_identifier(string(object, field)?) {
        return Err(format!("invalid evidence {field} reference"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
        && (b'1'..=b'8').contains(&bytes[14])
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

// Match Go destination.ParseIPLiteral's identity rules without resolving DNS.
// Numeric aliases and invalid numeric final labels must not become separate
// symbolic DNS identities. Numeric earlier labels remain ordinary DNS names
// when the final label is a nonnumeric DNS label.
fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) => ip.to_string() == host,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none() && ip.to_string() == host,
        };
    }
    let last_label = host.rsplit('.').next().unwrap_or("");
    if (!last_label.is_empty() && last_label.bytes().all(|b| b.is_ascii_digit()))
        || last_label
            .strip_prefix("0x")
            .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

use crate::types::{AuditPacket, Totals};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::sync::LazyLock;

// Embedded at compile time from the in-crate vendored copy of the canonical
// Audit Packet v0 schema. The crate must be self-contained for `cargo publish`
// (cargo only packages files inside the crate root), so the schema lives here
// rather than at sdk/audit-packet/v0.json. The vendored copy is kept
// byte-identical to the canonical source by the drift guard in verifiers.yaml
// (re-vendor with: cp sdk/audit-packet/v0.json sdk/verifiers/rust/audit-packet-v0.json).
static SCHEMA: &str = include_str!("../audit-packet-v0.json");
static COMPILED_SCHEMA: LazyLock<JSONSchema> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(SCHEMA).expect("embedded schema parses");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .expect("embedded schema compiles")
});

const VERIFIER_VERDICTS: &[&str] = &[
    "valid",
    "invalid",
    "error",
    "not_run",
    "self_consistent_only",
];
const PROVIDERS: &[&str] = &["github_actions", "self_hosted", "local"];
const RAW_SOCKET_STATUSES: &[&str] = &["denied", "allowed", "unknown"];
const DOCKER_SOCKET_STATUSES: &[&str] = &["denied", "masked", "allowed", "absent", "unknown"];
const DNS_UDP_STATUSES: &[&str] = &["denied", "proxied", "allowed", "unknown"];
const BROWSER_PROXY_STATUSES: &[&str] = &["forced", "advisory", "absent", "unknown"];
const WEBSOCKET_FRAME_SCANNING: &[&str] = &["explicit_ws_proxy_path_required", "always_on", "off"];

pub fn validate_audit_packet(packet: &AuditPacket) -> Vec<String> {
    let mut errors = validate_schema(packet);
    errors.extend(validate_structural(packet));
    errors
}

pub fn validate_schema(packet: &AuditPacket) -> Vec<String> {
    match COMPILED_SCHEMA.validate(packet) {
        Ok(()) => Vec::new(),
        Err(errors) => errors
            .map(|err| {
                let location = err.instance_path.to_string();
                let location = if location.is_empty() {
                    "/".to_string()
                } else {
                    location
                };
                format!("{location} {}", err)
            })
            .collect(),
    }
}

pub fn validate_structural(packet: &AuditPacket) -> Vec<String> {
    let mut errors = Vec::new();
    if packet.get("schema_version").and_then(Value::as_str) != Some("pipelock.audit_packet.v0") {
        errors.push(format!(
            "schema_version {} is not \"pipelock.audit_packet.v0\"",
            json_text(packet.get("schema_version"))
        ));
    }

    match packet.get("run") {
        Some(run) => {
            enum_check("provider", run.get("provider"), PROVIDERS, &mut errors);
            if run
                .get("agent_identity")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                errors.push("agent_identity is required".to_string());
            }
            if run
                .get("started_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                errors.push("started_at is required".to_string());
            }
        }
        None => errors.push("run is required".to_string()),
    }

    if !packet
        .get("policy")
        .and_then(|policy| policy.get("policy_hashes"))
        .is_some_and(Value::is_array)
    {
        errors.push("policy_hashes is required (use empty array, not null)".to_string());
    }

    match packet
        .get("summary")
        .and_then(|summary| summary.get("totals"))
    {
        Some(totals) => {
            let receipt_count = packet
                .get("summary")
                .and_then(|summary| summary.get("receipt_count"))
                .and_then(Value::as_u64);
            if receipt_count.is_none() {
                errors.push("receipt_count must be non-negative".to_string());
            }
            let mut sum = 0;
            let mut invalid_total = false;
            for key in Totals::keys() {
                let value = totals.get(key).and_then(Value::as_u64);
                if value.is_none() {
                    invalid_total = true;
                    errors.push(format!("totals.{key} must be non-negative"));
                }
                sum += value.unwrap_or(0);
            }
            if !invalid_total {
                if let Some(receipt_count) = receipt_count {
                    if sum != receipt_count {
                        errors.push(format!(
                            "totals sum {sum} does not match receipt_count {receipt_count}"
                        ));
                    }
                }
            }
            if let Some(summary) = packet.get("summary") {
                non_negative_map("transports", summary.get("transports"), &mut errors);
                non_negative_map("layers", summary.get("layers"), &mut errors);
                domains_check(summary.get("domains_touched"), &mut errors);
            }
        }
        None => errors.push("summary.totals is required".to_string()),
    }

    match packet.get("verifier") {
        Some(verifier) => {
            let verdict = verifier.get("verdict").and_then(Value::as_str);
            if !verdict.is_some_and(|value| VERIFIER_VERDICTS.contains(&value)) {
                errors.push(format!(
                    "verdict {} not in {{valid, invalid, error, not_run, self_consistent_only}}",
                    json_text(verifier.get("verdict"))
                ));
            }
            if verifier.get("trusted").and_then(Value::as_bool) == Some(true)
                && verdict != Some("valid")
            {
                errors.push(format!(
                    "trusted=true requires verdict=valid, got {}",
                    json_text(verifier.get("verdict"))
                ));
            }
            if verdict == Some("valid")
                && verifier.get("trusted").and_then(Value::as_bool) != Some(true)
            {
                errors.push("verdict=valid requires trusted=true".to_string());
            }
            if verifier.get("trusted").and_then(Value::as_bool) == Some(true)
                && verifier
                    .get("signer_key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
            {
                errors.push("trusted=true requires signer_key".to_string());
            }
            if verifier
                .get("receipt_count")
                .is_some_and(|value| value.as_u64().is_none())
            {
                errors.push("receipt_count must be non-negative".to_string());
            }
            if verifier
                .get("final_seq")
                .is_some_and(|value| value.as_u64().is_none())
            {
                errors.push("final_seq must be non-negative".to_string());
            }
        }
        None => errors.push("verifier is required".to_string()),
    }

    match packet.get("posture") {
        Some(posture) => {
            if posture
                .get("enforcement_mode")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                errors.push("enforcement_mode is required".to_string());
            }
            if posture
                .get("runner_os")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                errors.push("runner_os is required".to_string());
            }
            enum_check(
                "raw_socket_status",
                posture.get("raw_socket_status"),
                RAW_SOCKET_STATUSES,
                &mut errors,
            );
            enum_check(
                "docker_socket_status",
                posture.get("docker_socket_status"),
                DOCKER_SOCKET_STATUSES,
                &mut errors,
            );
            enum_check(
                "dns_udp_status",
                posture.get("dns_udp_status"),
                DNS_UDP_STATUSES,
                &mut errors,
            );
            enum_check(
                "browser_proxy_status",
                posture.get("browser_proxy_status"),
                BROWSER_PROXY_STATUSES,
                &mut errors,
            );
            enum_check(
                "websocket_frame_scanning",
                posture.get("websocket_frame_scanning"),
                WEBSOCKET_FRAME_SCANNING,
                &mut errors,
            );
            if !posture
                .get("unsupported_paths")
                .is_some_and(Value::is_array)
            {
                errors
                    .push("unsupported_paths is required (use empty array, not null)".to_string());
            }
        }
        None => errors.push("posture is required".to_string()),
    }

    if packet
        .get("artifacts")
        .and_then(|artifacts| artifacts.get("packet"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        errors.push("packet path is required".to_string());
    }
    if packet
        .get("artifacts")
        .and_then(|artifacts| artifacts.get("evidence"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        errors.push("evidence path is required".to_string());
    }
    if packet
        .get("artifacts")
        .and_then(|artifacts| artifacts.get("verifier"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        errors.push("verifier path is required".to_string());
    }

    errors
}

fn enum_check(name: &str, value: Option<&Value>, values: &[&str], errors: &mut Vec<String>) {
    if !value
        .and_then(Value::as_str)
        .is_some_and(|value| values.contains(&value))
    {
        errors.push(format!(
            "{name} {} is not a valid v0 value",
            json_text(value)
        ));
    }
}

fn non_negative_map(name: &str, value: Option<&Value>, errors: &mut Vec<String>) {
    let Some(object) = value.and_then(Value::as_object) else {
        return;
    };
    for (key, count) in object {
        if count.as_u64().is_none() {
            errors.push(format!("{name}[{}] must be non-negative", json_string(key)));
        }
    }
}

fn domains_check(value: Option<&Value>, errors: &mut Vec<String>) {
    let Some(domains) = value.and_then(Value::as_array) else {
        return;
    };
    for index in 1..domains.len() {
        let prev = domains[index - 1].as_str().unwrap_or("");
        let current = domains[index].as_str().unwrap_or("");
        if prev > current {
            errors.push(format!(
                "domains_touched[{index}] {} must sort after {}",
                json_string(current),
                json_string(prev)
            ));
        }
        if prev == current {
            errors.push(format!(
                "domains_touched contains duplicate {} at index {index}",
                json_string(current),
            ));
        }
    }
}

fn json_text(value: Option<&Value>) -> String {
    value.map_or_else(|| "null".to_string(), Value::to_string)
}

fn json_string(value: &str) -> String {
    Value::String(value.to_string()).to_string()
}

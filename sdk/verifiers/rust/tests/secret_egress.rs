// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

mod common;

use pipelock_verifier_rs::receipt::run_receipt;
use pipelock_verifier_rs::secret_egress::{
    validate_decision, validate_outcome_of, validate_payload,
};
use pipelock_verifier_rs::signing::normalize_evidence_receipt;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;

fn decision() -> Value {
    json!({
        "version": 1,
        "action_id": "01990000-0000-7000-8000-000000000001",
        "decision_id": "01990000-0000-7000-8000-000000000002",
        "site_id": "proxy.forward.body.original",
        "plane": "proxy",
        "transport": "forward",
        "location": "body",
        "view": "original",
        "boundary": "upstream_request",
        "phase": "intent",
        "destination_kind": "network",
        "destination_ref": "api.vendor.example",
        "pattern_class": "configured",
        "rule_id": "configured.sample_rule",
        "finding_disposition": "observe",
        "planned_byte_form": "original",
        "authorization": {"kind": "none"},
        "persistence_policy": "required_before_action"
    })
}

fn observed(intent: &Value) -> Value {
    let mut value = intent.clone();
    value["phase"] = json!("outcome");
    value["outcome"] = json!({"release":"complete", "byte_form":"original"});
    value
}

fn fallback() -> Value {
    json!({"reason":"no_safe_raw_span", "policy_ref":"fallback.sample", "policy_origin":"operator"})
}

#[test]
fn frozen_go_model_fixtures_and_pairings_match() {
    let directory = common::repo_root().join("internal/egressevidence/testdata/decision-v1");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(directory.join("manifest.json")).unwrap())
            .unwrap();
    let mut decisions = std::collections::HashMap::new();
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["id"].as_str().unwrap();
        let raw = fs::read_to_string(directory.join(fixture["file"].as_str().unwrap())).unwrap();
        let value: Value = serde_json::from_str(&raw).unwrap();
        // Parsed-value validation cannot recover duplicate source keys. Apply
        // its documented raw-parser prerequisite before checking the model.
        let source_valid = pipelock_verifier_rs::util::reject_duplicate_keys(&raw).is_ok();
        assert_eq!(
            source_valid && validate_decision(&value).is_ok(),
            fixture["valid"].as_bool().unwrap(),
            "{name}"
        );
        decisions.insert(name, value);
    }
    for fixture in manifest["fixtures"].as_array().unwrap() {
        if let Some(intent_id) = fixture["intent_id"].as_str() {
            validate_outcome_of(
                &decisions[fixture["id"].as_str().unwrap()],
                &decisions[intent_id],
            )
            .unwrap();
        }
    }
}

#[test]
fn shared_signed_corpus_matches_go() {
    let directory = common::repo_root().join("sdk/conformance/testdata/secret-egress-v1");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(directory.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 1);
    assert!(!manifest["cases"].as_array().unwrap().is_empty());
    let key = manifest["public_key_hex"].as_str().unwrap();
    for fixture in manifest["cases"].as_array().unwrap() {
        let path = directory.join(fixture["file"].as_str().unwrap());
        let result = run_receipt(path.to_str().unwrap(), key, false);
        let valid = result.as_ref().is_ok_and(|report| report.valid);
        assert_eq!(
            valid,
            fixture["valid"].as_bool().unwrap(),
            "{}: {result:?}",
            fixture["name"]
        );
    }
}

#[test]
fn mandatory_fields_reject_missing_null_and_case_aliases() {
    let original = decision();
    validate_decision(&original).unwrap();
    for key in original.as_object().unwrap().keys() {
        for form in ["missing", "null", "alias", "extra_alias"] {
            let mut changed = original.clone();
            let map = changed.as_object_mut().unwrap();
            let value = map.remove(key).unwrap();
            match form {
                "missing" => {}
                "null" => {
                    map.insert(key.clone(), Value::Null);
                }
                "alias" => {
                    map.insert(key.to_uppercase(), value);
                }
                _ => {
                    map.insert(key.clone(), value.clone());
                    map.insert(key.to_uppercase(), value);
                }
            }
            assert!(validate_decision(&changed).is_err(), "{key} {form}");
        }
    }
    for value in [Value::Null, json!([]), json!(1), json!("decision")] {
        assert!(validate_decision(&value).is_err());
    }
    for value in [
        json!(0),
        json!(2),
        json!(1.0),
        json!("1"),
        json!(-1),
        json!(true),
    ] {
        let mut changed = original.clone();
        changed["version"] = value;
        assert!(validate_decision(&changed).is_err());
    }
}

#[test]
fn references_are_bounded_and_ids_are_canonical_distinct_uuids() {
    for field in ["site_id", "rule_id"] {
        for value in ["", "has whitespace", "path/value", "é", &"a".repeat(129)] {
            let mut changed = decision();
            changed[field] = json!(value);
            assert!(validate_decision(&changed).is_err(), "{field} {value}");
        }
        let mut valid = decision();
        valid[field] = json!("a".repeat(128));
        validate_decision(&valid).unwrap();
        valid[field] = json!("A.b_C-d:2");
        validate_decision(&valid).unwrap();
    }
    for value in [
        "",
        "uuid",
        "0199000A-0000-7000-8000-000000000001",
        "01990000-0000-0000-8000-000000000001",
        "01990000-0000-9000-8000-000000000001",
        "01990000-0000-7000-7000-000000000001",
        "01990000_0000-7000-8000-000000000001",
    ] {
        for field in ["action_id", "decision_id"] {
            let mut changed = decision();
            changed[field] = json!(value);
            assert!(validate_decision(&changed).is_err(), "{field}: {value}");
        }
    }
    let mut changed = decision();
    changed["decision_id"] = changed["action_id"].clone();
    assert!(validate_decision(&changed).is_err());
}

#[test]
fn transports_and_boundaries_match_the_frozen_category_matrix() {
    for transport in [
        "fetch",
        "forward",
        "connect",
        "intercept",
        "reverse",
        "websocket",
        "mcp_stdio",
        "mcp_http_upstream",
        "mcp_http_listener",
        "mcp_ws",
        "mcp_http",
        "mcp_websocket",
        "agent_hook",
        "future",
    ] {
        for boundary in [
            "upstream_request",
            "upstream_frame",
            "tunnel_admission",
            "tool_dispatch",
            "hook_decision",
            "future",
        ] {
            let expected = match transport {
                "fetch" | "forward" | "intercept" | "reverse" => boundary == "upstream_request",
                "connect" => boundary == "tunnel_admission",
                "websocket" => matches!(boundary, "upstream_request" | "upstream_frame"),
                "mcp_stdio" | "mcp_http_upstream" | "mcp_http_listener" | "mcp_ws" => {
                    matches!(boundary, "upstream_request" | "tool_dispatch")
                }
                _ => false,
            };
            let mut value = decision();
            value["transport"] = json!(transport);
            value["boundary"] = json!(boundary);
            if transport == "mcp_stdio" {
                value["destination_kind"] = json!("local_process");
                value["destination_ref"] = json!("mcp.sample_upstream");
            }
            assert_eq!(
                validate_decision(&value).is_ok(),
                expected,
                "{transport}/{boundary}"
            );
        }
    }
    for plane in ["hook", "future"] {
        let mut value = decision();
        value["plane"] = json!(plane);
        assert!(validate_decision(&value).is_err());
    }
    for (field, values) in [
        (
            "location",
            vec![
                "url",
                "header",
                "body",
                "tool_arguments",
                "envelope",
                "frame",
            ],
        ),
        (
            "view",
            vec![
                "original",
                "normalized",
                "post_transform",
                "reassembled",
                "authorization",
            ],
        ),
        (
            "persistence_policy",
            vec!["required_before_action", "best_effort"],
        ),
    ] {
        for value in values {
            let mut d = decision();
            d[field] = json!(value);
            validate_decision(&d).unwrap();
        }
        let mut d = decision();
        d[field] = json!("future");
        assert!(validate_decision(&d).is_err(), "{field}");
    }
}

#[test]
fn canonical_network_references_match_go_without_network_access() {
    for host in [
        "api.vendor.example",
        "xn--bcher-kva.example",
        "192.0.2.1",
        "2001:db8::1",
        "::",
        "::1",
        "::c000:201",
        "a",
        "123.vendor.example",
        "0xdeadbeef.vendor.example",
        "0xg",
        "0x.vendor.example",
        "999.999.vendor.example",
    ] {
        let mut value = decision();
        value["destination_ref"] = json!(host);
        validate_decision(&value).unwrap_or_else(|e| panic!("{host}: {e}"));
    }
    for host in [
        "",
        "API.vendor.example",
        "api.vendor.example.",
        "https://api.vendor.example",
        "api.vendor.example/path",
        "api.vendor.example:443",
        "sample@api.vendor.example",
        "api..vendor.example",
        "-api.vendor.example",
        "api-.vendor.example",
        "bücher.example",
        "[2001:db8::1]",
        "2001:0db8::1",
        "2001:db8:0:0:0:0:0:1",
        "fe80::1%eth0",
        "::ffff:192.0.2.1",
        "::ffff:c000:201",
        "192.0.2.1.",
        "0300.0.2.1",
        "0xc0.0.2.1",
        "192.1",
        "192.0.513",
        "3221225985",
        "0xc0000201",
        "0",
        "00",
        "0001",
        "192.000.2.1",
        "0x100000000",
        "4294967296",
        "999.999.999.999",
        "08",
        "1.2.3.4.5",
        "vendor.123",
        "vendor.0xdeadbeef",
        "vendor.0x",
        "0x",
        "+1",
        &"a".repeat(254),
        &format!("{}.example", "a".repeat(64)),
    ] {
        let mut value = decision();
        value["destination_ref"] = json!(host);
        assert!(validate_decision(&value).is_err(), "{host}");
    }
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let mut value = decision();
    value["destination_ref"] = json!(host);
    validate_decision(&value).unwrap();
}

#[test]
fn local_process_references_require_stdio_and_symbolic_identity() {
    for transport in [
        "mcp_stdio",
        "mcp_http_upstream",
        "mcp_http_listener",
        "mcp_ws",
        "mcp_http",
        "mcp_websocket",
        "forward",
    ] {
        let mut value = decision();
        value["transport"] = json!(transport);
        value["destination_kind"] = json!("local_process");
        value["destination_ref"] = json!("mcp.sample_upstream");
        assert_eq!(validate_decision(&value).is_ok(), transport == "mcp_stdio");
        value["destination_kind"] = json!("network");
        value["destination_ref"] = json!("api.vendor.example");
        assert_eq!(
            validate_decision(&value).is_ok(),
            !matches!(transport, "mcp_stdio" | "mcp_http" | "mcp_websocket")
        );
        value["destination_kind"] = json!("local_process");
        value["destination_ref"] = json!("sample --argument");
        assert!(validate_decision(&value).is_err());
    }
    let mut value = decision();
    value["destination_kind"] = json!("future");
    assert!(validate_decision(&value).is_err());
}

#[test]
fn core_handling_is_not_inherently_invalid_and_plans_remain_typed() {
    for class in ["core_floor", "configured", "future"] {
        for finding in [
            "block",
            "redact",
            "observe",
            "authorize",
            "exempt",
            "future",
        ] {
            for planned in ["none", "original", "transformed", "unknown"] {
                let mut value = decision();
                value["pattern_class"] = json!(class);
                value["finding_disposition"] = json!(finding);
                value["planned_byte_form"] = json!(planned);
                if matches!(finding, "authorize" | "exempt") {
                    value["authorization"] = json!({"kind":if finding == "authorize" {"authorization"} else {"exemption"}, "ref":"authority.sample", "origin":"builtin"});
                }
                let expected = class != "future"
                    && planned != "unknown"
                    && match finding {
                        "block" => planned == "none",
                        "redact" => planned != "original",
                        "observe" | "authorize" | "exempt" => true,
                        _ => false,
                    };
                assert_eq!(
                    validate_decision(&value).is_ok(),
                    expected,
                    "{class}/{finding}/{planned}"
                );
            }
        }
    }
}

#[test]
fn authority_objects_require_named_origin_and_reject_unused_fields() {
    for origin in ["builtin", "operator"] {
        for (finding, kind) in [("authorize", "authorization"), ("exempt", "exemption")] {
            let mut d = decision();
            d["finding_disposition"] = json!(finding);
            d["authorization"] = json!({"kind":kind, "ref":"policy.sample", "origin":origin});
            validate_decision(&d).unwrap();
            for field in ["kind", "ref", "origin"] {
                for replacement in [
                    None,
                    Some(Value::Null),
                    Some(json!("")),
                    Some(json!("future value")),
                ] {
                    let mut changed = d.clone();
                    let authority = changed["authorization"].as_object_mut().unwrap();
                    if let Some(value) = replacement {
                        authority.insert(field.to_string(), value);
                    } else {
                        authority.remove(field);
                    }
                    assert!(validate_decision(&changed).is_err(), "{finding}/{field}");
                }
            }
        }
    }
    for authority in [
        json!({"kind":"none","ref":""}),
        json!({"kind":"none","origin":""}),
        json!({"Kind":"none"}),
        json!({"kind":"none","persisted":true}),
        json!({}),
        Value::Null,
        json!([]),
        json!({"kind":"authorization","ref":"policy.sample","origin":"operator"}),
    ] {
        let mut value = decision();
        value["authorization"] = authority;
        assert!(validate_decision(&value).is_err());
    }
}

#[test]
fn rewrite_fallback_is_optional_but_strict_when_present() {
    for reason in [
        "unparseable_body",
        "no_safe_raw_span",
        "unsupported_encoding",
        "unsupported_shape",
        "opaque_arguments",
    ] {
        for origin in ["builtin", "operator"] {
            let mut value = decision();
            value["rewrite_fallback"] =
                json!({"reason":reason,"policy_ref":"fallback.sample","policy_origin":origin});
            validate_decision(&value).unwrap();
        }
    }
    for field in ["reason", "policy_ref", "policy_origin"] {
        for replacement in [
            None,
            Some(Value::Null),
            Some(json!("")),
            Some(json!("future value")),
        ] {
            let mut value = decision();
            value["rewrite_fallback"] = fallback();
            let f = value["rewrite_fallback"].as_object_mut().unwrap();
            if let Some(value) = replacement {
                f.insert(field.to_string(), value);
            } else {
                f.remove(field);
            }
            assert!(validate_decision(&value).is_err(), "{field}");
        }
    }
    for f in [
        Value::Null,
        json!([]),
        json!({"Reason":"no_safe_raw_span","policy_ref":"fallback.sample","policy_origin":"operator"}),
        json!({"reason":"no_safe_raw_span","policy_ref":"fallback.sample","policy_origin":"operator","fsync_success":true}),
    ] {
        let mut value = decision();
        value["rewrite_fallback"] = f;
        assert!(validate_decision(&value).is_err());
    }
}

#[test]
fn observed_outcome_matrix_does_not_erase_truthful_contradictions() {
    let mut intent = decision();
    intent["pattern_class"] = json!("core_floor");
    intent["finding_disposition"] = json!("block");
    intent["planned_byte_form"] = json!("none");
    for release in ["none", "partial", "complete", "unknown", "future"] {
        for form in ["none", "original", "transformed", "unknown", "future"] {
            let mut value = observed(&intent);
            value["outcome"] = json!({"release":release,"byte_form":form});
            let expected = release != "future"
                && form != "future"
                && ((release == "none") == (form == "none"));
            assert_eq!(
                validate_decision(&value).is_ok(),
                expected,
                "{release}/{form}"
            );
            assert_eq!(validate_outcome_of(&value, &intent).is_ok(), expected);
        }
    }
    for outcome in [
        Value::Null,
        json!({}),
        json!({"release":"complete"}),
        json!({"release":"complete","byte_form":null}),
        json!({"release":"complete","Byte_form":"original"}),
        json!({"release":"complete","byte_form":"original","persisted":true}),
    ] {
        let mut value = observed(&intent);
        value["outcome"] = outcome;
        assert!(validate_decision(&value).is_err());
    }
    let mut invalid = observed(&intent);
    invalid.as_object_mut().unwrap().remove("outcome");
    assert!(validate_decision(&invalid).is_err());
    invalid = observed(&intent);
    invalid["phase"] = json!("intent");
    assert!(validate_decision(&invalid).is_err());
    invalid["phase"] = json!("future");
    assert!(validate_decision(&invalid).is_err());
}

#[test]
fn pairings_compare_values_and_all_selected_facts() {
    let mut intent = decision();
    intent["rewrite_fallback"] = fallback();
    let mut outcome = observed(&intent);
    outcome["rewrite_fallback"] = json!({"policy_origin":"operator","policy_ref":"fallback.sample","reason":"no_safe_raw_span"});
    validate_outcome_of(&outcome, &intent).unwrap();
    for (field, value) in [
        ("action_id", json!("01990000-0000-7000-8000-000000000003")),
        ("decision_id", json!("01990000-0000-7000-8000-000000000004")),
        ("site_id", json!("proxy.forward.body.normalized")),
        ("rule_id", json!("configured.other")),
        ("persistence_policy", json!("best_effort")),
        ("planned_byte_form", json!("transformed")),
        ("destination_ref", json!("other.vendor.example")),
        ("view", json!("normalized")),
        ("pattern_class", json!("core_floor")),
        ("transport", json!("fetch")),
        ("location", json!("header")),
    ] {
        let mut changed = outcome.clone();
        changed[field] = value;
        validate_decision(&changed).unwrap();
        assert!(validate_outcome_of(&changed, &intent).is_err(), "{field}");
    }
    for field in ["reason", "policy_ref", "policy_origin"] {
        let mut changed = outcome.clone();
        changed["rewrite_fallback"][field] = json!(match field {
            "reason" => "opaque_arguments",
            "policy_ref" => "fallback.other",
            _ => "builtin",
        });
        validate_decision(&changed).unwrap();
        assert!(validate_outcome_of(&changed, &intent).is_err());
    }
    let mut no_fallback = outcome.clone();
    no_fallback
        .as_object_mut()
        .unwrap()
        .remove("rewrite_fallback");
    assert!(validate_outcome_of(&no_fallback, &intent).is_err());
    assert!(validate_outcome_of(&intent, &intent).is_err());
    assert!(validate_outcome_of(&outcome, &outcome).is_err());
    let mut invalid = intent.clone();
    invalid["version"] = json!(0);
    assert!(validate_outcome_of(&outcome, &invalid).is_err());
    assert!(validate_outcome_of(&invalid, &intent).is_err());
}

#[test]
fn registry_digest_is_exact_but_does_not_claim_membership() {
    let mut payload =
        json!({"registry_hash":format!("sha256:{}", "a".repeat(64)), "decision":decision()});
    validate_payload(&payload).unwrap();
    payload["decision"]["site_id"] = json!("unregistered.but.structurally_valid");
    validate_payload(&payload).unwrap();
    for digest in [
        "",
        &"a".repeat(64),
        &format!("sha256:{}", "a".repeat(63)),
        &format!("sha256:{}", "A".repeat(64)),
        &format!("sha256:{}", "g".repeat(64)),
    ] {
        let mut changed = payload.clone();
        changed["registry_hash"] = json!(digest);
        assert!(validate_payload(&changed).is_err());
    }
    for field in ["registry_hash", "decision"] {
        for replacement in [None, Some(Value::Null)] {
            let mut changed = payload.clone();
            let map = changed.as_object_mut().unwrap();
            if let Some(v) = replacement {
                map.insert(field.to_string(), v);
            } else {
                map.remove(field);
            }
            assert!(validate_payload(&changed).is_err());
        }
    }
    payload["registry_version"] = json!(1);
    assert!(validate_payload(&payload).is_err());
}

#[test]
fn required_critical_feature_is_paired_only_with_its_payload_kind() {
    let directory = common::repo_root().join("sdk/conformance/testdata/secret-egress-v1");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(directory.join("manifest.json")).unwrap())
            .unwrap();
    let fixture = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["valid"] == true)
        .unwrap();
    let receipt: Value = serde_json::from_str(
        &fs::read_to_string(directory.join(fixture["file"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    normalize_evidence_receipt(&receipt).unwrap();
    for crit in [
        json!([]),
        json!(["canonicalization"]),
        json!(["secret_egress_decision_v1"]),
        json!([
            "canonicalization",
            "secret_egress_decision_v1",
            "source_spans"
        ]),
        json!([
            "canonicalization",
            "secret_egress_decision_v1",
            "secret_egress_decision_v1"
        ]),
        json!(["canonicalization", "future"]),
    ] {
        let mut changed = receipt.clone();
        changed["crit"] = crit;
        assert!(normalize_evidence_receipt(&changed).is_err());
    }
    let mut changed = receipt.clone();
    changed["payload_kind"] = json!("proxy_decision");
    assert!(normalize_evidence_receipt(&changed).is_err());
    for field in ["action_id", "decision_id"] {
        let mut changed = receipt.clone();
        changed["event_id"] = changed["payload"]["decision"][field].clone();
        assert!(normalize_evidence_receipt(&changed).is_err());
    }
    let mut changed = receipt.clone();
    changed["signature"]["key_purpose"] = json!("registry-signing");
    assert!(normalize_evidence_receipt(&changed).is_err());
    changed = receipt;
    changed.as_object_mut().unwrap().remove("policy_hash");
    assert!(normalize_evidence_receipt(&changed).is_err());
}

fn signed_receipt() -> (Value, String) {
    use ed25519_dalek::{Signer, SigningKey};
    use pipelock_verifier_rs::canonical::canonicalize_jcs_value;
    // Deterministic fixture-only key; no production credential material.
    let key = SigningKey::from_bytes(&[42; 32]);
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let mut receipt = json!({
        "record_type":"evidence_receipt_v2",
        "receipt_version":2,
        "payload_kind":"secret_egress_decision_v1",
        "canonicalization":{
            "jcs_profile":"pipelock-jcs-rfc8785-nfc-v1",
            "jcs_version":"rfc8785", "hash_alg":"sha256", "sig_alg":"ed25519",
            "redaction_ruleset_id":"pipelock-transform-v1", "redaction_ruleset_version":"1",
            "redaction_ruleset_hash":"sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e"
        },
        "crit":["canonicalization","secret_egress_decision_v1"],
        "event_id":"01990000-0000-7000-8000-000000000003",
        "timestamp":"2026-09-30T12:00:00Z",
        "chain_seq":0, "chain_prev_hash":"genesis",
        "policy_hash":format!("sha256:{}", "a".repeat(64)),
        "payload":{"registry_hash":format!("sha256:{}", "b".repeat(64)), "decision":decision()},
        "signature":{"signer_key_id":"", "key_purpose":"", "algorithm":"", "signature":""}
    });
    let signature = key.sign(&canonicalize_jcs_value(&receipt).unwrap());
    receipt["signature"] = json!({"signer_key_id":public_key,"key_purpose":"receipt-signing","algorithm":"ed25519","signature":format!("ed25519:{}", hex::encode(signature.to_bytes()))});
    (receipt, public_key)
}

struct TempFixture(std::path::PathBuf);
impl TempFixture {
    fn new(text: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pipelock-secret-egress-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        Self::create(path, text).unwrap()
    }

    fn create(path: std::path::PathBuf, text: &str) -> std::io::Result<Self> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let fixture = Self(path);
        let result = file.write_all(text.as_bytes());
        drop(file);
        result?;
        Ok(fixture)
    }
}
impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn temp_fixture_preserves_existing_file_and_cleans_its_own_file() {
    let fixture = TempFixture::new("benign original fixture");
    let path = fixture.0.clone();
    let error = TempFixture::create(path.clone(), "replacement")
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "benign original fixture"
    );
    drop(fixture);
    assert!(!path.exists());
}

#[test]
fn independent_signed_receipt_is_verified_without_claiming_compliance() {
    let (receipt, key) = signed_receipt();
    for raw in [
        receipt.to_string(),
        serde_json::to_string_pretty(&receipt).unwrap(),
        receipt
            .to_string()
            .replace("\"decision\":", "\"deci\\u0073ion\":"),
    ] {
        let fixture = TempFixture::new(&raw);
        let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
        assert!(report.valid, "{:?}", report.error);
        assert_eq!(report.transport.as_deref(), Some("forward"));
        assert_eq!(report.verdict, None);
        let action_id = receipt["payload"]["decision"]["action_id"].as_str();
        assert_ne!(action_id, receipt["event_id"].as_str());
        assert_eq!(report.action_id.as_deref(), action_id);
        let unpinned = run_receipt(fixture.0.to_str().unwrap(), "", false).unwrap();
        assert!(!unpinned.valid);
        assert_eq!(unpinned.unpinned, Some(true));
    }
    let mut tampered = receipt;
    tampered["payload"]["decision"]["rule_id"] = json!("configured.other");
    let fixture = TempFixture::new(&tampered.to_string());
    let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
    assert!(!report.valid);
    assert!(report
        .error
        .unwrap()
        .contains("signature verification failed"));
}

#[test]
fn raw_nested_decision_bound_applies_to_receipts_and_recorder_entries() {
    use pipelock_verifier_rs::rawjson::object_member_span;
    use pipelock_verifier_rs::recorder::extract_receipts;
    let (receipt, key) = signed_receipt();
    let raw = receipt.to_string();
    let (payload_start, _) = object_member_span(&raw, 0, "payload").unwrap();
    let (start, end) = object_member_span(&raw, payload_start, "decision").unwrap();
    for size in [16 * 1024, 16 * 1024 + 1] {
        let mut padded = raw.clone();
        padded.insert_str(start + 1, &" ".repeat(size - (end - start)));
        let fixture = TempFixture::new(&padded);
        let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
        assert_eq!(report.valid, size == 16 * 1024, "{:?}", report.error);
        if !report.valid {
            assert_eq!(report.action_id, None);
            assert!(report.error.unwrap().contains("decision size"));
        }
        let line = format!(r#"{{"v":2,"type":"evidence_receipt","detail":{padded}}}"#);
        let fixture = TempFixture::new(&line);
        assert_eq!(extract_receipts(&fixture.0).is_ok(), size == 16 * 1024);
    }
}

#[test]
fn raw_duplicate_decision_members_are_rejected_before_metadata() {
    let (receipt, key) = signed_receipt();
    let raw = receipt.to_string();
    for (from, to) in [
        (r#""version":1"#, r#""version":1,"version":1"#),
        (r#""kind":"none""#, r#""kind":"none","kind":"none""#),
        (r#""kind":"none""#, r#""kind":"none","\u006bind":"none""#),
    ] {
        let duplicate = raw.replacen(from, to, 1);
        assert_ne!(raw, duplicate);
        let fixture = TempFixture::new(&duplicate);
        let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
        assert!(!report.valid);
        assert_eq!(report.action_id, None);
        assert!(report.error.unwrap().contains("duplicate object key"));
    }
}

#[test]
fn shared_registry_manifest_jcs_digest_matches_go() {
    use pipelock_verifier_rs::canonical::canonicalize_jcs_value;
    use pipelock_verifier_rs::util::sha256_hex;
    let directory = common::repo_root().join("sdk/conformance/testdata/secret-egress-v1");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(directory.join("manifest.json")).unwrap())
            .unwrap();
    let registry: Value = serde_json::from_str(
        &fs::read_to_string(directory.join(manifest["registry_manifest"].as_str().unwrap()))
            .unwrap(),
    )
    .unwrap();
    let digest = format!(
        "sha256:{}",
        sha256_hex(&canonicalize_jcs_value(&registry).unwrap())
    );
    assert_eq!(manifest["registry_hash"], digest);
}

#[test]
fn new_kind_envelope_requires_exact_non_null_fields_at_every_level() {
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, _) = signed_receipt();
    for object_path in ["", "/canonicalization", "/signature"] {
        let fields: Vec<_> = receipt
            .pointer(object_path)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for field in fields {
            for form in ["missing", "null", "case_alias", "unknown"] {
                let mut changed = receipt.clone();
                let map = changed
                    .pointer_mut(object_path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                let old = map.remove(&field).unwrap();
                match form {
                    "missing" => {}
                    "null" => {
                        map.insert(field.clone(), Value::Null);
                    }
                    "case_alias" => {
                        map.insert(field.to_uppercase(), old);
                    }
                    _ => {
                        map.insert(field.clone(), old);
                        map.insert("undeclared_field".to_string(), json!(true));
                    }
                }
                // Both payload_kind and crit select the strict guard, so either
                // required selector can be missing or aliased without bypassing it.
                assert!(
                    normalize_evidence_receipt(&changed).is_err(),
                    "{object_path}/{field}/{form}"
                );
                assert!(
                    parse_json_text(&changed.to_string(), "fixture").is_err(),
                    "raw {object_path}/{field}/{form}"
                );
            }
        }
    }
}

#[test]
fn new_kind_optional_fields_have_explicit_omission_and_type_rules() {
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, _) = signed_receipt();
    for field in [
        "principal",
        "actor",
        "active_manifest_hash",
        "contract_hash",
        "selector_id",
    ] {
        for valid in [false, true] {
            let mut value = receipt.clone();
            value[field] = if valid {
                json!("fixture-reference")
            } else {
                json!("")
            };
            assert_eq!(normalize_evidence_receipt(&value).is_ok(), valid, "{field}");
            assert_eq!(
                parse_json_text(&value.to_string(), "fixture").is_ok(),
                valid
            );
        }
        for bad in [Value::Null, json!(false), json!(0), json!([]), json!({})] {
            let mut value = receipt.clone();
            value[field] = bad;
            assert!(normalize_evidence_receipt(&value).is_err());
            assert!(parse_json_text(&value.to_string(), "fixture").is_err());
        }
    }
    for (delegation, valid) in [
        (json!(["principal-a", "principal-b"]), true),
        (json!([]), false),
        (json!([""]), false),
        (json!([null]), false),
        (json!([1]), false),
        (json!("principal-a"), false),
        (Value::Null, false),
    ] {
        let mut value = receipt.clone();
        value["delegation_chain"] = delegation;
        assert_eq!(normalize_evidence_receipt(&value).is_ok(), valid);
        assert_eq!(
            parse_json_text(&value.to_string(), "fixture").is_ok(),
            valid
        );
    }
    for (generation, valid) in [
        (json!(1), true),
        (json!(9_007_199_254_740_991_u64), true),
        (json!(0), false),
        (json!(-1), false),
        (json!(9_007_199_254_740_992_u64), false),
        (json!(1.0), false),
        (json!("1"), false),
        (Value::Null, false),
    ] {
        let mut value = receipt.clone();
        value["contract_generation"] = generation;
        assert_eq!(normalize_evidence_receipt(&value).is_ok(), valid);
        assert_eq!(
            parse_json_text(&value.to_string(), "fixture").is_ok(),
            valid
        );
    }
}

#[test]
fn new_kind_raw_numeric_tokens_are_canonical_at_receipt_and_recorder_entries() {
    use pipelock_verifier_rs::recorder::extract_receipts;
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, key) = signed_receipt();
    for (field, original, tokens) in [
        (
            "receipt_version",
            "2",
            vec!["2.0", "2e0", "2E+0", "-2", "true", "\"2\""],
        ),
        (
            "chain_seq",
            "0",
            vec!["-0", "0.0", "0e0", "1e0", "9007199254740992", "\"0\""],
        ),
        (
            "contract_generation",
            "1",
            vec!["0", "-0", "1.0", "1e0", "9007199254740992", "null"],
        ),
    ] {
        let mut base = receipt.clone();
        if field == "contract_generation" {
            base[field] = json!(1);
        }
        let raw = base.to_string();
        for token in tokens {
            let changed = raw.replacen(
                &format!("\"{field}\":{original}"),
                &format!("\"{field}\":{token}"),
                1,
            );
            assert_ne!(raw, changed);
            assert!(
                parse_json_text(&changed, "fixture").is_err(),
                "{field}={token}"
            );
            let fixture = TempFixture::new(&changed);
            let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
            assert!(!report.valid);
            assert_eq!(report.action_id, None);
            let line = format!(r#"{{"v":2,"type":"evidence_receipt","detail":{changed}}}"#);
            let fixture = TempFixture::new(&line);
            assert!(
                extract_receipts(&fixture.0).is_err(),
                "recorder {field}={token}"
            );
        }
    }
    for sequence in [0_u64, 1, 9_007_199_254_740_991] {
        let mut value = receipt.clone();
        value["chain_seq"] = json!(sequence);
        normalize_evidence_receipt(&value).unwrap();
        parse_json_text(&value.to_string(), "fixture").unwrap();
    }
}

#[test]
fn raw_selectors_cannot_hide_new_kind_behind_case_aliases_or_duplicate_values() {
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, _) = signed_receipt();
    for alias in ["Payload_kind", "PAYLOAD_KIND", "payload_Kind"] {
        let mut value = receipt.clone();
        value.as_object_mut().unwrap().remove("crit");
        let kind = value
            .as_object_mut()
            .unwrap()
            .remove("payload_kind")
            .unwrap();
        value[alias] = kind;
        assert!(
            parse_json_text(&value.to_string(), "fixture").is_err(),
            "{alias}"
        );
    }
    let mut value = receipt.clone();
    value.as_object_mut().unwrap().remove("payload_kind");
    let crit = value.as_object_mut().unwrap().remove("crit").unwrap();
    value["CRIT"] = crit;
    assert!(parse_json_text(&value.to_string(), "fixture").is_err());
    value["CRIT"] = json!(["secret_egress_decision_v1", null]);
    assert!(parse_json_text(&value.to_string(), "fixture").is_err());
    let mut value = receipt;
    value.as_object_mut().unwrap().remove("crit");
    let raw = value.to_string();
    let duplicate = raw.replacen(
        r#""payload_kind":"secret_egress_decision_v1""#,
        r#""payload_kind":"secret_egress_decision_v1","payload_kind":"proxy_decision""#,
        1,
    );
    assert_ne!(raw, duplicate);
    assert!(parse_json_text(&duplicate, "fixture").is_err());
    let escaped = duplicate.replace(
        "secret_egress_decision_v1",
        "\\u0073ecret_egress_decision_v1",
    );
    assert!(parse_json_text(&escaped, "fixture").is_err());
}

#[test]
fn new_kind_timestamps_use_canonical_utc_rfc3339nano() {
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, _) = signed_receipt();
    for (timestamp, expected) in [
        ("2026-09-30T12:34:56Z", true),
        ("2026-09-30T12:34:56.1Z", true),
        ("2026-09-30T12:34:56.000000001Z", true),
        ("2026-09-30T12:34:56.123456789Z", true),
        ("2000-02-29T23:59:59Z", true),
        ("0000-02-29T00:00:00Z", true),
        ("0001-01-01T00:00:00.1Z", true),
        ("9999-12-31T23:59:59.999999999Z", true),
        ("0001-01-01T00:00:00Z", false),
        ("1900-02-29T00:00:00Z", false),
        ("2026-02-29T00:00:00Z", false),
        ("2026-04-31T00:00:00Z", false),
        ("2026-00-01T00:00:00Z", false),
        ("2026-13-01T00:00:00Z", false),
        ("2026-01-00T00:00:00Z", false),
        ("2026-01-32T00:00:00Z", false),
        ("2026-01-01T24:00:00Z", false),
        ("2026-01-01T00:60:00Z", false),
        ("2026-01-01T00:00:60Z", false),
        ("2026-01-01T00:00:00.0Z", false),
        ("2026-01-01T00:00:00.10Z", false),
        ("2026-01-01T00:00:00.Z", false),
        ("2026-01-01T00:00:00.1234567891Z", false),
        ("2026-01-01T00:00:00,1Z", false),
        ("2026-01-01T00:00:00+00:00", false),
        ("2026-01-01T00:00:00-04:00", false),
        ("2026-01-01t00:00:00z", false),
        ("2026-1-01T00:00:00Z", false),
        ("2026-01-01T0:00:00Z", false),
        ("10000-01-01T00:00:00Z", false),
        ("2026-01-01T00:00:00Z ", false),
        ("2026-01-01T00:00:00.xZ", false),
        ("not-a-timestamp", false),
        ("", false),
    ] {
        let mut value = receipt.clone();
        value["timestamp"] = json!(timestamp);
        assert_eq!(
            normalize_evidence_receipt(&value).is_ok(),
            expected,
            "typed {timestamp}"
        );
        assert_eq!(
            parse_json_text(&value.to_string(), "fixture").is_ok(),
            expected,
            "raw {timestamp}"
        );
    }
}

#[test]
fn older_payload_kinds_retain_their_existing_envelope_semantics() {
    use pipelock_verifier_rs::util::parse_json_text;
    let (mut receipt, _) = signed_receipt();
    receipt["payload_kind"] = json!("proxy_decision");
    receipt["crit"] = json!(["canonicalization"]);
    receipt["payload"] = json!({"action_type":"write","target":"api.vendor.example","verdict":"block","transport":"http","policy_sources":["config"],"winning_source":"config"});
    receipt["timestamp"] = json!("legacy-nonempty-timestamp");
    receipt["actor"] = json!("");
    receipt["principal"] = Value::Null;
    receipt["delegation_chain"] = json!([]);
    receipt["contract_generation"] = json!(0);
    normalize_evidence_receipt(&receipt).unwrap();
    parse_json_text(&receipt.to_string(), "fixture").unwrap();
}

#[test]
fn new_kind_raw_timestamp_token_is_unescaped_ascii() {
    use pipelock_verifier_rs::recorder::extract_receipts;
    use pipelock_verifier_rs::util::parse_json_text;
    let (receipt, key) = signed_receipt();
    let raw = receipt.to_string();
    let fixture = TempFixture::new(&raw);
    assert!(
        run_receipt(fixture.0.to_str().unwrap(), &key, false)
            .unwrap()
            .valid
    );
    let escaped = raw.replacen("2026-09-30T12:00:00Z", r"\u0032026-09-30T12:00:00Z", 1);
    assert_ne!(raw, escaped);
    // The decoded timestamp and JCS signing preimage are unchanged. The
    // rejection is the candidate wire encoding rule, not signature failure.
    let decoded: Value = serde_json::from_str(&escaped).unwrap();
    assert_eq!(decoded["timestamp"], receipt["timestamp"]);
    assert!(parse_json_text(&escaped, "fixture").is_err());
    let fixture = TempFixture::new(&escaped);
    let report = run_receipt(fixture.0.to_str().unwrap(), &key, false).unwrap();
    assert!(!report.valid);
    assert_eq!(report.action_id, None);
    assert!(report.error.unwrap().contains("unescaped ASCII"));
    let line = format!(r#"{{"v":2,"type":"evidence_receipt","detail":{escaped}}}"#);
    let fixture = TempFixture::new(&line);
    assert!(extract_receipts(&fixture.0).is_err());

    let mut legacy = receipt;
    legacy["payload_kind"] = json!("proxy_decision");
    legacy["crit"] = json!(["canonicalization"]);
    let legacy_raw =
        legacy
            .to_string()
            .replacen("2026-09-30T12:00:00Z", r"\u0032026-09-30T12:00:00Z", 1);
    parse_json_text(&legacy_raw, "legacy fixture").unwrap();
}

#[test]
fn new_kind_signature_text_has_one_lowercase_hex_spelling() {
    let (receipt, key) = signed_receipt();
    normalize_evidence_receipt(&receipt).unwrap();
    let signature = receipt["signature"]["signature"].as_str().unwrap();
    let hex = signature.strip_prefix("ed25519:").unwrap();
    for text in [
        format!("ed25519:{}", hex.to_uppercase()),
        format!("ed25519: {hex}"),
        format!("ed25519:{hex} "),
        format!("ED25519:{hex}"),
        format!("ed25519:{}", &hex[1..]),
        format!("ed25519:{hex}0"),
        format!("ed25519:{}g", &hex[..127]),
    ] {
        let mut changed = receipt.clone();
        changed["signature"]["signature"] = json!(text);
        assert!(normalize_evidence_receipt(&changed).is_err());
        let file = TempFixture::new(&changed.to_string());
        assert!(
            !run_receipt(file.0.to_str().unwrap(), &key, false).is_ok_and(|report| report.valid)
        );
    }
}

#[test]
fn redacted_destination_is_a_sum_type_not_a_shared_identity() {
    let mut redacted = decision();
    redacted.as_object_mut().unwrap().remove("destination_ref");
    redacted["destination_redaction"] = json!({"reason":"classified_sensitive"});
    validate_decision(&redacted).unwrap();
    validate_outcome_of(&observed(&redacted), &redacted).unwrap();
    let round_trip: Value = serde_json::from_str(&redacted.to_string()).unwrap();
    validate_outcome_of(&observed(&round_trip), &redacted).unwrap();

    let mut local = redacted.clone();
    local["transport"] = json!("mcp_stdio");
    local["boundary"] = json!("tool_dispatch");
    local["destination_kind"] = json!("local_process");
    validate_decision(&local).unwrap();
    local["destination_kind"] = json!("network");
    assert!(validate_decision(&local).is_err());

    for invalid in [
        Value::Null,
        json!({}),
        json!({"Reason":"classified_sensitive"}),
        json!({"reason":null}),
        json!({"reason":"unknown"}),
        json!({"reason":"classified_sensitive", "extra":true}),
    ] {
        let mut changed = redacted.clone();
        changed["destination_redaction"] = invalid;
        assert!(validate_decision(&changed).is_err());
    }
    for reference in [json!("api.vendor.example"), json!(""), Value::Null] {
        let mut both = redacted.clone();
        both["destination_ref"] = reference;
        assert!(validate_decision(&both).is_err());
    }
    let mut neither = redacted.clone();
    neither
        .as_object_mut()
        .unwrap()
        .remove("destination_redaction");
    assert!(validate_decision(&neither).is_err());
    let mut differently_attributed = observed(&redacted);
    differently_attributed["decision_id"] = json!("01990000-0000-7000-8000-000000000003");
    assert!(validate_outcome_of(&differently_attributed, &redacted).is_err());
    assert!(validate_outcome_of(&observed(&decision()), &redacted).is_err());
}

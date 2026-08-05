// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use pipelock_verifier_rs::provenance::{Recipe, PROFILE_DIGEST};
use serde_json::Value;
use std::fs;

const CORPUS: &str = "../../conformance/testdata/transform-profile/evidence-provenance-v1.json";

#[test]
fn unicode_normalization_tables_match_pinned_profile_version() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (15, 0, 0));
}

#[test]
fn evidence_provenance_shared_corpus() {
    let corpus: Value = serde_json::from_str(&fs::read_to_string(CORPUS).expect("read corpus"))
        .expect("parse corpus");
    assert_eq!(corpus["profile_digest"], PROFILE_DIGEST);
    for vector in corpus["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().unwrap_or("unnamed");
        let input = base64::engine::general_purpose::STANDARD
            .decode(vector["input_b64"].as_str().expect("input_b64"))
            .expect("input base64");
        let digest = vector
            .get("transform_profile_digest")
            .and_then(Value::as_str)
            .unwrap_or(PROFILE_DIGEST);
        let result = vector
            .get("recipe")
            .map(|recipe| Recipe::from_json(digest, recipe).and_then(|r| r.apply_bytes(&input)))
            .unwrap_or_else(|| {
                Recipe::from_json(digest, &Value::Array(vec![])).and_then(|r| r.apply_bytes(&input))
            });
        if let Some(want) = vector
            .get("want_error")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            assert!(result.unwrap_err().contains(want), "{id}");
        } else {
            let want = base64::engine::general_purpose::STANDARD
                .decode(vector["output_b64"].as_str().expect("output_b64"))
                .expect("output base64");
            assert_eq!(result.expect(id), want, "{id}");
        }
    }
}

#[test]
fn html_entity_decode_supports_full_html5_table_and_repeated_passes() {
    let recipe = Recipe::from_json(
        PROFILE_DIGEST,
        &serde_json::json!([{"kind": "html_entity_decode"}]),
    )
    .expect("recipe");
    assert_eq!(
        recipe
            .apply("&amp;CounterClockwiseContourIntegral;")
            .expect("decode"),
        "∳"
    );
}

#[test]
fn recipe_validation_rejects_malformed_operation_shapes() {
    for (operations, want) in [
        (serde_json::json!(null), "operations must be an array"),
        (serde_json::json!([null]), "operation must be an object"),
        (
            serde_json::json!([{"kind": "identity", "extra": 1}]),
            "unsupported extra",
        ),
        (
            serde_json::json!([{"kind": "url_component", "component": "port"}]),
            "unknown URL component",
        ),
        (
            serde_json::json!([{"kind": "url_component", "component": "path", "selector": "x"}]),
            "unsupported selector",
        ),
        (
            serde_json::json!([{"kind": "base64_decode_liberal", "alphabet": "other"}]),
            "unknown base64 alphabet",
        ),
        (
            serde_json::json!([{"kind": "encoded_token_normalize", "alphabet": "other"}]),
            "unknown encoded-token alphabet",
        ),
        (
            serde_json::json!([{"kind": "query_subsequence", "indices": [1, 1]}]),
            "strictly increasing",
        ),
        (
            serde_json::json!([{"kind": "encoded_run", "minimum_length": 0}]),
            "must be positive",
        ),
        (
            serde_json::json!([{"kind": "text_segment", "occurrence": -1}]),
            "must be a uint32",
        ),
        (
            serde_json::json!([{"kind": "base64_decode", "decode_padding": 1}]),
            "must be a boolean",
        ),
    ] {
        let error = Recipe::from_json(PROFILE_DIGEST, &operations).unwrap_err();
        assert!(error.contains(want), "{error:?} does not contain {want:?}");
    }
}

#[test]
fn url_component_surfaces_are_distinct() {
    let input = "https://api.vendor.example/a/b?x=y";
    for (component, want) in [
        ("url", input),
        ("hostname", "api.vendor.example"),
        ("path", "/a/b"),
        ("raw_query", "x=y"),
    ] {
        let recipe = Recipe::from_json(
            PROFILE_DIGEST,
            &serde_json::json!([{"kind": "url_component", "component": component}]),
        )
        .expect("recipe");
        assert_eq!(recipe.apply(input).expect("apply"), want);
    }
}

#[test]
fn liberal_hex_rejects_non_utf8_output() {
    let recipe = Recipe::from_json(
        PROFILE_DIGEST,
        &serde_json::json!([{"kind": "hex_decode_liberal"}]),
    )
    .expect("recipe");
    assert!(recipe.apply("ff").unwrap_err().contains("invalid UTF-8"));
}

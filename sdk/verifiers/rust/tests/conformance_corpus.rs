// Cross-language conformance corpus checks for the Rust verifier. Paths are
// relative to the crate directory (cargo test CWD), matching the vendored
// corpus shared by all four reference verifiers.

use pipelock_verifier_rs::receipt::run_receipt;
use pipelock_verifier_rs::util::reject_duplicate_keys;
use std::fs;

const CORPUS: &str = "../../conformance/testdata/corpus";

fn corpus_key() -> String {
    let data = fs::read_to_string(format!("{CORPUS}/test-key.json")).expect("read test-key");
    let value: serde_json::Value = serde_json::from_str(&data).expect("parse test-key");
    value["public_key_hex"]
        .as_str()
        .expect("public_key_hex")
        .to_string()
}

#[test]
fn shield_bearing_corpus_receipt_verifies() {
    let key = corpus_key();
    let report = run_receipt(
        &format!("{CORPUS}/golden/09-allow-shield-summary.json"),
        &key,
        false,
    )
    .expect("run receipt");
    assert!(report.valid, "{:?}", report.error);
}

#[test]
fn full_field_differential_corpus_receipt_verifies() {
    let key = corpus_key();
    let report = run_receipt(
        &format!("{CORPUS}/golden/10-full-field-differential.json"),
        &key,
        false,
    )
    .expect("run receipt");
    assert!(report.valid, "{:?}", report.error);
}

#[test]
fn duplicate_key_corpus_receipt_rejected() {
    let key = corpus_key();
    let report = run_receipt(
        &format!("{CORPUS}/malicious/m13-duplicate-key-verdict.json"),
        &key,
        false,
    )
    .expect("run receipt");
    assert!(!report.valid);
    assert!(report
        .error
        .as_deref()
        .unwrap_or("")
        .contains("duplicate object key"));
}

#[test]
fn reject_duplicate_keys_clean_passes() {
    reject_duplicate_keys(r#"{"a":1,"b":{"c":2},"d":[{"e":3},{"e":4}]}"#).expect("clean json");
}

#[test]
fn reject_duplicate_keys_top_level_dup() {
    assert!(reject_duplicate_keys(r#"{"a":1,"a":2}"#).is_err());
}

#[test]
fn reject_duplicate_keys_nested_object_dup() {
    assert!(reject_duplicate_keys(r#"{"x":{"a":1,"a":2}}"#).is_err());
}

#[test]
fn reject_duplicate_keys_array_element_dup() {
    assert!(reject_duplicate_keys(r#"{"arr":[{"a":1},{"a":1,"a":2}]}"#).is_err());
}

#[test]
fn reject_duplicate_keys_unicode_escaped_dup() {
    // "a" decodes to "a"; must be caught (cross-language smuggling vector).
    assert!(reject_duplicate_keys(r#"{"a":1,"\u0061":2}"#).is_err());
}

#[test]
fn reject_duplicate_keys_over_deep_nesting() {
    let max_depth = format!("{}1{}", "[".repeat(128), "]".repeat(128));
    reject_duplicate_keys(&max_depth).expect("exact max-depth nesting");

    let deep = format!("{}1{}", "[".repeat(129), "]".repeat(129));
    assert!(reject_duplicate_keys(&deep).is_err());
}

#[test]
fn reject_duplicate_keys_string_delimiters_not_confused() {
    reject_duplicate_keys(r#"{"a":"}{:,","b":2}"#).expect("delimiters inside a string value");
    assert!(reject_duplicate_keys(r#"{"a":"x","a":"y"}"#).is_err());
}

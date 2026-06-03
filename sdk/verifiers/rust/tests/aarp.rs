// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//! AARP verifier tests: a corpus-driven conformance test that runs the built
//! binary over every fixture in the shared corpus, plus library-level unit
//! tests for the JCS canonicalizer, number safety, typed-string grammars,
//! envelope decoding, signature appraisal, and chain linkage.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pipelock_verifier_rs::aarp::chain::{comparable_chain, verify_chain};
use pipelock_verifier_rs::aarp::envelope::{
    check_critical_extensions, validate_hex256, validate_timestamp, validate_uint64_string,
    Envelope, ProtectedHeader, CANON_ID, PROFILE,
};
use pipelock_verifier_rs::aarp::jcs::{
    canonicalize_tree, enforce_safe_numbers, parse_strict, JcsError, Json,
};
use pipelock_verifier_rs::aarp::verify::{comparable_appraisal, verify, TrustEntry, VerifyOptions};

const CORPUS: &str = "../../conformance/testdata/aarp-corpus";

fn corpus_dir() -> PathBuf {
    PathBuf::from(CORPUS)
}

fn trust_path() -> PathBuf {
    corpus_dir().join("trust.json")
}

fn binary() -> PathBuf {
    // The integration test runs after the crate (and its bin) are built.
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("release");
    path.push("pipelock-verifier-rs");
    if path.exists() {
        return path;
    }
    // Fall back to the debug profile if release was not built.
    let mut dbg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dbg.push("target");
    dbg.push("debug");
    dbg.push("pipelock-verifier-rs");
    dbg
}

struct RunResult {
    stdout: String,
    code: i32,
}

fn run_aarp(fixture: &Path, chain: bool) -> RunResult {
    let mut cmd = Command::new(binary());
    cmd.arg("aarp")
        .arg(fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--json");
    if chain {
        cmd.arg("--chain");
    }
    let output = cmd.output().expect("run verifier binary");
    RunResult {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        code: output.status.code().unwrap_or(-1),
    }
}

/// run_aarp_svid runs a single-envelope appraisal with a `--svid` sidecar.
fn run_aarp_svid(fixture: &Path, svid: &Path) -> RunResult {
    let output = Command::new(binary())
        .arg("aarp")
        .arg(fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--svid")
        .arg(svid)
        .arg("--json")
        .output()
        .expect("run verifier binary");
    RunResult {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        code: output.status.code().unwrap_or(-1),
    }
}

fn expect_field(expect: &str, key: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(expect).ok()?;
    value.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

/// The flagship test: drive the built binary over the entire corpus and assert,
/// for every fixture, that the verifier matches the committed expectation.
#[test]
fn corpus_conformance() {
    let root = corpus_dir();
    assert!(root.exists(), "corpus dir missing at {}", root.display());
    let mut checked = 0;
    for category in ["golden", "malicious", "edge", "chain"] {
        let dir = root.join(category);
        for entry in fs::read_dir(&dir).expect("read category dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy();
            if !name.ends_with(".expect.json") {
                continue;
            }
            let base = name.trim_end_matches(".expect.json").to_string();
            let expect = fs::read_to_string(&path).expect("read expect");
            let verdict = expect_field(&expect, "verdict").expect("verdict");
            let informat = expect_field(&expect, "input_format").unwrap_or_default();

            let (fixture, is_chain) = if informat == "chain" {
                (dir.join(format!("{base}.aarp.jsonl")), true)
            } else {
                (dir.join(format!("{base}.aarp.json")), false)
            };
            assert!(fixture.exists(), "missing fixture {}", fixture.display());

            let result = run_aarp(&fixture, is_chain);
            checked += 1;

            if verdict == "fatal" {
                assert_ne!(
                    result.code, 0,
                    "{base}: fatal fixture must be rejected (non-zero exit)"
                );
            } else {
                assert_eq!(
                    result.code, 0,
                    "{base}: appraise fixture must exit 0; stdout={}",
                    result.stdout
                );
                let want = fs::read_to_string(dir.join(format!("{base}.appraisal.json")))
                    .expect("read committed appraisal");
                assert_eq!(
                    result.stdout.trim_end(),
                    want.trim_end(),
                    "{base}: comparable bytes diverge from committed appraisal"
                );
            }
        }
    }
    assert!(
        checked >= 31,
        "expected at least 31 fixtures, got {checked}"
    );
}

/// The SVID conformance test: drive the built binary over every fixture in the
/// `svid/` arm with `--svid` and assert byte-identical comparable output to the
/// committed appraisal. s01 (P-256) and s02 (Ed25519) confirm all three SVID
/// claims; every malicious fixture (s03–s21) appraises WITHOUT them (no
/// inflation), and s13 (unsigned) reports assertion_signed false. s17 (malformed
/// SPIFFE-ID dot-segment path) and s19 (issued_at one nanosecond past a
/// whole-second leaf expiry) are the strict-grammar / full-precision-time
/// regressions; s18 (signing CA expired at action time) withholds via the
/// CA-window check.
#[test]
fn corpus_conformance_svid() {
    let dir = corpus_dir().join("svid");
    assert!(dir.exists(), "svid corpus dir missing at {}", dir.display());
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("read svid dir") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".expect.json") {
            continue;
        }
        let base = name.trim_end_matches(".expect.json").to_string();
        let expect = fs::read_to_string(&path).expect("read expect");
        let verdict = expect_field(&expect, "verdict").expect("verdict");
        // Every svid fixture appraises (the binding failures are appraisal-level,
        // never envelope-fatal).
        assert_eq!(verdict, "appraise", "{base}: svid fixtures must appraise");

        let fixture = dir.join(format!("{base}.aarp.json"));
        let svid = dir.join(format!("{base}.svid.json"));
        assert!(fixture.exists(), "missing fixture {}", fixture.display());
        assert!(svid.exists(), "missing svid sidecar {}", svid.display());

        let result = run_aarp_svid(&fixture, &svid);
        checked += 1;
        assert_eq!(
            result.code, 0,
            "{base}: svid fixture must exit 0; stdout={}",
            result.stdout
        );
        let want = fs::read_to_string(dir.join(format!("{base}.appraisal.json")))
            .expect("read committed appraisal");
        assert_eq!(
            result.stdout.trim_end(),
            want.trim_end(),
            "{base}: svid comparable bytes diverge from committed appraisal"
        );
    }
    assert_eq!(checked, 21, "expected 21 svid fixtures, got {checked}");
}

/// Without `--svid`, an SVID fixture appraises to exactly the envelope appraisal
/// (the three SVID claims never appear), proving the layer is additive.
#[test]
fn svid_omitted_yields_plain_envelope_appraisal() {
    let dir = corpus_dir().join("svid");
    let fixture = dir.join("s01-valid-ecdsa-p256-baseline.aarp.json");
    let result = run_aarp(&fixture, false);
    assert_eq!(result.code, 0, "stdout={}", result.stdout);
    // The SVID claims never appear in verified_claims or axes without --svid.
    let value: serde_json::Value =
        serde_json::from_str(result.stdout.trim_end()).expect("parse appraisal json");
    let verified = value
        .get("verified_claims")
        .and_then(|v| v.as_array())
        .expect("verified_claims array");
    for claim in [
        "workload_identity_verified",
        "x509_svid_bound",
        "svid_valid_at_action_time",
    ] {
        assert!(
            !verified.iter().any(|c| c.as_str() == Some(claim)),
            "without --svid the SVID claim {claim:?} must not be verified: {}",
            result.stdout
        );
    }
    // The producer claim stays in claimed_unverified without --svid.
    assert!(
        result
            .stdout
            .contains("\"claimed_unverified\":[\"workload_identity_verified\"]"),
        "the producer claim stays in claimed_unverified without --svid: {}",
        result.stdout
    );
}

/// `--svid` combined with `--chain` is a usage error (exit 64): the SVID binding
/// is single-envelope only.
#[test]
fn svid_with_chain_is_usage_error() {
    let dir = corpus_dir().join("svid");
    let fixture = dir.join("s01-valid-ecdsa-p256-baseline.aarp.json");
    let svid = dir.join("s01-valid-ecdsa-p256-baseline.svid.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--svid")
        .arg(&svid)
        .arg("--chain")
        .arg("--json")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn missing_trust_makes_signatures_unknown_key() {
    // With no --trust file, the smoke golden fixture's signature is unknown_key,
    // so it is still appraised (exit 0) but assertion_signed is false.
    let fixture = corpus_dir().join("golden/g01-single-ed25519-mediated.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--json")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"assertion_signed\":false"), "{stdout}");
    assert!(stdout.contains("\"status\":\"unknown_key\""), "{stdout}");
}

#[test]
fn usage_error_on_missing_path() {
    let output = Command::new(binary())
        .arg("aarp")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn trust_file_error_exits_two() {
    let fixture = corpus_dir().join("golden/g01-single-ed25519-mediated.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg("/nonexistent/trust.json")
        .arg("--json")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn human_output_mode_prints_appraisal() {
    // No --json: the human-readable summary path (exit 0).
    let fixture = corpus_dir().join("golden/g01-single-ed25519-mediated.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AARP appraisal"), "{stdout}");
    assert!(stdout.contains("assertion_signed:"), "{stdout}");
}

#[test]
fn inline_trust_flag_form_is_accepted() {
    // The --trust=PATH inline form must resolve trust identically.
    let fixture = corpus_dir().join("golden/g01-single-ed25519-mediated.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg(format!("--trust={}", trust_path().display()))
        .arg("--json")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"assertion_signed\":true"), "{stdout}");
}

#[test]
fn fatal_envelope_json_body_marks_envelope_fatal() {
    let fixture = corpus_dir().join("edge/p02-float.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--json")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"envelope_fatal\":true"), "{stdout}");
}

#[test]
fn fatal_envelope_human_mode_prints_to_stderr() {
    let fixture = corpus_dir().join("edge/p02-float.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ENVELOPE FATAL"), "{stdout}");
}

#[test]
fn chain_non_json_mode_reports_count() {
    let fixture = corpus_dir().join("chain/c01-valid-stream.aarp.jsonl");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--chain")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AARP chain: 3 envelopes"), "{stdout}");
}

#[test]
fn chain_broken_non_json_mode_exits_one() {
    let fixture = corpus_dir().join("chain/c02-reordered-stream.aarp.jsonl");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--trust")
        .arg(trust_path())
        .arg("--chain")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn unknown_option_is_usage_error() {
    let fixture = corpus_dir().join("golden/g01-single-ed25519-mediated.aarp.json");
    let output = Command::new(binary())
        .arg("aarp")
        .arg(&fixture)
        .arg("--bogus")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn signature_unknown_critical_extension_is_appraised_not_fatal() {
    // A protected header carrying a non-empty (unknown) crit list is NOT
    // envelope-fatal: it is a per-signature outcome. The envelope unmarshals,
    // and the signature is reported unknown_suite (never verifies, no fallback).
    let fixture = corpus_dir().join("malicious/m12-sig-unknown-critical-extension.aarp.json");
    let env = load_envelope("malicious/m12-sig-unknown-critical-extension.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert!(!ap.assertion_signed);
    assert_eq!(ap.signatures[0].status, "unknown_suite");
    // The fixture still parses (no envelope-fatal rejection).
    let data = fs::read_to_string(&fixture).expect("read");
    assert!(Envelope::unmarshal(&data).is_ok());
}

// ---- JCS canonicalizer unit tests ----

#[test]
fn jcs_sorts_object_keys_by_codepoint() {
    let tree = parse_strict(r#"{"b":1,"a":2,"c":3}"#).expect("parse");
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":2,"b":1,"c":3}"#);
}

#[test]
fn jcs_html_escapes_like_go() {
    let tree = parse_strict(r#"{"k":"a<b>c&d"}"#).expect("parse");
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"k\":\"a\\u003cb\\u003ec\\u0026d\"}"
    );
}

#[test]
fn jcs_escapes_line_and_paragraph_separators() {
    // U+2028 and U+2029 must be escaped to match Go's json.Marshal.
    let tree = parse_strict("{\"k\":\"a\u{2028}b\u{2029}c\"}").expect("parse");
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"k\":\"a\\u2028b\\u2029c\"}"
    );
}

#[test]
fn jcs_nfc_normalizes_strings() {
    // "e" + combining acute (NFD) must normalize to the single NFC codepoint.
    let nfd = "e\u{0301}";
    let tree = Json::String(nfd.to_string());
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(String::from_utf8(out).unwrap(), "\"\u{00e9}\"");
}

#[test]
fn jcs_canonicalize_rejects_float() {
    let tree = Json::Number("1.5".to_string());
    assert!(matches!(
        canonicalize_tree(&tree),
        Err(JcsError::FloatNotAllowed(_))
    ));
}

#[test]
fn parse_strict_rejects_duplicate_keys() {
    assert!(matches!(
        parse_strict(r#"{"a":1,"a":2}"#),
        Err(JcsError::DuplicateKey(_))
    ));
}

#[test]
fn parse_strict_rejects_nested_duplicate_keys() {
    assert!(matches!(
        parse_strict(r#"{"x":{"a":1,"a":2}}"#),
        Err(JcsError::DuplicateKey(_))
    ));
}

#[test]
fn parse_strict_rejects_unicode_escaped_duplicate() {
    assert!(matches!(
        parse_strict(r#"{"a":1,"a":2}"#),
        Err(JcsError::DuplicateKey(_))
    ));
}

#[test]
fn parse_strict_rejects_trailing_tokens() {
    assert!(matches!(
        parse_strict(r#"{"a":1} {"b":2}"#),
        Err(JcsError::TrailingTokens(_))
    ));
}

#[test]
fn parse_strict_allows_trailing_whitespace() {
    parse_strict("{\"a\":1}\n  \t").expect("trailing whitespace is fine");
}

#[test]
fn parse_strict_decodes_surrogate_pairs() {
    let tree = parse_strict(r#"{"k":"😀"}"#).expect("parse");
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(String::from_utf8(out).unwrap(), "{\"k\":\"\u{1F600}\"}");
}

#[test]
fn parse_strict_matches_go_on_unpaired_surrogates() {
    let tree =
        parse_strict(r#"{"k":"\ud800.example","x":"\ud800\u0041","y":"\udc00"}"#).expect("parse");
    let out = canonicalize_tree(&tree).expect("canon");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"k\":\"�.example\",\"x\":\"�A\",\"y\":\"�\"}"
    );
}

// ---- number safety unit tests ----

#[test]
fn number_safety_rejects_large_integer() {
    let tree = parse_strict(r#"{"n":9007199254740992}"#).expect("parse");
    assert!(matches!(
        enforce_safe_numbers(&tree),
        Err(JcsError::UnsafeNumber(_))
    ));
}

#[test]
fn number_safety_accepts_max_safe_integer() {
    let tree = parse_strict(r#"{"n":9007199254740991}"#).expect("parse");
    enforce_safe_numbers(&tree).expect("max safe integer is allowed");
}

#[test]
fn number_safety_rejects_float() {
    let tree = parse_strict(r#"{"n":1.5}"#).expect("parse");
    assert!(matches!(
        enforce_safe_numbers(&tree),
        Err(JcsError::UnsafeNumber(_))
    ));
}

#[test]
fn number_safety_rejects_exponent() {
    let tree = parse_strict(r#"{"n":1e3}"#).expect("parse");
    assert!(matches!(
        enforce_safe_numbers(&tree),
        Err(JcsError::UnsafeNumber(_))
    ));
}

#[test]
fn number_safety_rejects_negative_zero() {
    let tree = parse_strict(r#"{"n":-0}"#).expect("parse");
    assert!(matches!(
        enforce_safe_numbers(&tree),
        Err(JcsError::UnsafeNumber(_))
    ));
}

#[test]
fn number_safety_walks_arrays() {
    let tree = parse_strict(r#"{"a":[1,2,99999999999999999]}"#).expect("parse");
    assert!(matches!(
        enforce_safe_numbers(&tree),
        Err(JcsError::UnsafeNumber(_))
    ));
}

// ---- grammar unit tests ----

#[test]
fn hex256_grammar() {
    let good = "a".repeat(64);
    validate_hex256(&good, "x").expect("64 lowercase hex");
    assert!(validate_hex256(&"a".repeat(63), "x").is_err());
    assert!(validate_hex256(&"A".repeat(64), "x").is_err());
}

#[test]
fn uint64_grammar() {
    validate_uint64_string("0", "x").expect("zero");
    validate_uint64_string("12345", "x").expect("decimal");
    assert!(validate_uint64_string("", "x").is_err());
    assert!(validate_uint64_string("01", "x").is_err());
    assert!(validate_uint64_string("1a", "x").is_err());
    assert!(validate_uint64_string("99999999999999999999", "x").is_err());
}

#[test]
fn timestamp_grammar() {
    validate_timestamp("2026-04-15T12:00:00.000000000Z", "x").expect("rfc3339nano");
    validate_timestamp("2026-04-15T12:00:00Z", "x").expect("no fraction");
    validate_timestamp("2026-04-15T12:00:00+02:00", "x").expect("offset zone");
    assert!(validate_timestamp("", "x").is_err());
    assert!(validate_timestamp("2026-04-15 12:00:00Z", "x").is_err());
    assert!(validate_timestamp("2026-04-15T12:00:00", "x").is_err());
    assert!(validate_timestamp("not-a-time", "x").is_err());
}

#[test]
fn critical_extension_registry_is_empty() {
    check_critical_extensions(&[]).expect("no extensions is fine");
    assert!(check_critical_extensions(&["anything".to_string()]).is_err());
    assert!(check_critical_extensions(&["".to_string()]).is_err());
    assert!(check_critical_extensions(&["x".to_string(), "x".to_string()]).is_err());
}

// ---- envelope + verify library tests ----

fn load_envelope(rel: &str) -> Envelope {
    let data = fs::read_to_string(corpus_dir().join(rel)).expect("read fixture");
    Envelope::unmarshal(&data).expect("unmarshal envelope")
}

fn corpus_trust() -> VerifyOptions {
    let data = fs::read_to_string(trust_path()).expect("read trust");
    let value: serde_json::Value = serde_json::from_str(&data).expect("parse trust");
    let mut opts = VerifyOptions::default();
    for (key_id, key_hex) in value["trusted_keys"].as_object().unwrap() {
        let raw = hex::decode(key_hex.as_str().unwrap()).unwrap();
        opts.trusted_keys
            .insert(key_id.clone(), raw.try_into().unwrap());
    }
    if let Some(entries) = value["trust_entries"].as_object() {
        for (key_id, entry) in entries {
            opts.trust.insert(
                key_id.clone(),
                TrustEntry {
                    mediator_id: entry["mediator_id"].as_str().unwrap_or("").to_string(),
                    role: entry
                        .get("role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    trust_domain: entry
                        .get("trust_domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                },
            );
        }
    }
    opts
}

#[test]
fn verify_pinned_mediator_confirms_both_claims() {
    let env = load_envelope("golden/g01-single-ed25519-mediated.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert!(ap.assertion_signed);
    assert!(ap
        .verified_claims
        .contains(&"mediator_key_pinned".to_string()));
    assert!(ap
        .verified_claims
        .contains(&"assertion_signature_valid".to_string()));
    assert!(ap.claimed_unverified.is_empty());
}

#[test]
fn verify_forged_signature_is_appraised_not_fatal() {
    let env = load_envelope("malicious/m01-forged-signature.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert!(!ap.assertion_signed);
    assert_eq!(ap.signatures[0].status, "failed");
    assert!(ap.claimed_unverified.contains(&"mediated".to_string()));
}

#[test]
fn verify_role_escalation_signs_but_not_pinned() {
    // m06: signature verifies but signer_role countersig != trust entry role
    // mediator, so mediator_key_pinned is NOT confirmed.
    let env = load_envelope("malicious/m06-role-escalation.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert!(ap.assertion_signed);
    assert!(!ap
        .verified_claims
        .contains(&"mediator_key_pinned".to_string()));
    assert!(ap.claimed_unverified.contains(&"mediated".to_string()));
}

#[test]
fn verify_untrusted_key_is_unknown_key() {
    let env = load_envelope("malicious/m05-untrusted-key.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert_eq!(ap.signatures[0].status, "unknown_key");
    assert!(!ap.assertion_signed);
}

#[test]
fn verify_unknown_suite_does_not_fallback() {
    let env = load_envelope("malicious/m04-unknown-suite-only.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert_eq!(ap.signatures[0].status, "unknown_suite");
    assert!(!ap.assertion_signed);
}

#[test]
fn verify_pq_slot_is_unimplemented() {
    let env = load_envelope("malicious/m03-downgrade-pq-only.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert_eq!(ap.signatures[0].status, "unimplemented");
    assert!(!ap.assertion_signed);
}

#[test]
fn verify_unknown_claim_reported_claim_only() {
    // m07 carries a post-sign-added "transparency_inclusion" claim; with a
    // failed signature both producer claims are reported unverified.
    let env = load_envelope("malicious/m07-post-sign-claim-add.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    assert!(ap
        .claimed_unverified
        .contains(&"transparency_inclusion".to_string()));
}

#[test]
fn comparable_appraisal_is_canonical() {
    let env = load_envelope("golden/g01-single-ed25519-mediated.aarp.json");
    let ap = verify(&env, &corpus_trust()).expect("verify");
    let bytes = comparable_appraisal(&ap).expect("comparable");
    let want =
        fs::read_to_string(corpus_dir().join("golden/g01-single-ed25519-mediated.appraisal.json"))
            .expect("read appraisal");
    assert_eq!(String::from_utf8(bytes).unwrap(), want.trim_end());
}

// ---- fatal decode paths ----

#[test]
fn unmarshal_rejects_unknown_field() {
    let data =
        fs::read_to_string(corpus_dir().join("edge/p07-unknown-field.aarp.json")).expect("read");
    assert!(Envelope::unmarshal(&data).is_err());
}

#[test]
fn unmarshal_rejects_profile_mismatch() {
    let data = fs::read_to_string(corpus_dir().join("malicious/m09-profile-mismatch.aarp.json"))
        .expect("read");
    assert!(Envelope::unmarshal(&data).is_err());
}

#[test]
fn unmarshal_rejects_empty_signatures() {
    let data = fs::read_to_string(corpus_dir().join("malicious/m13-empty-signatures.aarp.json"))
        .expect("read");
    assert!(Envelope::unmarshal(&data).is_err());
}

#[test]
fn unmarshal_rejects_bad_digest_grammar() {
    let data = fs::read_to_string(corpus_dir().join("edge/p08-bad-digest-grammar.aarp.json"))
        .expect("read");
    assert!(Envelope::unmarshal(&data).is_err());
}

// ---- chain library tests ----

fn load_chain(rel: &str) -> Vec<Envelope> {
    let data = fs::read_to_string(corpus_dir().join(rel)).expect("read jsonl");
    data.trim()
        .split('\n')
        .filter(|line| !line.trim().is_empty())
        .map(|line| Envelope::unmarshal(line).expect("unmarshal chain line"))
        .collect()
}

#[test]
fn chain_valid_stream_links() {
    let envs = load_chain("chain/c01-valid-stream.aarp.jsonl");
    verify_chain(&envs).expect("contiguous single-issuer stream links");
    let bytes = comparable_chain(&envs).expect("comparable chain");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"chain_linked":true,"length":3}"#
    );
}

#[test]
fn chain_reordered_stream_breaks() {
    let envs = load_chain("chain/c02-reordered-stream.aarp.jsonl");
    assert!(verify_chain(&envs).is_err());
}

#[test]
fn chain_mixed_issuer_breaks() {
    let envs = load_chain("chain/c03-mixed-issuer-stream.aarp.jsonl");
    assert!(verify_chain(&envs).is_err());
}

#[test]
fn chain_backdated_breaks() {
    let envs = load_chain("chain/c04-backdated-stream.aarp.jsonl");
    assert!(verify_chain(&envs).is_err());
}

#[test]
fn chain_empty_is_not_linked() {
    let envs: Vec<Envelope> = Vec::new();
    assert!(verify_chain(&envs).is_err());
    let bytes = comparable_chain(&envs).expect("comparable empty");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"chain_linked":false,"length":0}"#
    );
}

// ---- signing input ----

#[test]
fn signing_input_omits_empty_crit() {
    let digest = "a".repeat(64);
    let header = ProtectedHeader {
        profile: PROFILE.to_string(),
        canon: CANON_ID.to_string(),
        alg: "ed25519".to_string(),
        key_type: "ed25519".to_string(),
        key_id: "k-signer".to_string(),
        signer_role: "mediator".to_string(),
        crit: Vec::new(),
    };
    let bytes = Envelope::signing_input(&digest, &header).expect("signing input");
    let text = String::from_utf8(bytes).unwrap();
    // context + payload_sha256 + protected; protected omits crit when empty.
    assert!(text.contains("\"context\":\"pipelock-aarp-v0.1/assurance-assertion\""));
    assert!(text.contains(&format!("\"payload_sha256\":\"{digest}\"")));
    assert!(!text.contains("\"crit\""));
}

#[test]
fn signing_input_includes_present_crit() {
    let digest = "b".repeat(64);
    let header = ProtectedHeader {
        profile: PROFILE.to_string(),
        canon: CANON_ID.to_string(),
        alg: "ed25519".to_string(),
        key_type: "ed25519".to_string(),
        key_id: "k-signer".to_string(),
        signer_role: "mediator".to_string(),
        crit: vec!["x".to_string()],
    };
    let bytes = Envelope::signing_input(&digest, &header).expect("signing input");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"crit\":[\"x\"]"));
}

// Regression: a high,high,low surrogate-escape run must re-pair the 2nd and 3rd
// escapes into a valid astral char (non-greedy), matching Go encoding/json and
// Python json. A greedy decoder consumes the 2nd escape and emits three U+FFFD,
// producing different canonical bytes than Go -- a cross-language differential
// that would silently break chain prior_hash linkage in some languages only.
#[test]
fn surrogate_high_high_low_repairs_non_greedy() {
    let got = canonicalize_tree(&parse_strict(r#"{"x":"\ud800\udbff\udc00"}"#).unwrap()).unwrap();
    // Decoded reference form: U+FFFD followed by the astral pair U+10FC00.
    let want = canonicalize_tree(&parse_strict("{\"x\":\"\u{FFFD}\u{10FC00}\"}").unwrap()).unwrap();
    assert_eq!(got, want, "high,high,low must re-pair like Go (non-greedy)");
    let three_fffd =
        canonicalize_tree(&parse_strict("{\"x\":\"\u{FFFD}\u{FFFD}\u{FFFD}\"}").unwrap()).unwrap();
    assert_ne!(
        got, three_fffd,
        "greedy three-U+FFFD output is a Go divergence"
    );
}

// Regression: a lone high surrogate followed by a non-low \u escape decodes the
// high to U+FFFD and reprocesses the second escape (does not consume it).
#[test]
fn surrogate_high_then_non_low_is_non_greedy() {
    let got = canonicalize_tree(&parse_strict(r#"{"x":"\ud800A"}"#).unwrap()).unwrap();
    let want = canonicalize_tree(&parse_strict("{\"x\":\"\u{FFFD}A\"}").unwrap()).unwrap();
    assert_eq!(got, want);
}

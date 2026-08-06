// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Experimental, fixture-only evidence-provenance verifier.
//!
//! This module deliberately consumes a test fixture wrapper rather than a
//! registered receipt payload. It must not be wired into production receipt
//! emission or treated as a capability claim.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2_10::Sha256 as HmacSha256;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use crate::provenance::{Recipe as TransformRecipe, PROFILE_DIGEST};
use crate::util::{reject_duplicate_keys, sha256_hex, Result, VerifierError};

const FIXTURE_FORMAT: &str = "pipelock-evidence-provenance-verification-fixture/v1";
const PROOF_VERSION: &str = "pipelock-evidence-provenance-proof/v1";
const GENESIS: &str = "genesis";
const TRUST_ROOTS: &str = "fixture supplied; self-attested; not authenticated";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProvenanceReport {
    pub trust_roots: String,
    pub authenticated_provenance: bool,
    pub signature: String,
    pub chain: String,
    pub artifacts: String,
    pub source_commitment: String,
    pub view_reproduction: String,
    pub location: String,
    pub match_commitment: String,
    pub overall: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
}

impl ProvenanceReport {
    fn pending() -> Self {
        Self {
            trust_roots: TRUST_ROOTS.into(),
            authenticated_provenance: false,
            signature: "not_checked".into(),
            chain: "not_checked".into(),
            artifacts: "attested_unchecked".into(),
            source_commitment: "not_checked".into(),
            view_reproduction: "not_checked".into(),
            location: "not_checked".into(),
            match_commitment: "not_checked".into(),
            overall: "incomplete".into(),
            failure_stage: None,
        }
    }

    fn fail(&mut self, stage: &str) {
        self.overall = "invalid".into();
        self.failure_stage = Some(stage.into());
    }

    fn proof_structure_failure() -> Self {
        let mut report = Self::pending();
        report.fail("proof_structure");
        report
    }
}

#[derive(Clone)]
struct SignedEntry {
    bytes: Vec<u8>,
    value: Value,
}

#[derive(Clone)]
struct VerificationInput {
    signer: Vec<u8>,
    commitment_key: Option<Vec<u8>>,
    sources: BTreeMap<String, String>,
    binary: Option<Vec<u8>>,
    ruleset: Option<Vec<u8>>,
}

pub fn run_provenance(path: &Path) -> Result<ProvenanceReport> {
    let bytes = fs::read(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    Ok(
        verify_fixture_bytes(&bytes)
            .unwrap_or_else(|_| ProvenanceReport::proof_structure_failure()),
    )
}

/// Verify one fixture. Errors here indicate a malformed fixture envelope;
/// authenticated proof failures are represented in [`ProvenanceReport`].
pub fn verify_fixture_bytes(bytes: &[u8]) -> std::result::Result<ProvenanceReport, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "fixture: invalid UTF-8".to_string())?;
    reject_duplicate_keys(text).map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(text).map_err(|err| format!("fixture JSON: {err}"))?;
    let object = object(&value, "fixture")?;
    exact_keys(object, &["format", "entries", "verification"], "fixture")?;
    if string(object, "format", "fixture")? != FIXTURE_FORMAT {
        return Err("fixture: unsupported format".into());
    }
    let verification = parse_verification(required(object, "verification", "fixture")?)?;
    let entries = array(required(object, "entries", "fixture")?, "fixture.entries")?;
    if entries.is_empty() {
        return Err("fixture.entries: must not be empty".into());
    }
    let parsed = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_entry(entry, index))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    verify_entries(&parsed, &verification)
}

fn parse_entry(value: &Value, index: usize) -> std::result::Result<SignedEntry, String> {
    let entry = object(value, &format!("fixture.entries[{index}]"))?;
    exact_keys(entry, &["signed_b64", "signature"], "fixture entry")?;
    let bytes = decode_b64(string(entry, "signed_b64", "fixture entry")?, "signed_b64")?;
    let signed_text =
        std::str::from_utf8(&bytes).map_err(|_| "signed_b64: invalid UTF-8".to_string())?;
    reject_duplicate_keys(signed_text).map_err(|err| format!("signed JSON: {err}"))?;
    let signed: Value =
        serde_json::from_str(signed_text).map_err(|err| format!("signed JSON: {err}"))?;
    let signature = string(entry, "signature", "fixture entry")?;
    if !signature.starts_with("ed25519:") {
        return Err("fixture entry: signature must use ed25519:".into());
    }
    // Retain the detached signature in the object so verification stays exact
    // while avoiding a second public wrapper type.
    let mut value = signed;
    value
        .as_object_mut()
        .ok_or_else(|| "signed JSON: must be an object".to_string())?
        .insert(
            "__fixture_signature".into(),
            Value::String(signature[8..].into()),
        );
    Ok(SignedEntry { bytes, value })
}

fn parse_verification(value: &Value) -> std::result::Result<VerificationInput, String> {
    let verification = object(value, "verification")?;
    exact_keys_with_optional(
        verification,
        &[
            "signer_public_key_hex",
            "commitment_key_hex",
            "sources",
            "binary_b64",
            "ruleset_b64",
        ],
        &["commitment_key_hex", "sources", "binary_b64", "ruleset_b64"],
        "verification",
    )?;
    let signer = decode_hex(
        string(verification, "signer_public_key_hex", "verification")?,
        32,
        "signer_public_key_hex",
    )?;
    let commitment_key = optional_string(verification, "commitment_key_hex")?
        .map(|value| decode_hex(value, 0, "commitment_key_hex"))
        .transpose()?;
    if let Some(key) = &commitment_key {
        if key.len() < 32 {
            return Err("commitment_key_hex: must encode at least 32 bytes".into());
        }
    }
    let sources_array: &[Value] = match verification.get("sources") {
        Some(value) => array(value, "verification.sources")?,
        None => &[],
    };
    let mut sources = BTreeMap::new();
    for (index, source) in sources_array.iter().enumerate() {
        let source = object(source, "verification source")?;
        exact_keys(source, &["source_id", "bytes_b64"], "verification source")?;
        let id = string(source, "source_id", "verification source")?.to_string();
        let bytes = decode_b64(
            string(source, "bytes_b64", "verification source")?,
            "source bytes",
        )?;
        let text =
            String::from_utf8(bytes).map_err(|_| "source bytes: invalid UTF-8".to_string())?;
        if sources.insert(id.clone(), text).is_some() {
            return Err(format!(
                "verification.sources[{index}]: duplicate source_id {id:?}"
            ));
        }
    }
    Ok(VerificationInput {
        signer,
        commitment_key,
        sources,
        binary: optional_string(verification, "binary_b64")?
            .map(|v| decode_b64(v, "binary_b64"))
            .transpose()?,
        ruleset: optional_string(verification, "ruleset_b64")?
            .map(|v| decode_b64(v, "ruleset_b64"))
            .transpose()?,
    })
}

fn verify_entries(
    entries: &[SignedEntry],
    input: &VerificationInput,
) -> std::result::Result<ProvenanceReport, String> {
    let mut report = ProvenanceReport::pending();
    let verifying: [u8; 32] = input
        .signer
        .as_slice()
        .try_into()
        .map_err(|_| "signer key length".to_string())?;
    let verifying =
        VerifyingKey::from_bytes(&verifying).map_err(|err| format!("signer key: {err}"))?;
    let mut missing_source = false;
    for entry in entries {
        let signature_hex = entry
            .value
            .get("__fixture_signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "fixture signature missing".to_string())?;
        let signature = decode_hex(signature_hex, 64, "signature")?;
        let signature =
            Signature::from_slice(&signature).map_err(|err| format!("signature: {err}"))?;
        if verifying.verify_strict(&entry.bytes, &signature).is_err() {
            report.signature = "invalid".into();
            report.fail("signature");
            return Ok(report);
        }
    }
    report.signature = "verified".into();

    let mut previous: Option<&SignedEntry> = None;
    for (index, entry) in entries.iter().enumerate() {
        let expected_previous = previous
            .map(|prior| format!("sha256:{}", sha256_hex(&prior.bytes)))
            .unwrap_or_else(|| GENESIS.into());
        if !chain_fields_match(entry, index as u64, &expected_previous) {
            report.chain = "invalid".into();
            report.fail("chain");
            return Ok(report);
        }
        previous = Some(entry);
    }
    report.chain = "verified".into();

    for entry in entries {
        let signed = match signed_object(entry) {
            Ok(signed) => signed,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        if !critical_features_ok(signed) {
            report.fail("critical_features");
            return Ok(report);
        }
        let proof_value = match required(signed, "proof", "signed") {
            Ok(proof) => proof,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        let proof = match parse_proof(proof_value) {
            Ok(proof) => proof,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        match verify_artifacts(&proof, input) {
            Stage::Matched => report.artifacts = "matched".into(),
            Stage::Unchecked => report.artifacts = "attested_unchecked".into(),
            Stage::Mismatch => {
                report.artifacts = "mismatch".into();
                report.fail("artifacts");
                return Ok(report);
            }
        }
        for source in &proof.sources {
            let Some(raw) = input.sources.get(&source.source_id) else {
                missing_source = true;
                report.view_reproduction = "not_checked".into();
                report.location = "not_checked".into();
                report.match_commitment = "not_checked".into();
                report.overall = "incomplete".into();
                continue;
            };
            let view = match apply_recipe(raw, &source.recipe) {
                Ok(view) => view,
                Err(_) => {
                    report.view_reproduction = "mismatch".into();
                    report.fail("view_reproduction");
                    return Ok(report);
                }
            };
            report.view_reproduction = "reproduced".into();
            if validate_intervals(
                Some(&view),
                source
                    .matches
                    .iter()
                    .map(|matched| (matched.start, matched.end)),
            )
            .is_err()
            {
                report.location = "mismatch".into();
                report.fail("location");
                return Ok(report);
            }
            for matched in &source.matches {
                report.location = "exact_coordinates".into();
                let Some(key) = input.commitment_key.as_deref() else {
                    report.match_commitment = "not_checked".into();
                    continue;
                };
                let expected_view = commitment(
                    key,
                    "pipelock/evidence-provenance/view/v1",
                    &[
                        u64_bytes(source.source_ordinal),
                        source.source_id.as_bytes().to_vec(),
                        source.recipe.profile.as_bytes().to_vec(),
                        recipe_bytes(&source.recipe)?,
                        view.as_bytes().to_vec(),
                    ],
                );
                if expected_view != source.view_commitment {
                    // Reproduction means the typed recipe ran and coordinates
                    // address that view. A view HMAC is a separate opening
                    // claim, so do not misreport this as failed reproduction.
                    if missing_source {
                        // Aggregate stages are only positive when every
                        // source can be reproduced. Still surface the later
                        // HMAC failure so a missing sibling cannot mask it.
                        report.view_reproduction = "not_checked".into();
                        report.location = "not_checked".into();
                    }
                    report.match_commitment = "mismatch".into();
                    report.fail("view_commitment");
                    return Ok(report);
                }
                let expected = commitment(
                    key,
                    "pipelock/evidence-provenance/match/v1",
                    &[
                        source.source_id.as_bytes().to_vec(),
                        source.recipe.profile.as_bytes().to_vec(),
                        recipe_bytes(&source.recipe)?,
                        source.view_commitment.as_bytes().to_vec(),
                        u64_bytes(matched.ordinal),
                        u64_bytes(matched.start),
                        u64_bytes(matched.end),
                        matched.class.as_bytes().to_vec(),
                    ],
                );
                if expected != matched.commitment {
                    report.match_commitment = "mismatch".into();
                    report.fail("match_commitment");
                    return Ok(report);
                }
                report.match_commitment = "opened".into();
            }
        }
    }
    if missing_source {
        report.view_reproduction = "not_checked".into();
        report.location = "not_checked".into();
        report.match_commitment = "not_checked".into();
    }
    // PR3 has no source commitment, so authenticated proof opening remains
    // incomplete by design until that future field exists.
    report.overall = "incomplete".into();
    Ok(report)
}

fn chain_fields_match(
    entry: &SignedEntry,
    expected_sequence: u64,
    expected_previous: &str,
) -> bool {
    let Ok(signed) = object(&entry.value, "signed") else {
        return false;
    };
    matches!(
        (signed.get("chain_seq").and_then(Value::as_u64), signed.get("chain_prev_hash").and_then(Value::as_str)),
        (Some(sequence), Some(previous)) if sequence == expected_sequence && previous == expected_previous
    )
}

fn signed_object(entry: &SignedEntry) -> std::result::Result<&Map<String, Value>, String> {
    let object = object(&entry.value, "signed")?;
    let mut allowed = HashSet::from([
        "chain_seq",
        "chain_prev_hash",
        "critical_features",
        "proof",
        "__fixture_signature",
    ]);
    if object.keys().any(|key| !allowed.remove(key.as_str())) || !allowed.is_empty() {
        return Err("signed: unknown or missing field".into());
    }
    Ok(object)
}

fn critical_features_ok(signed: &Map<String, Value>) -> bool {
    let Some(features) = signed.get("critical_features").and_then(Value::as_array) else {
        return false;
    };
    features.len() == 1 && features[0].as_str() == Some("evidence_provenance")
}

#[derive(Clone)]
struct Proof {
    producer: Producer,
    sources: Vec<ProofSource>,
}
#[derive(Clone)]
struct Producer {
    binary: Option<String>,
    ruleset: Option<String>,
}
#[derive(Clone)]
struct ProofSource {
    source_ordinal: u64,
    source_id: String,
    recipe: Recipe,
    view_commitment: String,
    matches: Vec<ProofMatch>,
}
#[derive(Clone)]
struct ProofMatch {
    ordinal: u64,
    start: u64,
    end: u64,
    class: String,
    commitment: String,
}
#[derive(Clone)]
struct Recipe {
    profile: String,
    operations: Vec<Operation>,
    executor: TransformRecipe,
}
#[derive(Clone)]
struct Operation {
    kind: String,
    component: String,
    selector: String,
    occurrence: u32,
    passes: u8,
    profile: String,
    padding: bool,
    alphabet: String,
    indices: Vec<u8>,
    minimum_length: u32,
}

fn parse_proof(value: &Value) -> std::result::Result<Proof, String> {
    let proof = object(value, "proof")?;
    exact_keys(
        proof,
        &["version", "transform_profile_digest", "sources", "producer"],
        "proof",
    )?;
    if string(proof, "version", "proof")? != PROOF_VERSION
        || string(proof, "transform_profile_digest", "proof")? != PROFILE_DIGEST
    {
        return Err("proof: unsupported version or profile".into());
    }
    let producer_value = object(required(proof, "producer", "proof")?, "proof.producer")?;
    exact_keys_with_optional(
        producer_value,
        &["binary_digest", "ruleset_digest"],
        &["binary_digest", "ruleset_digest"],
        "producer",
    )?;
    let producer = Producer {
        binary: optional_string(producer_value, "binary_digest")?.map(str::to_string),
        ruleset: optional_string(producer_value, "ruleset_digest")?.map(str::to_string),
    };
    for digest in [producer.binary.as_deref(), producer.ruleset.as_deref()]
        .into_iter()
        .flatten()
    {
        valid_digest(digest, "sha256:")?;
    }
    let mut prior_source = None;
    let mut ids = HashSet::new();
    let mut sources = Vec::new();
    for value in array(required(proof, "sources", "proof")?, "proof.sources")? {
        let source = object(value, "proof source")?;
        exact_keys(
            source,
            &[
                "source_ordinal",
                "source_id",
                "recipe",
                "view_commitment",
                "matches",
            ],
            "proof source",
        )?;
        let ordinal = u64_value(source, "source_ordinal", "proof source")?;
        let id = string(source, "source_id", "proof source")?.to_string();
        if id.is_empty()
            || !ids.insert(id.clone())
            || prior_source.is_some_and(|prior| ordinal <= prior)
        {
            return Err("proof source: duplicate or unordered identity".into());
        }
        prior_source = Some(ordinal);
        let recipe = parse_recipe(required(source, "recipe", "proof source")?)?;
        let commitment = string(source, "view_commitment", "proof source")?.to_string();
        valid_digest(&commitment, "hmac-sha256:")?;
        let mut matches = Vec::new();
        let mut prior_match_ordinal = None;
        for value in array(required(source, "matches", "proof source")?, "matches")? {
            let matched = object(value, "match")?;
            exact_keys(
                matched,
                &[
                    "match_ordinal",
                    "byte_start",
                    "byte_end",
                    "match_class",
                    "match_commitment",
                ],
                "match",
            )?;
            let ordinal = u64_value(matched, "match_ordinal", "match")?;
            let start = u64_value(matched, "byte_start", "match")?;
            let end = u64_value(matched, "byte_end", "match")?;
            let class = string(matched, "match_class", "match")?.to_string();
            if class.is_empty() {
                return Err("match: class is required".into());
            }
            let commitment = string(matched, "match_commitment", "match")?.to_string();
            valid_digest(&commitment, "hmac-sha256:")?;
            if prior_match_ordinal.is_some_and(|prior| ordinal <= prior) {
                return Err("match: invalid ordinal order".into());
            }
            prior_match_ordinal = Some(ordinal);
            matches.push(ProofMatch {
                ordinal,
                start,
                end,
                class,
                commitment,
            });
        }
        validate_intervals(
            None,
            matches.iter().map(|matched| (matched.start, matched.end)),
        )?;
        sources.push(ProofSource {
            source_ordinal: ordinal,
            source_id: id,
            recipe,
            view_commitment: commitment,
            matches,
        });
    }
    Ok(Proof { producer, sources })
}

fn parse_recipe(value: &Value) -> std::result::Result<Recipe, String> {
    let recipe = object(value, "recipe")?;
    exact_keys(
        recipe,
        &["transform_profile_digest", "operations"],
        "recipe",
    )?;
    let profile = string(recipe, "transform_profile_digest", "recipe")?.to_string();
    if profile.is_empty() {
        return Err("missing transform profile digest".into());
    }
    if profile != PROFILE_DIGEST {
        return Err("recipe: unknown transform profile".into());
    }
    let operation_values = required(recipe, "operations", "recipe")?;
    let executor = TransformRecipe::from_json(&profile, operation_values)?;
    let mut operations = Vec::new();
    for value in array(operation_values, "operations")? {
        let operation = object(value, "operation")?;
        let allowed = [
            "kind",
            "component",
            "selector",
            "occurrence",
            "passes",
            "profile",
            "decode_padding",
            "alphabet",
            "indices",
            "minimum_length",
        ];
        if operation.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err("operation: unknown field".into());
        }
        let op = Operation {
            kind: string(operation, "kind", "operation")?.to_string(),
            component: optional_string(operation, "component")?
                .unwrap_or("")
                .to_string(),
            selector: optional_string(operation, "selector")?
                .unwrap_or("")
                .to_string(),
            occurrence: optional_u64(operation, "occurrence")?
                .unwrap_or(0)
                .try_into()
                .map_err(|_| "operation: occurrence out of range")?,
            passes: optional_u64(operation, "passes")?
                .unwrap_or(0)
                .try_into()
                .map_err(|_| "operation: passes out of range")?,
            profile: optional_string(operation, "profile")?
                .unwrap_or("")
                .to_string(),
            padding: operation
                .get("decode_padding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            alphabet: optional_string(operation, "alphabet")?
                .unwrap_or("")
                .to_string(),
            indices: match operation.get("indices") {
                None => Vec::new(),
                Some(value) => array(value, "operation indices")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .ok_or_else(|| "operation index must be unsigned".to_string())?
                            .try_into()
                            .map_err(|_| "operation index exceeds uint8".to_string())
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            },
            minimum_length: optional_u64(operation, "minimum_length")?
                .unwrap_or(0)
                .try_into()
                .map_err(|_| "operation minimum_length exceeds uint32")?,
        };
        operations.push(op);
    }
    Ok(Recipe {
        profile,
        operations,
        executor,
    })
}

enum Stage {
    Matched,
    Unchecked,
    Mismatch,
}
fn verify_artifacts(proof: &Proof, input: &VerificationInput) -> Stage {
    let checks = [
        (proof.producer.binary.as_deref(), input.binary.as_deref()),
        (proof.producer.ruleset.as_deref(), input.ruleset.as_deref()),
    ];
    let mut unchecked = false;
    let mut mismatch = false;
    for (claim, bytes) in checks {
        if let Some(claim) = claim {
            match bytes {
                Some(bytes) if claim == format!("sha256:{}", sha256_hex(bytes)) => {}
                Some(_) => mismatch = true,
                None => unchecked = true,
            }
        }
    }
    if mismatch {
        Stage::Mismatch
    } else if unchecked {
        Stage::Unchecked
    } else {
        Stage::Matched
    }
}

fn apply_recipe(input: &str, recipe: &Recipe) -> std::result::Result<String, String> {
    recipe.executor.apply(input)
}

fn recipe_bytes(recipe: &Recipe) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    frame_into(&mut bytes, b"pipelock/evidence-provenance/recipe/v1");
    frame_into(&mut bytes, recipe.profile.as_bytes());
    frame_into(&mut bytes, &u64_bytes(recipe.operations.len() as u64));
    for operation in &recipe.operations {
        let mut encoded = Vec::new();
        frame_into(&mut encoded, &[kind_byte(&operation.kind)?]);
        frame_into(&mut encoded, &[component_byte(&operation.component)?]);
        frame_into(&mut encoded, operation.selector.as_bytes());
        frame_into(&mut encoded, &operation.occurrence.to_be_bytes());
        frame_into(&mut encoded, &[operation.passes]);
        frame_into(&mut encoded, operation.profile.as_bytes());
        frame_into(&mut encoded, &[u8::from(operation.padding)]);
        if kind_byte(&operation.kind)? >= 12 {
            frame_into(&mut encoded, operation.alphabet.as_bytes());
            frame_into(&mut encoded, &operation.indices);
            frame_into(&mut encoded, &operation.minimum_length.to_be_bytes());
        }
        frame_into(&mut bytes, &encoded);
    }
    Ok(bytes)
}
fn kind_byte(kind: &str) -> std::result::Result<u8, String> {
    match kind {
        "identity" => Ok(1),
        "url_component" => Ok(2),
        "percent_decode" => Ok(3),
        "dlp_normalize" => Ok(4),
        "lowercase" => Ok(5),
        "invisible_strip" => Ok(6),
        "hex_decode" => Ok(7),
        "base32_decode" => Ok(8),
        "base64_decode" => Ok(9),
        "leetspeak" => Ok(10),
        "vowel_fold" => Ok(11),
        "query_unescape" => Ok(12),
        "invisible_space" => Ok(13),
        "matching_normalize" => Ok(14),
        "hex_decode_liberal" => Ok(15),
        "base32_decode_liberal" => Ok(16),
        "base64_decode_liberal" => Ok(17),
        "encoded_token_normalize" => Ok(18),
        "text_segment" => Ok(19),
        "html_entity_decode" => Ok(20),
        "whitespace_compact" => Ok(21),
        "url_noise_strip" => Ok(22),
        "ordered_query_concat" => Ok(23),
        "query_subsequence" => Ok(24),
        "hostname_dot_remove" => Ok(25),
        "encoded_run" => Ok(26),
        "canary_canonicalize" => Ok(27),
        _ => Err("unknown operation".into()),
    }
}
fn component_byte(component: &str) -> std::result::Result<u8, String> {
    match component {
        "" => Ok(0),
        "url" => Ok(1),
        "hostname" => Ok(2),
        "path" => Ok(3),
        "query_key" => Ok(4),
        "query_value" => Ok(5),
        "raw_query" => Ok(6),
        _ => Err("unknown component".into()),
    }
}
fn commitment(key: &[u8], domain: &str, parts: &[Vec<u8>]) -> String {
    let mut mac = Hmac::<HmacSha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    let mut framed = Vec::new();
    frame_into(&mut framed, domain.as_bytes());
    for part in parts {
        frame_into(&mut framed, part)
    }
    mac.update(&framed);
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}
fn frame_into(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value)
}
fn u64_bytes(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
fn validate_intervals<I>(view: Option<&str>, intervals: I) -> std::result::Result<(), String>
where
    I: IntoIterator<Item = (u64, u64)>,
{
    let mut previous = None;
    for (start, end) in intervals {
        if end <= start {
            return Err("byte end must be greater".into());
        }
        if let Some(view) = view {
            if end > view.len() as u64 {
                return Err("out of bounds".into());
            }
            if !byte_boundary(view, start) || !byte_boundary(view, end) {
                return Err("splits UTF-8".into());
            }
        }
        if let Some((previous_start, previous_end)) = previous {
            if start < previous_start {
                return Err("unsorted".into());
            }
            if start == previous_start {
                return Err("duplicate".into());
            }
            if start < previous_end {
                return Err("overlap".into());
            }
        }
        previous = Some((start, end));
    }
    Ok(())
}

fn byte_boundary(view: &str, offset: u64) -> bool {
    offset == 0
        || offset == view.len() as u64
        || (offset < view.len() as u64 && view.as_bytes()[offset as usize] & 0xc0 != 0x80)
}

fn object<'a>(
    value: &'a Value,
    label: &str,
) -> std::result::Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label}: must be an object"))
}
fn array<'a>(value: &'a Value, label: &str) -> std::result::Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label}: must be an array"))
}
fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("{label}: missing {key}"))
}
fn string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<&'a str, String> {
    required(object, key, label)?
        .as_str()
        .ok_or_else(|| format!("{label}: {key} must be a string"))
}
fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("{key}: must be a string when present")),
    }
}
fn u64_value(
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<u64, String> {
    required(object, key, label)?
        .as_u64()
        .ok_or_else(|| format!("{label}: {key} must be an unsigned integer"))
}
fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<u64>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("operation: {key} must be unsigned")),
    }
}
fn exact_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    exact_keys_with_optional(object, allowed, &[], label)
}

fn exact_keys_with_optional(
    object: &Map<String, Value>,
    allowed: &[&str],
    optional: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || allowed
            .iter()
            .any(|key| !object.contains_key(*key) && !optional.contains(key))
    {
        Err(format!("{label}: unknown or missing field"))
    } else {
        Ok(())
    }
}
fn decode_b64(value: &str, label: &str) -> std::result::Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| format!("{label}: invalid base64"))
}
fn decode_hex(value: &str, length: usize, label: &str) -> std::result::Result<Vec<u8>, String> {
    if value
        .chars()
        .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
    {
        return Err(format!("{label}: invalid lowercase hex"));
    };
    let bytes = hex::decode(value).map_err(|_| format!("{label}: invalid hex"))?;
    if length != 0 && bytes.len() != length {
        return Err(format!("{label}: wrong length"));
    };
    Ok(bytes)
}
fn valid_digest(value: &str, prefix: &str) -> std::result::Result<(), String> {
    let hex = value
        .strip_prefix(prefix)
        .ok_or_else(|| "digest prefix".to_string())?;
    if hex.len() != 64 {
        return Err("digest length".into());
    };
    decode_hex(hex, 32, "digest").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct TransformCorpus {
        profile_digest: String,
        vectors: Vec<TransformVector>,
        interval_vectors: Vec<IntervalVector>,
    }

    #[derive(Deserialize)]
    struct TransformVector {
        id: String,
        input_b64: String,
        #[serde(default)]
        output_b64: String,
        #[serde(default)]
        want_error: String,
        transform_profile_digest: Option<String>,
        recipe: Option<Value>,
    }

    #[derive(Deserialize)]
    struct IntervalVector {
        id: String,
        view_b64: String,
        matches: Vec<[u64; 2]>,
        want_error: String,
    }

    #[test]
    fn transform_profile_corpus_is_byte_exact() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/transform-profile/evidence-provenance-v1.json"
        );
        let corpus: TransformCorpus =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let TransformCorpus {
            profile_digest,
            vectors,
            ..
        } = corpus;
        assert_eq!(vectors.len(), 63, "corpus vector count changed");
        for vector in vectors {
            let input = STANDARD.decode(&vector.input_b64).unwrap();
            let result = String::from_utf8(input)
                .map_err(|_| "invalid UTF-8".to_string())
                .and_then(|input| {
                    let recipe = json!({
                        "transform_profile_digest": vector
                            .transform_profile_digest
                            .as_deref()
                            .unwrap_or(&profile_digest),
                        "operations": vector.recipe.unwrap_or_else(|| json!([])),
                    });
                    TransformRecipe::from_json(
                        recipe["transform_profile_digest"]
                            .as_str()
                            .unwrap_or_default(),
                        &recipe["operations"],
                    )
                    .and_then(|recipe| recipe.apply(&input))
                });
            if vector.want_error.is_empty() {
                let output = STANDARD.decode(&vector.output_b64).unwrap();
                assert_eq!(result.unwrap().as_bytes(), output, "{}", vector.id);
            } else {
                let error = result.expect_err(&vector.id);
                assert!(
                    error.contains(&vector.want_error),
                    "{} error={error:?} want={:?}",
                    vector.id,
                    vector.want_error
                );
            }
        }
    }

    #[test]
    fn interval_corpus_exercises_utf8_boundaries_and_ordering() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/transform-profile/evidence-provenance-v1.json"
        );
        let corpus: TransformCorpus =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            corpus.interval_vectors.len(),
            8,
            "interval vector count changed"
        );
        for vector in corpus.interval_vectors {
            let view = String::from_utf8(STANDARD.decode(&vector.view_b64).unwrap()).unwrap();
            let result = validate_intervals(
                Some(&view),
                vector.matches.iter().map(|bounds| (bounds[0], bounds[1])),
            );
            if vector.want_error.is_empty() {
                result.unwrap();
            } else {
                let error = result.expect_err(&vector.id);
                assert!(
                    error.contains(&vector.want_error),
                    "{} error={error:?} want={:?}",
                    vector.id,
                    vector.want_error
                );
            }
        }
    }

    #[test]
    fn interval_corpus_exercises_structural_rules_without_a_view() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/transform-profile/evidence-provenance-v1.json"
        );
        let corpus: TransformCorpus =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            corpus.interval_vectors.len(),
            8,
            "interval vector count changed"
        );
        for vector in corpus.interval_vectors {
            if matches!(vector.want_error.as_str(), "splits UTF-8" | "out of bounds") {
                continue;
            }
            let result = validate_intervals(
                None,
                vector.matches.iter().map(|bounds| (bounds[0], bounds[1])),
            );
            if vector.want_error.is_empty() {
                result.unwrap();
            } else {
                let error = result.expect_err(&vector.id);
                assert!(
                    error.contains(&vector.want_error),
                    "{} error={error:?} want={:?}",
                    vector.id,
                    vector.want_error
                );
            }
        }
    }

    #[test]
    fn valid_fixture_is_incomplete_without_commitment_key() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["evidence_provenance"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"sources":[],"producer":{}}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"sources":[]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.signature, "verified");
        assert_eq!(report.chain, "verified");
        assert_eq!(report.overall, "incomplete");
        assert_eq!(serde_json::to_string(&report).unwrap(),"{\"trust_roots\":\"fixture supplied; self-attested; not authenticated\",\"authenticated_provenance\":false,\"signature\":\"verified\",\"chain\":\"verified\",\"artifacts\":\"matched\",\"source_commitment\":\"not_checked\",\"view_reproduction\":\"not_checked\",\"location\":\"not_checked\",\"match_commitment\":\"not_checked\",\"overall\":\"incomplete\"}");
    }

    #[test]
    fn empty_match_class_fixture_fails_at_proof_structure() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p34-empty-match-class.json"
        );
        let report = verify_fixture_bytes(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report.failure_stage.as_deref(), Some("proof_structure"));
    }

    #[test]
    fn unknown_critical_feature_has_its_own_failure_stage() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["unknown"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"sources":[],"producer":{}}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"sources":[]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.failure_stage.as_deref(), Some("critical_features"));
    }

    #[test]
    fn byte_boundary_is_a_location_failure_after_view_reproduction() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let commitment_key = vec![4; 32];
        let recipe = parse_recipe(&json!({
            "transform_profile_digest": PROFILE_DIGEST,
            "operations": [{"kind": "identity"}],
        }))
        .unwrap();
        let view = "A💩B";
        let view_commitment = commitment(
            &commitment_key,
            "pipelock/evidence-provenance/view/v1",
            &[
                u64_bytes(0),
                b"source".to_vec(),
                PROFILE_DIGEST.as_bytes().to_vec(),
                recipe_bytes(&recipe).unwrap(),
                view.as_bytes().to_vec(),
            ],
        );
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["evidence_provenance"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"producer":{},"sources":[{"source_ordinal":0,"source_id":"source","recipe":{"transform_profile_digest":PROFILE_DIGEST,"operations":[{"kind":"identity"}]},"view_commitment":view_commitment,"matches":[{"match_ordinal":0,"byte_start":2,"byte_end":5,"match_class":"credential","match_commitment":format!("hmac-sha256:{}", "0".repeat(64))}]}]}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"commitment_key_hex":hex::encode(&commitment_key),"sources":[{"source_id":"source","bytes_b64":STANDARD.encode(view)}]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "reproduced");
        assert_eq!(report.location, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("location"));
    }

    #[test]
    fn artifact_mismatch_outranks_a_missing_sibling_artifact() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let signed = json!({
            "chain_seq": 0,
            "chain_prev_hash": "genesis",
            "critical_features": ["evidence_provenance"],
            "proof": {
                "version": PROOF_VERSION,
                "transform_profile_digest": PROFILE_DIGEST,
                "sources": [],
                "producer": {
                    "binary_digest": format!("sha256:{}", sha256_hex(b"binary")),
                    "ruleset_digest": format!("sha256:{}", sha256_hex(b"expected-rules"))
                }
            }
        });
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({
            "format": FIXTURE_FORMAT,
            "entries": [{
                "signed_b64": STANDARD.encode(&bytes),
                "signature": format!("ed25519:{}", hex::encode(signing.sign(&bytes).to_bytes()))
            }],
            "verification": {
                "signer_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
                "ruleset_b64": STANDARD.encode("wrong-rules")
            }
        });
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.artifacts, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("artifacts"));
    }

    #[test]
    fn later_available_source_still_invalidates_after_missing_source() {
        let signing = SigningKey::from_bytes(&[11; 32]);
        let commitment_key = vec![5; 32];
        let source = |ordinal: u64, id: &str, commitment: String| {
            json!({
                "source_ordinal": ordinal,
                "source_id": id,
                "recipe": {"transform_profile_digest": PROFILE_DIGEST, "operations": [{"kind":"identity"}]},
                "view_commitment": commitment,
                "matches": [{
                    "match_ordinal": 0,
                    "byte_start": 0,
                    "byte_end": 5,
                    "match_class": "credential",
                    "match_commitment": format!("hmac-sha256:{}", "0".repeat(64))
                }]
            })
        };
        let signed = json!({
            "chain_seq": 0,
            "chain_prev_hash": "genesis",
            "critical_features": ["evidence_provenance"],
            "proof": {
                "version": PROOF_VERSION,
                "transform_profile_digest": PROFILE_DIGEST,
                "producer": {},
                "sources": [
                    source(0, "missing", format!("hmac-sha256:{}", "0".repeat(64))),
                    source(1, "available", format!("hmac-sha256:{}", "0".repeat(64)))
                ]
            }
        });
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({
            "format": FIXTURE_FORMAT,
            "entries": [{
                "signed_b64": STANDARD.encode(&bytes),
                "signature": format!("ed25519:{}", hex::encode(signing.sign(&bytes).to_bytes()))
            }],
            "verification": {
                "signer_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
                "commitment_key_hex": hex::encode(commitment_key),
                "sources": [{"source_id":"available", "bytes_b64": STANDARD.encode("value")}]
            }
        });
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "not_checked");
        assert_eq!(report.location, "not_checked");
        assert_eq!(report.match_commitment, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("view_commitment"));
    }

    #[test]
    fn missing_source_before_valid_source_downgrades_aggregate_stages() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p28-missing-source-before-valid-source.json"
        );
        let report = verify_fixture_bytes(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "not_checked");
        assert_eq!(report.location, "not_checked");
        assert_eq!(report.match_commitment, "not_checked");
        assert_eq!(report.overall, "incomplete");
    }

    #[test]
    fn commitment_implementation_matches_frozen_known_answer() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p00-valid.json"
        );
        let report = verify_fixture_bytes(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report.match_commitment, "opened");
        assert_eq!(report.overall, "incomplete");
    }

    #[test]
    fn duplicate_keys_in_envelope_and_signed_payload_are_rejected() {
        let envelope = br#"{"format":"one","format":"two","entries":[],"verification":{}}"#;
        assert!(verify_fixture_bytes(envelope)
            .expect_err("duplicate fixture key must fail")
            .contains("duplicate"));

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p29-duplicate-signed-key.json"
        );
        assert!(verify_fixture_bytes(&std::fs::read(path).unwrap())
            .expect_err("duplicate signed key must fail")
            .contains("duplicate"));
    }

    #[test]
    fn required_fields_are_not_inferred_optional_by_name() {
        let present = json!({"binary_digest": "value"});
        exact_keys(
            present.as_object().unwrap(),
            &["binary_digest"],
            "required field",
        )
        .unwrap();

        let absent = json!({});
        assert!(exact_keys(
            absent.as_object().unwrap(),
            &["binary_digest"],
            "required field",
        )
        .is_err());
    }
}

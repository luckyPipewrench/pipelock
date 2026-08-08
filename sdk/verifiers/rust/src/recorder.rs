// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::types::Receipt;
use crate::util::{parse_json_line, reject_duplicate_keys, Result, VerifierError};
use std::fs;
use std::path::Path;

const ACTION_RECEIPT_TYPE: &str = "action_receipt";
const EVIDENCE_RECEIPT_TYPE: &str = "evidence_receipt";

// AF-37 receipt-chain mode: the known non-receipt operational entry types that
// extraction legitimately skips. Any entry whose type is outside the union of
// the receipt types and this set is REJECTED (fail-closed) rather than silently
// skipped, so a file mixing a valid chain with an unknown record type cannot be
// reported as a valid receipt subsequence.
const SKIPPABLE_ENTRY_TYPES: &[&str] = &[
    "checkpoint",
    "transcript_root",
    "decision",
    "capture",
    "capture_drop",
];

pub fn read_entries(path: &Path) -> Result<Vec<serde_json::Value>> {
    let text = fs::read_to_string(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    let mut entries = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_json_line(line, &format!("line {}", index + 1))?;
        reject_duplicate_keys(line)
            .map_err(|err| VerifierError::Invalid(format!("line {}: {}", index + 1, err)))?;
        let version = entry.get("v").and_then(serde_json::Value::as_u64);
        if version != Some(1) && version != Some(2) && version != Some(3) {
            errors_unsupported(index + 1, version)?;
        }
        validate_projected_strings(&entry, index + 1, version.unwrap_or_default())?;
        if version == Some(3)
            && entry
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .is_none()
        {
            return Err(VerifierError::Runtime(format!(
                "line {}: v3 seq must be an unsigned 64-bit integer",
                index + 1
            )));
        }
        if version != Some(3)
            && (legacy_namespace_field_is_set(&entry, "chain_kind")
                || legacy_namespace_field_is_set(&entry, "writer_instance_id"))
        {
            return Err(VerifierError::Invalid(format!(
                "line {}: legacy entry cannot carry v3 recorder namespace fields",
                index + 1
            )));
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn legacy_namespace_field_is_set(entry: &serde_json::Value, field: &str) -> bool {
    match entry.get(field) {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(value)) => !value.is_empty(),
        Some(_) => true,
    }
}

pub fn extract_receipts(path: &Path) -> Result<Vec<Receipt>> {
    let mut receipts = Vec::new();
    for entry in read_entries(path)? {
        let entry_type = entry.get("type").and_then(serde_json::Value::as_str);
        let is_receipt =
            entry_type == Some(ACTION_RECEIPT_TYPE) || entry_type == Some(EVIDENCE_RECEIPT_TYPE);
        if !is_receipt {
            let known = entry_type.is_some_and(|t| SKIPPABLE_ENTRY_TYPES.contains(&t));
            if known {
                continue;
            }
            return Err(VerifierError::Invalid(format!(
                "unexpected recorder entry type {:?} at seq {}",
                entry_type.unwrap_or("null"),
                entry
                    .get("seq")
                    .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
            )));
        }
        let detail = entry.get("detail").ok_or_else(|| {
            VerifierError::Runtime(format!(
                "entry seq {}: receipt detail is not an object",
                entry
                    .get("seq")
                    .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
            ))
        })?;
        if !detail.is_object() {
            return Err(VerifierError::Runtime(format!(
                "entry seq {}: receipt detail is not an object",
                entry
                    .get("seq")
                    .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
            )));
        }
        // EV2-FU-1: an extracted v1 action receipt must satisfy the strict
        // unknown-field contract (evidence_receipt v2 has its own schema).
        if entry_type == Some(ACTION_RECEIPT_TYPE) {
            crate::strict::validate_v1_receipt(detail).map_err(|err| {
                VerifierError::Invalid(format!(
                    "entry seq {}: {err}",
                    entry
                        .get("seq")
                        .map_or_else(|| "null".to_string(), serde_json::Value::to_string)
                ))
            })?;
        }
        receipts.push(detail.clone());
    }
    Ok(receipts)
}

pub fn extract_receipts_from_session_dir(dir: &Path, session_id: &str) -> Result<Vec<Receipt>> {
    let prefix = format!("evidence-{session_id}-");
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", dir.display())))?
    {
        let entry =
            entry.map_err(|err| VerifierError::Runtime(format!("read dir entry: {err}")))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if entry
            .file_type()
            .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", name)))?
            .is_dir()
            || !name.starts_with(&prefix)
            || !name.ends_with(".jsonl")
        {
            continue;
        }
        files.push(entry.path());
    }
    let mut files = files
        .into_iter()
        .map(|path| seq_start(&path).map(|seq| (seq, path)))
        .collect::<Result<Vec<_>>>()?;
    files.sort_by_key(|(seq, _)| *seq);
    let mut receipts = Vec::new();
    for (_, file) in files {
        receipts.extend(extract_receipts(&file)?);
    }
    Ok(receipts)
}

fn seq_start(path: &Path) -> Result<u64> {
    let name = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let suffix = name
        .rsplit_once('-')
        .map(|(_, suffix)| suffix)
        .unwrap_or("");
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(VerifierError::Runtime(format!(
            "evidence file has non-numeric sequence suffix: {}",
            display_path(path)
        )));
    }
    suffix.parse::<u64>().map_err(|_| {
        VerifierError::Runtime(format!(
            "evidence file has non-numeric sequence suffix: {}",
            display_path(path)
        ))
    })
}

fn errors_unsupported(line: usize, version: Option<u64>) -> Result<()> {
    Err(VerifierError::Runtime(format!(
        "line {line}: unsupported entry version {} (accepted: 1, 2, 3)",
        version.map_or_else(|| "null".to_string(), |value| value.to_string())
    )))
}

fn validate_projected_strings(entry: &serde_json::Value, line: usize, version: u64) -> Result<()> {
    let mut fields = vec![
        "ts",
        "session_id",
        "trace_id",
        "type",
        "event_kind",
        "transport",
        "summary",
        "raw_ref",
        "prev_hash",
    ];
    if version == 3 {
        fields.extend(["chain_kind", "writer_instance_id"]);
    }
    for field in fields {
        let missing = entry.get(field).is_none();
        let value = match entry.get(field) {
            None => "",
            Some(value) => match value.as_str() {
                Some(value) => value,
                None if version != 3 => continue,
                None => {
                    return Err(VerifierError::Runtime(format!(
                        "line {line}: v3 {field} must be a string"
                    )))
                }
            },
        };
        let required = version == 3
            && matches!(
                field,
                "ts" | "session_id"
                    | "chain_kind"
                    | "writer_instance_id"
                    | "type"
                    | "transport"
                    | "summary"
                    | "prev_hash"
            );
        let namespace_required = field == "chain_kind" || field == "writer_instance_id";
        if (required && missing) || (version == 3 && namespace_required && value.is_empty()) {
            return Err(VerifierError::Runtime(format!(
                "line {line}: v3 {field} required"
            )));
        }
        if value.contains('\0') {
            return Err(VerifierError::Runtime(format!(
                "line {line}: v{version} {field} cannot contain NUL"
            )));
        }
        if version == 3 && field == "ts" {
            crate::aarp::envelope::validate_timestamp(value, "recorder ts")
                .map_err(|err| VerifierError::Runtime(format!("line {line}: {err}")))?;
        }
    }
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

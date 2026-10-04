// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::types::Receipt;
use crate::util::{
    parse_json_line, read_verifier_text, reject_duplicate_keys, Result, VerifierError,
};
use std::path::Path;

const ACTION_RECEIPT_TYPE: &str = "action_receipt";
const EVIDENCE_RECEIPT_TYPE: &str = "evidence_receipt";

// Receipt-chain mode: the known non-receipt operational entry types that
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
    Ok(read_entry_lines(path)?
        .into_iter()
        .map(|line| line.entry)
        .collect())
}

/// One validated recorder entry, the Go-encoded source bytes of an action
/// receipt's ext bag when it has one, and the trimmed source line, which the
/// recorder hash chain check needs byte for byte. The input file is bounded
/// by the verifier's read limit, so keeping the lines is bounded too.
#[derive(Clone)]
pub(crate) struct RecorderLine {
    pub(crate) entry: serde_json::Value,
    pub(crate) ext: Option<String>,
    pub(crate) line: String,
}

pub(crate) fn read_entry_lines(path: &Path) -> Result<Vec<RecorderLine>> {
    let text = read_verifier_text(path)?;
    read_entry_lines_text(&text)
}

/// Parses recorder entries from already validated UTF-8 text. Recovery-seal
/// verification uses this for the complete, newline-terminated prefix of a
/// damaged final shard without copying or rewriting evidence on disk.
pub(crate) fn read_entry_lines_text(text: &str) -> Result<Vec<RecorderLine>> {
    let mut entries = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_json_line(line, &format!("line {}", index + 1))?;
        reject_duplicate_keys(line)
            .map_err(|err| VerifierError::Invalid(format!("line {}: {}", index + 1, err)))?;
        if entry.get("type").and_then(serde_json::Value::as_str) == Some(EVIDENCE_RECEIPT_TYPE) {
            if let Some(detail) = entry.get("detail") {
                if let Some((start, end)) = crate::rawjson::object_member_span(line, 0, "detail") {
                    crate::secret_egress::validate_raw_receipt(detail, &line[start..end]).map_err(
                        |err| VerifierError::Invalid(format!("line {}: {err}", index + 1)),
                    )?;
                }
            }
        }
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
        let ext_bytes =
            if entry.get("type").and_then(serde_json::Value::as_str) == Some(ACTION_RECEIPT_TYPE) {
                crate::rawjson::recorder_line_ext_bytes(line)
            } else {
                None
            };
        entries.push(RecorderLine {
            entry,
            ext: ext_bytes,
            line: line.to_string(),
        });
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

#[derive(Default)]
pub(crate) struct ExtractedReceipts {
    pub(crate) action: Vec<Receipt>,
    pub(crate) evidence: Vec<Receipt>,
}

impl ExtractedReceipts {
    // select_chain mirrors the Go reference receipt-chain mode, which verifies
    // the action_receipt subsequence and skips evidence_receipt entries. A
    // default Pipelock run interleaves both types in one file, each on its own
    // chain. A file that carries only evidence_receipt entries is verified as
    // an evidence_receipt_v2 chain.
    pub(crate) fn select_chain(self) -> Vec<Receipt> {
        if self.action.is_empty() {
            self.evidence
        } else {
            self.action
        }
    }
}

pub fn extract_receipts(path: &Path) -> Result<Vec<Receipt>> {
    Ok(extract_typed_receipts(path)?.select_chain())
}

pub(crate) fn extract_typed_receipts(path: &Path) -> Result<ExtractedReceipts> {
    extract_typed_from_lines(read_entry_lines(path)?)
}

/// Splits already-read recorder entries into the two receipt chains, refusing
/// any entry type it does not know.
pub(crate) fn extract_typed_from_lines(lines: Vec<RecorderLine>) -> Result<ExtractedReceipts> {
    let mut extracted = ExtractedReceipts::default();
    for RecorderLine {
        entry,
        ext: ext_bytes,
        ..
    } in lines
    {
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
        let mut receipt = detail.clone();
        if entry_type == Some(ACTION_RECEIPT_TYPE) {
            if let (Some(bytes), Some(object)) = (ext_bytes, receipt.as_object_mut()) {
                object.insert(
                    crate::rawjson::EXT_SOURCE_KEY.to_string(),
                    serde_json::Value::String(bytes),
                );
            }
            extracted.action.push(receipt);
        } else {
            extracted.evidence.push(receipt);
        }
    }
    Ok(extracted)
}

/// Returns one session's selected receipt chain. Membership is Go's
/// parsed-equality rule (`evidencename.Parse`), shared with the chain-set
/// reader: for session `s`, `evidence-s-evil-0.jsonl` belongs to session
/// `s-evil` and is not read, although it starts with `evidence-s-`.
pub fn extract_receipts_from_session_dir(dir: &Path, session_id: &str) -> Result<Vec<Receipt>> {
    Ok(extract_typed_receipts_from_session_dir(dir, session_id)?.select_chain())
}

/// Returns one session's action-receipt and evidence-receipt chains.
pub(crate) fn extract_typed_receipts_from_session_dir(
    dir: &Path,
    session_id: &str,
) -> Result<ExtractedReceipts> {
    let (action, evidence) =
        crate::chain_set::read_session_receipts(dir, session_id).map_err(VerifierError::Runtime)?;
    Ok(ExtractedReceipts { action, evidence })
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

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::line_space::trim_go_space;
use crate::types::Receipt;
use crate::util::{
    open_verifier_file, parse_json_line, reject_duplicate_keys, same_open_file, Result,
    VerifierError,
};
use std::fs::Metadata;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

const MAX_RECORDER_LINE_BYTES: usize = 1 << 20;

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
/// recorder hash chain check needs byte for byte. Collection memory is
/// proportional to parsed entries, although input bytes are streamed.
#[derive(Clone)]
pub(crate) struct RecorderLine {
    pub(crate) entry: serde_json::Value,
    pub(crate) ext: Option<String>,
    pub(crate) line: String,
}

pub(crate) fn read_entry_lines(path: &Path) -> Result<Vec<RecorderLine>> {
    read_entry_lines_using(path, read_entry_lines_text_from)
}

pub(crate) fn read_entry_lines_prefix(path: &Path) -> Result<(Vec<RecorderLine>, bool)> {
    read_entry_lines_prefix_using(path, true, read_entry_lines_text_from)
}

fn read_entry_lines_using(
    path: &Path,
    parse_line: impl FnMut(&str, usize) -> Result<Vec<RecorderLine>>,
) -> Result<Vec<RecorderLine>> {
    read_entry_lines_prefix_using(path, false, parse_line).map(|(entries, _)| entries)
}

fn read_entry_lines_prefix_using(
    path: &Path,
    skip_unterminated_tail: bool,
    mut parse_line: impl FnMut(&str, usize) -> Result<Vec<RecorderLine>>,
) -> Result<(Vec<RecorderLine>, bool)> {
    let file = open_verifier_file(path)?;
    let before = file
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?;
    let mut reader = BufReader::new(file).take(before.len());
    let parsed = (|| {
        let mut entries = Vec::new();
        let mut line_number = 0usize;
        let mut torn = false;
        loop {
            let mut raw = Vec::new();
            let read = reader
                .by_ref()
                .take((MAX_RECORDER_LINE_BYTES + 3) as u64)
                .read_until(b'\n', &mut raw)
                .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
            if read == 0 {
                break;
            }
            line_number += 1;
            let terminated = raw.last() == Some(&b'\n');
            let mut payload_len = raw.len();
            if terminated {
                payload_len -= 1;
                if payload_len > 0 && raw[payload_len - 1] == b'\r' {
                    payload_len -= 1;
                }
            }
            if payload_len > MAX_RECORDER_LINE_BYTES || raw.len() > MAX_RECORDER_LINE_BYTES + 2 {
                return Err(VerifierError::Runtime(format!(
                    "line {line_number}: exceeds {MAX_RECORDER_LINE_BYTES}-byte recorder entry limit"
                )));
            }
            if skip_unterminated_tail && !terminated {
                torn = true;
                break;
            }
            let text = String::from_utf8(raw)
                .map_err(|err| VerifierError::Runtime(format!("input is not UTF-8: {err}")))?;
            entries.extend(parse_line(&text, line_number)?);
        }
        Ok((entries, torn))
    })();
    let after = reader
        .get_ref()
        .get_ref()
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?;
    let reopened = open_verifier_file(path)?;
    if !same_open_file(reader.get_ref().get_ref(), &reopened)?
        || !same_file_snapshot(&before, &after)
    {
        return Err(VerifierError::Runtime(
            "input changed while reading".to_string(),
        ));
    }
    parsed
}

// Unix ctime detects ordinary same-inode overwrites even when mtime is
// restored. Windows and filesystems with coarse/change-time semantics expose
// weaker metadata here; this check detects observed changes but is not an
// atomic snapshot guarantee.
fn same_file_snapshot(before: &Metadata, after: &Metadata) -> bool {
    if before.len() != after.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        // Windows and other supported non-Unix targets expose last-write time
        // here, but not a portable change-time/ctime with Unix semantics. A
        // same-size rewrite with a restored/coarse timestamp may go undetected.
        before.modified().ok() == after.modified().ok()
    }
}

/// Parses recorder entries from already validated UTF-8 text. Recovery-seal
/// verification uses this for the complete, newline-terminated prefix of a
/// damaged final shard without copying or rewriting evidence on disk.
pub(crate) fn read_entry_lines_text(text: &str) -> Result<Vec<RecorderLine>> {
    read_entry_lines_text_from(text, 1)
}

fn read_entry_lines_text_from(text: &str, first_line: usize) -> Result<Vec<RecorderLine>> {
    let mut entries = Vec::new();
    for (index, raw_line) in text.split_terminator('\n').enumerate() {
        let line_number = first_line + index;
        let line = trim_go_space(raw_line);
        if line.is_empty() {
            continue;
        }
        let entry = parse_json_line(line, &format!("line {line_number}"))?;
        reject_duplicate_keys(line)
            .map_err(|err| VerifierError::Invalid(format!("line {line_number}: {err}")))?;
        if entry.get("type").and_then(serde_json::Value::as_str) == Some(EVIDENCE_RECEIPT_TYPE) {
            if let Some(detail) = entry.get("detail") {
                if let Some((start, end)) = crate::rawjson::object_member_span(line, 0, "detail") {
                    crate::secret_egress::validate_raw_receipt(detail, &line[start..end]).map_err(
                        |err| VerifierError::Invalid(format!("line {line_number}: {err}")),
                    )?;
                }
            }
        }
        let version = entry.get("v").and_then(serde_json::Value::as_u64);
        if version != Some(1) && version != Some(2) && version != Some(3) {
            errors_unsupported(line_number, version)?;
        }
        validate_projected_strings(&entry, line_number, version.unwrap_or_default())?;
        if version == Some(3)
            && entry
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .is_none()
        {
            return Err(VerifierError::Runtime(format!(
                "line {line_number}: v3 seq must be an unsigned 64-bit integer"
            )));
        }
        if version != Some(3)
            && (legacy_namespace_field_is_set(&entry, "chain_kind")
                || legacy_namespace_field_is_set(&entry, "writer_instance_id"))
        {
            return Err(VerifierError::Invalid(format!(
                "line {line_number}: legacy entry cannot carry v3 recorder namespace fields"
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

#[cfg(all(test, unix))]
mod tests {
    use super::{read_entry_lines_using, same_file_snapshot};
    use crate::util::VerifierError;
    use std::fs::{FileTimes, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{Duration, SystemTime};

    #[test]
    fn same_inode_rewrite_with_restored_mtime_changes_snapshot() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pipelock-recorder-ctime-{}-{unique}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
            .expect("create fixture");
        file.write_all(b"first\nsecond\n").expect("write fixture");
        let fixed = SystemTime::now() - Duration::from_secs(10);
        file.set_times(FileTimes::new().set_modified(fixed))
            .expect("set stable mtime");
        let before = file.metadata().expect("stat before");

        file.seek(SeekFrom::Start(0)).expect("seek fixture");
        file.write_all(b"other\nsecond\n").expect("rewrite fixture");
        file.set_times(FileTimes::new().set_modified(fixed))
            .expect("restore mtime");
        let after = file.metadata().expect("stat after");

        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert!(!same_file_snapshot(&before, &after));
        drop(file);
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn changed_input_takes_precedence_over_parse_error() {
        let path = std::env::temp_dir().join(format!(
            "pipelock-recorder-parse-race-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"malformed\nsecond\n").expect("write fixture");
        let mutation_path = path.clone();
        let result = read_entry_lines_using(&path, move |_, _| {
            std::fs::write(&mutation_path, b"replacement\nsecond\n").expect("mutate fixture");
            Err(VerifierError::Invalid("malformed JSON".to_string()))
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("changed parse input must fail"),
        };
        assert!(error.to_string().contains("changed while reading"));
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn pathname_replacement_takes_precedence_over_parse_error() {
        let path = std::env::temp_dir().join(format!(
            "pipelock-recorder-path-race-{}",
            std::process::id()
        ));
        let replacement = path.with_extension("replacement");
        std::fs::write(&path, b"malformed\n").expect("write fixture");
        std::fs::write(&replacement, b"replacement\n").expect("write replacement");
        let replacement_path = replacement.clone();
        let path_for_replace = path.clone();
        let result = read_entry_lines_using(&path, move |_, _| {
            std::fs::rename(&replacement_path, &path_for_replace).expect("replace pathname");
            Err(VerifierError::Invalid("malformed JSON".to_string()))
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("replaced parse input must fail"),
        };
        assert!(error.to_string().contains("changed while reading"));
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn append_during_parse_is_bounded_by_initial_file_size() {
        let path = std::env::temp_dir().join(format!(
            "pipelock-recorder-append-race-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"first\nsecond\n").expect("write fixture");
        let append_path = path.clone();
        let mut appended = false;
        let mut visited = 0;
        let result = read_entry_lines_using(&path, |_, _| {
            visited += 1;
            if !appended {
                appended = true;
                OpenOptions::new()
                    .append(true)
                    .open(&append_path)
                    .expect("open for append")
                    .write_all(b"later\n")
                    .expect("append fixture");
            }
            Ok(Vec::new())
        });
        assert_eq!(visited, 2, "appended entries must not enter the snapshot");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("append during read must be detected"),
        };
        assert!(error.to_string().contains("changed while reading"));
        std::fs::remove_file(path).expect("remove fixture");
    }
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

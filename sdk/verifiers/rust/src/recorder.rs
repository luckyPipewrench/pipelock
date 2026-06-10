use crate::types::Receipt;
use crate::util::{parse_json_line, reject_duplicate_keys, Result, VerifierError};
use std::fs;
use std::path::Path;

const ACTION_RECEIPT_TYPE: &str = "action_receipt";
const EVIDENCE_RECEIPT_TYPE: &str = "evidence_receipt";

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
        if version != Some(1) && version != Some(2) {
            errors_unsupported(index + 1, version)?;
        }
        entries.push(entry);
    }
    Ok(entries)
}

pub fn extract_receipts(path: &Path) -> Result<Vec<Receipt>> {
    let mut receipts = Vec::new();
    for entry in read_entries(path)? {
        let entry_type = entry.get("type").and_then(serde_json::Value::as_str);
        if entry_type != Some(ACTION_RECEIPT_TYPE) && entry_type != Some(EVIDENCE_RECEIPT_TYPE) {
            continue;
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
        "line {line}: unsupported entry version {} (accepted: 1, 2)",
        version.map_or_else(|| "null".to_string(), |value| value.to_string())
    )))
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

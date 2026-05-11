use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Runtime(String),
    #[error("{0}")]
    Invalid(String),
}

impl VerifierError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 64,
            Self::Runtime(_) => 2,
            Self::Invalid(_) => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, VerifierError>;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn parse_json_file(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|err| VerifierError::Runtime(format!("malformed JSON: {err}")))
}

pub fn parse_json_line(text: &str, label: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|err| VerifierError::Runtime(format!("{label}: {err}")))
}

pub fn decode_hex(input: &str, byte_len: usize, label: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.len() != byte_len * 2 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid {label} length: got {}, want {byte_len}",
            trimmed.len() / 2
        ));
    }
    hex::decode(trimmed).map_err(|err| format!("invalid {label}: {err}"))
}

pub fn resolve_signer_key(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let mut value = trimmed.to_string();
    let path = Path::new(trimmed);
    if path.exists() {
        value = fs::read_to_string(path)
            .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?
            .trim()
            .to_string();
    }

    let mut lines = value.lines();
    if lines
        .next()
        .map(|line| line.trim_end_matches('\r'))
        == Some("pipelock-ed25519-public-v1")
    {
        let body = lines.next().unwrap_or("").trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|err| VerifierError::Runtime(format!("decode public key: {err}")))?;
        value = hex::encode(bytes);
    }

    decode_hex(&value, 32, "public key").map_err(VerifierError::Runtime)?;
    Ok(value.to_ascii_lowercase())
}

pub fn resolve_packet_path(target: &str) -> Result<(PathBuf, PathBuf)> {
    let clean = PathBuf::from(target);
    let info = fs::metadata(&clean)
        .map_err(|err| VerifierError::Runtime(format!("stat {target}: {err}")))?;
    if info.is_dir() {
        Ok((clean.join("packet.json"), clean))
    } else {
        let base = clean.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        Ok((clean, base))
    }
}

pub fn resolve_artifact_path(base_dir: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(VerifierError::Runtime("artifact path is empty".to_string()));
    }
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err(VerifierError::Runtime(format!(
            "artifact path must be relative: {rel}"
        )));
    }
    if rel.contains('\\') || rel.contains(':') {
        return Err(VerifierError::Runtime(format!(
            "artifact path contains forbidden character: {rel}"
        )));
    }
    if rel_path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(VerifierError::Runtime(format!(
            "artifact path escapes packet directory: {rel}"
        )));
    }

    let abs_base = fs::canonicalize(base_dir)
        .map_err(|err| VerifierError::Runtime(format!("resolve {}: {err}", base_dir.display())))?;
    let abs_full = abs_base.join(rel_path);
    let mut current = abs_base.clone();
    for component in rel_path.components() {
        current.push(component.as_os_str());
        if current.exists() {
            let resolved = fs::canonicalize(&current).map_err(|err| {
                VerifierError::Runtime(format!("resolve {}: {err}", current.display()))
            })?;
            if !resolved.starts_with(&abs_base) {
                return Err(VerifierError::Runtime(format!(
                    "artifact path escapes packet directory via symlink: {rel}"
                )));
            }
        }
    }
    if abs_full.exists() {
        let resolved = fs::canonicalize(&abs_full).map_err(|err| {
            VerifierError::Runtime(format!("resolve {}: {err}", abs_full.display()))
        })?;
        if !resolved.starts_with(&abs_base) {
            return Err(VerifierError::Runtime(format!(
                "artifact path escapes packet directory via symlink: {rel}"
            )));
        }
    }
    Ok(abs_full)
}

pub fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

pub fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

pub fn string_vec_at(value: &Value, path: &[&str]) -> Vec<String> {
    let mut current = value;
    for key in path {
        match current.get(*key) {
            Some(next) => current = next,
            None => return Vec::new(),
        }
    }
    current
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

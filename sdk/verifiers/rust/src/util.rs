// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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

pub const MAX_VERIFIER_INPUT_BYTES: u64 = 8 << 20;

thread_local! { static PINNED_EVIDENCE_DIRECTORY: Cell<bool> = const { Cell::new(false) }; }

pub(crate) fn pinned_evidence_directory() -> bool {
    PINNED_EVIDENCE_DIRECTORY.with(Cell::get)
}

pub(crate) fn set_pinned_evidence_directory(active: bool) {
    PINNED_EVIDENCE_DIRECTORY.with(|flag| flag.set(active));
}

pub(crate) fn same_open_file(a: &File, b: &File) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = a
            .metadata()
            .map_err(|err| VerifierError::Runtime(err.to_string()))?;
        let b = b
            .metadata()
            .map_err(|err| VerifierError::Runtime(err.to_string()))?;
        Ok(a.dev() == b.dev() && a.ino() == b.ino() && a.ino() != 0)
    }
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        #[derive(Default, PartialEq, Eq)]
        struct FileIdInfo {
            volume: u64,
            id: [u8; 16],
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFileInformationByHandleEx(
                handle: *mut c_void,
                class: u32,
                info: *mut c_void,
                size: u32,
            ) -> i32;
        }
        fn identity(file: &File) -> Result<FileIdInfo> {
            let mut info = FileIdInfo::default();
            // FileIdInfo = 0x12; an unsupported filesystem fails closed.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    0x12,
                    (&mut info as *mut FileIdInfo).cast(),
                    std::mem::size_of::<FileIdInfo>() as u32,
                )
            };
            if ok == 0 || info.id == [0; 16] {
                return Err(VerifierError::Runtime(
                    "cannot identify opened evidence directory".to_string(),
                ));
            }
            Ok(info)
        }
        return Ok(identity(a)? == identity(b)?);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (a, b);
        Err(VerifierError::Runtime(
            "unsupported evidence directory platform".to_string(),
        ))
    }
}

pub fn open_verifier_file(path: &Path) -> Result<File> {
    // Operator-supplied keys and endorsements were made absolute before the
    // directory is entered. Only relative child names belong to the pinned
    // evidence directory.
    let pinned = pinned_evidence_directory() && !path.is_absolute();
    if pinned {
        let mut components = path
            .components()
            .filter(|c| !matches!(c, std::path::Component::CurDir));
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(VerifierError::Runtime(
                "evidence filename must be a base name".to_string(),
            ));
        }
        if fs::symlink_metadata(path)
            .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?
            .file_type()
            .is_symlink()
        {
            return Err(VerifierError::Runtime(
                "refuse symlink in evidence directory".to_string(),
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | if pinned { libc::O_NOFOLLOW } else { 0 });
    #[cfg(windows)]
    if pinned {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    let info = file
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?;
    if !info.is_file() {
        return Err(VerifierError::Runtime(
            "input must be a regular file".to_string(),
        ));
    }
    if pinned && info.file_type().is_symlink() {
        return Err(VerifierError::Runtime(
            "refuse symlink in evidence directory".to_string(),
        ));
    }
    Ok(file)
}

pub fn read_verifier_bytes(path: &Path) -> Result<Vec<u8>> {
    let file = open_verifier_file(path)?;
    let info = file
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?;
    if info.len() > MAX_VERIFIER_INPUT_BYTES {
        return Err(VerifierError::Runtime(format!(
            "input exceeds {MAX_VERIFIER_INPUT_BYTES} bytes"
        )));
    }
    let mut data = Vec::new();
    file.take(MAX_VERIFIER_INPUT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    if data.len() as u64 > MAX_VERIFIER_INPUT_BYTES {
        return Err(VerifierError::Runtime(format!(
            "input exceeds {MAX_VERIFIER_INPUT_BYTES} bytes"
        )));
    }
    Ok(data)
}

pub fn read_verifier_text(path: &Path) -> Result<String> {
    String::from_utf8(read_verifier_bytes(path)?)
        .map_err(|err| VerifierError::Runtime(format!("input is not UTF-8: {err}")))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn parse_json_file(path: &Path) -> Result<Value> {
    let text = read_verifier_text(path)?;
    parse_json_text(&text, "malformed JSON")
}

pub fn parse_json_line(text: &str, label: &str) -> Result<Value> {
    parse_json_text(text, label)
}

pub fn parse_json_text(text: &str, label: &str) -> Result<Value> {
    use serde::Deserialize;
    // For the new kind, enforce duplicate and nesting limits before building a
    // parsed value. Source selector inspection preserves duplicate selectors.
    if crate::secret_egress::selects_raw_payload(text) {
        reject_duplicate_keys(text)?;
    }
    let mut de = serde_json::Deserializer::from_str(text);
    // Keep normal parsing aligned with reject_duplicate_keys: serde_json's
    // built-in recursion limit rejects one level earlier than the shared
    // verifier boundary, so parse with it disabled after the explicit scanner
    // has enforced the 128-level cap.
    de.disable_recursion_limit();
    let value = Value::deserialize(&mut de)
        .map_err(|err| VerifierError::Runtime(format!("{label}: {err}")))?;
    de.end()
        .map_err(|err| VerifierError::Runtime(format!("{label}: {err}")))?;
    crate::secret_egress::validate_raw_receipt(&value, text).map_err(VerifierError::Invalid)?;
    Ok(value)
}

/// reject_duplicate_keys returns an Invalid error if text contains a duplicate
/// object key at any nesting depth. serde_json keeps the last value for a
/// duplicate key, so {"verdict":"allow","verdict":"block"} deserializes as
/// "block" with no error — a parser-differential smuggling vector where a
/// display or log layer reading the first occurrence sees a value different
/// from the one the signature was verified against. The verify path rejects
/// such input before signature verification. Implemented as a recursive serde
/// Visitor so it reuses serde_json's tokenizer rather than a hand parser.
pub fn reject_duplicate_keys(text: &str) -> Result<()> {
    use serde::de::DeserializeSeed;
    let mut de = serde_json::Deserializer::from_str(text);
    // serde_json's built-in recursion limit rejects one level earlier than the
    // Go/TypeScript/Python verifier cap. Disable it and enforce the shared
    // receipt-nesting bound explicitly in NoDupSeed so all four allow exactly
    // 128 nested JSON arrays/objects and reject the 129th.
    de.disable_recursion_limit();
    match (NoDupSeed { depth: 0 }).deserialize(&mut de) {
        Ok(_) => Ok(()),
        Err(err) => Err(VerifierError::Invalid(err.to_string())),
    }
}

const MAX_NESTING_DEPTH: usize = 128;
const MAX_EXACT_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

/// NoDup deserializes any JSON value purely to assert there are no duplicate
/// object keys; it carries no data.
struct NoDupSeed {
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for NoDupSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};
        use std::collections::HashSet;
        use std::fmt;

        struct NoDupVisitor {
            depth: usize,
        }

        impl<'de> Visitor<'de> for NoDupVisitor {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
            where
                A: MapAccess<'de>,
            {
                if self.depth >= MAX_NESTING_DEPTH {
                    return Err(de::Error::custom(format!(
                        "JSON nesting exceeds maximum depth {MAX_NESTING_DEPTH}"
                    )));
                }
                let mut seen: HashSet<String> = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom(format!("duplicate object key: {key}")));
                    }
                    map.next_value_seed(NoDupSeed {
                        depth: self.depth + 1,
                    })?;
                }
                Ok(())
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
            where
                A: SeqAccess<'de>,
            {
                if self.depth >= MAX_NESTING_DEPTH {
                    return Err(de::Error::custom(format!(
                        "JSON nesting exceeds maximum depth {MAX_NESTING_DEPTH}"
                    )));
                }
                while seq
                    .next_element_seed(NoDupSeed {
                        depth: self.depth + 1,
                    })?
                    .is_some()
                {}
                Ok(())
            }

            fn visit_bool<E>(self, _v: bool) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                Ok(())
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                if v.unsigned_abs() > MAX_EXACT_JSON_INTEGER {
                    return Err(de::Error::custom(format!(
                        "JSON number {v} exceeds cross-language exact range"
                    )));
                }
                Ok(())
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                if v > MAX_EXACT_JSON_INTEGER {
                    return Err(de::Error::custom(format!(
                        "JSON number {v} exceeds cross-language exact range"
                    )));
                }
                Ok(())
            }

            fn visit_f64<E>(self, v: f64) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                if v.abs() > MAX_EXACT_JSON_INTEGER as f64 {
                    return Err(de::Error::custom(format!(
                        "JSON number {v} exceeds cross-language exact range"
                    )));
                }
                Ok(())
            }

            fn visit_str<E>(self, _v: &str) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                Ok(())
            }

            fn visit_unit<E>(self) -> std::result::Result<(), E>
            where
                E: de::Error,
            {
                Ok(())
            }
        }

        deserializer.deserialize_any(NoDupVisitor { depth: self.depth })
    }
}

pub fn decode_hex(
    input: &str,
    byte_len: usize,
    label: &str,
) -> std::result::Result<Vec<u8>, String> {
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

    // Both supported literal forms are unambiguously key material. Parse them
    // before consulting the filesystem so an untrusted working directory
    // cannot replace a pinned literal with a same-named file.
    if (trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()))
        || trimmed
            .lines()
            .next()
            .is_some_and(|line| line.trim_end_matches('\r') == "pipelock-ed25519-public-v1")
    {
        return parse_signer_key_value(trimmed);
    }

    let path = Path::new(trimmed);
    let value = if path.exists() {
        read_verifier_text(path)?.trim().to_string()
    } else {
        trimmed.to_string()
    };

    parse_signer_key_value(&value)
}

fn parse_signer_key_value(value: &str) -> Result<String> {
    let mut lines = value.lines();
    if lines.next().map(|line| line.trim_end_matches('\r')) == Some("pipelock-ed25519-public-v1") {
        let body = lines.next().unwrap_or("").trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|err| VerifierError::Runtime(format!("decode public key: {err}")))?;
        let decoded = hex::encode(bytes);
        decode_hex(&decoded, 32, "public key").map_err(VerifierError::Runtime)?;
        return Ok(decoded);
    }

    decode_hex(value, 32, "public key").map_err(VerifierError::Runtime)?;
    Ok(value.to_ascii_lowercase())
}

pub fn resolve_packet_path(target: &str) -> Result<(PathBuf, PathBuf)> {
    let clean = PathBuf::from(target);
    let info = fs::metadata(&clean)
        .map_err(|err| VerifierError::Runtime(format!("stat {target}: {err}")))?;
    if info.is_dir() {
        Ok((clean.join("packet.json"), clean))
    } else {
        let base = clean
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
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

#[cfg(test)]
mod tests {
    use super::reject_duplicate_keys;

    #[test]
    fn rejects_numbers_outside_cross_language_exact_range() {
        let err = reject_duplicate_keys(r#"{"count":9007199254740993}"#)
            .expect_err("unsafe integer must be rejected");
        assert!(err.to_string().contains("cross-language exact range"));

        reject_duplicate_keys(r#"{"count":9007199254740991}"#)
            .expect("maximum exact integer must remain valid");
    }
}

pub(crate) fn same_directory_identity(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        before.is_dir() && after.is_dir()
    }
}

pub(crate) fn metadata_identity(metadata: &std::fs::Metadata) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        [
            metadata.dev().to_be_bytes().as_slice(),
            metadata.ino().to_be_bytes().as_slice(),
            metadata.ctime().to_be_bytes().as_slice(),
            metadata.ctime_nsec().to_be_bytes().as_slice(),
        ]
        .concat()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Vec::new()
    }
}

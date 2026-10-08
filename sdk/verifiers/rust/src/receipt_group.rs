// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Verification for signed multi-shard receipt groups.
//!
//! A shard is never treated as a complete group. The verifier first checks
//! the trusted opening, every gated shard, native AEL streams, and the signed
//! close. Successor groups additionally require a signed transition.

use crate::canonical::go_json_bytes;
use crate::chain::{receipt_hash, verify_chain_with_options};
use crate::chain_set::{indexed_session_files, parse_evidence_filename};
use crate::line_space::trim_go_space;
use crate::recorder::{extract_typed_from_lines, read_entry_lines_text, RecorderLine};
use crate::recorder_chain::verify_recorder_chain;
use crate::util::{reject_duplicate_keys, sha256_hex};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

const OPEN_DOMAIN: &str = "pipelock/receipt-group-open/v1";
const CLOSE_DOMAIN: &str = "pipelock/receipt-group-close/v1";
const TRANSITION_DOMAIN: &str = "pipelock/receipt-group-transition/v1";
const MAX_GROUP_FILE: u64 = 128 * 1024;

/// Detect grouped evidence before a directory reader chooses legacy mode.
/// A torn final write cannot hide a complete first recorder group gate.
pub(crate) fn receipt_group_evidence_present(dir: &Path) -> Result<bool, String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("receipt-group-") {
            return Ok(true);
        }
        let Some((_, start)) = parse_evidence_filename(&name) else {
            continue;
        };
        if start != 0 {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            // The legacy verifier reports invalid shard files in its normal verdict.
            continue;
        }
        let file = open_checked_regular(&entry.path(), &metadata)?;
        let mut reader = BufReader::new(file.take((1 << 20) + 1));
        let mut first = Vec::new();
        reader
            .read_until(b'\n', &mut first)
            .map_err(|e| e.to_string())?;
        if first.last() != Some(&b'\n') {
            continue;
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&first[..first.len() - 1]) {
            if value.get("type").and_then(Value::as_str) == Some("receipt_group_v1") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupShard {
    pub shard_index: usize,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupOpen {
    pub version: u32,
    pub kind: String,
    pub group_id: String,
    pub base_session: String,
    pub shard_count: usize,
    pub process_shard_index: usize,
    pub signer_key: String,
    pub shards: Vec<ReceiptGroupShard>,
    pub previous_group_id: String,
    pub previous_open_manifest_sha256: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupShardHead {
    pub shard_index: usize,
    pub session_id: String,
    pub final_chain_seq: u64,
    pub final_chain_hash: String,
    pub receipt_count: u64,
    pub session_close_hash: String,
    pub transcript_root_hash: String,
    pub checkpoint_hash: String,
    pub native_ael_final_seq: u64,
    pub native_ael_final_hash: String,
    pub native_ael_record_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupClose {
    pub version: u32,
    pub kind: String,
    pub group_id: String,
    pub open_manifest_sha256: String,
    pub status: String,
    pub shards: Vec<ReceiptGroupShardHead>,
    pub closed_at: String,
    pub signer_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupPredecessor {
    pub shard_index: usize,
    pub session_id: String,
    pub final_chain_seq: u64,
    pub final_chain_hash: String,
    pub recovery_seal_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptGroupTransition {
    pub version: u32,
    pub kind: String,
    pub new_group_id: String,
    pub new_open_manifest_sha256: String,
    pub previous_group_id: String,
    pub previous_open_manifest_sha256: String,
    pub previous_close_manifest_sha256: String,
    pub predecessors: Vec<ReceiptGroupPredecessor>,
    pub created_at: String,
    pub signer_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecoverySeal {
    kind: String,
    version: u32,
    predecessor_session: String,
    shard: String,
    shard_size: u64,
    shard_sha256: String,
    damage_offset: u64,
    last_good_seq: u64,
    last_good_hash: String,
    predecessor_tail_seq: u64,
    predecessor_tail_hash: String,
    predecessor_signer_key: String,
    successor_session: String,
    successor_signer_key: String,
    successor_open_hash: String,
    observed_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signature: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReceiptGroupReport {
    pub group_id: String,
    pub verdict: String,
    pub base_session: Option<String>,
    pub shard_count: usize,
    pub open_manifest_sha256: Option<String>,
    pub close_manifest_sha256: Option<String>,
    pub error: Option<String>,
}

/// Verify one complete published group. `trusted_keys` must contain at least
/// one externally pinned Ed25519 public key; self-consistent signatures alone
/// cannot produce GROUP_VALID.
pub fn verify_receipt_group(
    dir: &Path,
    group_id: &str,
    trusted_keys: &[String],
) -> ReceiptGroupReport {
    match verify_inner(dir, group_id, trusted_keys) {
        Ok(report) => report,
        Err((verdict, reason)) => ReceiptGroupReport {
            group_id: group_id.to_string(),
            verdict: verdict.into(),
            base_session: None,
            shard_count: 0,
            open_manifest_sha256: None,
            close_manifest_sha256: None,
            error: Some(reason),
        },
    }
}

fn verify_inner(
    dir: &Path,
    group_id: &str,
    trusted: &[String],
) -> Result<ReceiptGroupReport, (&'static str, String)> {
    if trusted.is_empty() {
        return Err((
            "GROUP_INVALID",
            "receipt group requires a trusted signer key".into(),
        ));
    }
    if !hex_exact(group_id, 32) {
        return Err(("GROUP_INVALID", "invalid receipt group ID".into()));
    }
    let root_meta = fs::symlink_metadata(dir)
        .map_err(|e| invalid(format!("stat receipt group directory: {e}")))?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err((
            "GROUP_INVALID",
            "receipt group path is not a real directory".into(),
        ));
    }
    let before = inventory_fingerprint(dir).map_err(invalid)?;
    verify_group_artifact_names(dir).map_err(invalid)?;
    let open_name = format!("receipt-group-{group_id}-open.json");
    let open_raw = bounded_read(dir, &open_name).map_err(invalid)?;
    let open: ReceiptGroupOpen = strict_artifact(&open_raw).map_err(invalid)?;
    validate_open(&open, group_id).map_err(invalid)?;
    verify_signed(
        OPEN_DOMAIN,
        &open,
        &open.signature,
        &open.signer_key,
        trusted,
    )
    .map_err(invalid)?;
    let open_hash = sha256_hex(&open_raw);
    let close_name = format!("receipt-group-{group_id}-close.json");
    let close_path = dir.join(&close_name);
    let close_missing = match fs::symlink_metadata(&close_path) {
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => return Err(invalid(err.to_string())),
    };
    let close_raw = match bounded_read(dir, &close_name) {
        Ok(bytes) => bytes,
        Err(reason) if close_missing => {
            // Missing close is the only path to INCOMPLETE. Verify all extant
            // shard data first so malformed signed state cannot hide here.
            for (index, shard) in open.shards.iter().enumerate() {
                let mut present = false;
                for entry in fs::read_dir(dir).map_err(|e| invalid(e.to_string()))? {
                    let entry = entry.map_err(|e| invalid(e.to_string()))?;
                    if parse_evidence_filename(&entry.file_name().to_string_lossy())
                        .is_some_and(|(session, _)| session == shard.session_id)
                    {
                        present = true;
                    }
                }
                if !present {
                    continue;
                }
                verify_open_shard(dir, &open, &open_hash, index, shard).map_err(invalid)?;
            }
            verify_transitions_referencing(dir, &open_hash, trusted, true).map_err(invalid)?;
            verify_ael_inventory(dir, &open, trusted, true).map_err(invalid)?;
            if inventory_fingerprint(dir).map_err(invalid)? != before {
                return Err((
                    "GROUP_INVALID",
                    "receipt group directory changed during verification".into(),
                ));
            }
            let _ = reason;
            return Ok(ReceiptGroupReport {
                group_id: group_id.to_string(),
                verdict: "GROUP_INCOMPLETE".into(),
                base_session: Some(open.base_session),
                shard_count: open.shard_count,
                open_manifest_sha256: Some(open_hash),
                close_manifest_sha256: None,
                error: Some("receipt group has no signed close manifest".into()),
            });
        }
        Err(reason) => return Err(("GROUP_INVALID", reason)),
    };
    let close: ReceiptGroupClose = strict_artifact(&close_raw).map_err(invalid)?;
    validate_close(&close, &open, &open_hash).map_err(invalid)?;
    verify_signed(
        CLOSE_DOMAIN,
        &close,
        &close.signature,
        &close.signer_key,
        trusted,
    )
    .map_err(invalid)?;
    for (i, (claimed, shard)) in close.shards.iter().zip(open.shards.iter()).enumerate() {
        let actual = verify_shard(dir, &open, &open_hash, i, shard).map_err(invalid)?;
        if *claimed != actual {
            return Err((
                "GROUP_INVALID",
                format!("receipt group shard {i} head differs from signed close"),
            ));
        }
    }
    if !open.previous_group_id.is_empty() {
        verify_transition(dir, &open, &open_hash, trusted).map_err(invalid)?;
    }
    verify_transitions_referencing(dir, &open_hash, trusted, true).map_err(invalid)?;
    let (open_ael_tail, neighbor_ael_tail) =
        verify_ael_inventory(dir, &open, trusted, false).map_err(invalid)?;
    let predecessor_incomplete = if open.previous_group_id.is_empty() {
        false
    } else {
        match fs::symlink_metadata(dir.join(format!(
            "receipt-group-{}-close.json",
            open.previous_group_id
        ))) {
            Ok(_) => false,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(err) => return Err(invalid(err.to_string())),
        }
    };
    if inventory_fingerprint(dir).map_err(invalid)? != before {
        return Err((
            "GROUP_INVALID",
            "receipt group directory changed during verification".into(),
        ));
    }
    Ok(ReceiptGroupReport {
        group_id: group_id.to_string(),
        verdict: if open_ael_tail {
            "GROUP_INCOMPLETE"
        } else {
            "GROUP_VALID"
        }
        .into(),
        base_session: Some(open.base_session),
        shard_count: open.shard_count,
        open_manifest_sha256: Some(open_hash),
        close_manifest_sha256: Some(sha256_hex(&close_raw)),
        error: if open_ael_tail {
            Some("native AEL run has an open recorder tail".into())
        } else if predecessor_incomplete {
            Some("predecessor group is GROUP_INCOMPLETE: no signed close manifest".into())
        } else if neighbor_ael_tail {
            Some("predecessor or neighboring group is GROUP_INCOMPLETE: native AEL run has an open recorder tail".into())
        } else {
            None
        },
    })
}

fn invalid(reason: String) -> (&'static str, String) {
    ("GROUP_INVALID", reason)
}

fn strict_artifact<T: for<'de> Deserialize<'de> + Serialize>(raw: &[u8]) -> Result<T, String> {
    if raw.is_empty() || raw.len() as u64 > MAX_GROUP_FILE {
        return Err("invalid receipt group artifact size".into());
    }
    let text = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    reject_duplicate_keys(text).map_err(|e| e.to_string())?;
    let value: T = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let canonical = go_json_bytes(&value).map_err(|e| e.to_string())?;
    if canonical != raw {
        return Err(format!(
            "receipt group artifact is not canonical JSON (decoded={}, raw={})",
            String::from_utf8_lossy(&canonical),
            text
        ));
    }
    Ok(value)
}

fn validate_open(o: &ReceiptGroupOpen, requested: &str) -> Result<(), String> {
    if o.version != 1
        || o.kind != "receipt_group_open"
        || o.group_id != requested
        || !hex_exact(&o.group_id, 32)
        || !hex_exact(&o.signer_key, 64)
    {
        return Err("invalid receipt group opening identity".into());
    }
    if o.shard_count < 2
        || o.shard_count > 32
        || o.shards.len() != o.shard_count
        || o.process_shard_index >= o.shard_count
    {
        return Err("invalid receipt group shard count or process index".into());
    }
    if !canonical_time(&o.created_at)
        || (o.previous_group_id.is_empty() != o.previous_open_manifest_sha256.is_empty())
        || (!o.previous_group_id.is_empty()
            && (!hex_exact(&o.previous_group_id, 32)
                || !hex_exact(&o.previous_open_manifest_sha256, 64)
                || o.previous_group_id == o.group_id))
    {
        return Err("invalid receipt group predecessor or timestamp".into());
    }
    let mut seen = BTreeSet::new();
    for (i, s) in o.shards.iter().enumerate() {
        if s.shard_index != i
            || !s
                .session_id
                .starts_with(&format!("{}.run.", o.base_session))
            || !hex_exact(s.session_id.rsplit('.').next().unwrap_or(""), 32)
            || !seen.insert(s.session_id.as_str())
        {
            return Err(format!("invalid or duplicate receipt group shard {i}"));
        }
    }
    Ok(())
}

fn validate_close(
    c: &ReceiptGroupClose,
    o: &ReceiptGroupOpen,
    open_hash: &str,
) -> Result<(), String> {
    if c.version != 1
        || c.kind != "receipt_group_close"
        || c.status != "complete"
        || c.group_id != o.group_id
        || c.open_manifest_sha256 != open_hash
        || c.signer_key != o.signer_key
        || !canonical_time(&c.closed_at)
        || c.shards.len() != o.shards.len()
    {
        return Err("receipt group close does not bind opening".into());
    }
    for (i, h) in c.shards.iter().enumerate() {
        if h.shard_index != i
            || h.session_id != o.shards[i].session_id
            || ![
                &h.final_chain_hash,
                &h.session_close_hash,
                &h.transcript_root_hash,
                &h.checkpoint_hash,
                &h.native_ael_final_hash,
            ]
            .iter()
            .all(|s| hex_exact(s, 64))
        {
            return Err(format!("invalid receipt group close shard {i}"));
        }
    }
    Ok(())
}

fn verify_signed<T: Serialize>(
    domain: &str,
    value: &T,
    signature: &str,
    signer: &str,
    trusted: &[String],
) -> Result<(), String> {
    if !trusted.iter().any(|k| k.eq_ignore_ascii_case(signer)) {
        return Err("receipt group signer is not trusted".into());
    }
    let key_bytes = hex::decode(signer).map_err(|e| e.to_string())?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid Ed25519 key length")?;
    let key = VerifyingKey::from_bytes(&key_array).map_err(|e| e.to_string())?;
    let sig_hex = signature
        .strip_prefix("ed25519:")
        .ok_or("invalid receipt group signature encoding")?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    let mut unsigned = serde_json::to_value(value).map_err(|e| e.to_string())?;
    unsigned
        .as_object_mut()
        .ok_or("signed artifact is not an object")?
        .remove("signature");
    let preimage = [
        domain.as_bytes(),
        &go_json_bytes(&unsigned).map_err(|e| e.to_string())?,
    ]
    .concat();
    key.verify(&preimage, &sig).map_err(|e| e.to_string())
}

// Group decisions must see the entire recorder session, including a close
// written after rotation. Go's session walker delivers every complete line and
// then reports an unterminated final fragment as a torn tail, so the fragment
// is never evidence: this returns the terminated prefix and whether a fragment
// followed it. Only the last segment may be torn, and only when the caller
// allows it. An empty segment is an empty file, not a torn write.
fn read_group_session(
    dir: &Path,
    session: &str,
    allow_torn: bool,
) -> Result<(Vec<RecorderLine>, bool), String> {
    let index = indexed_session_files(dir)?;
    let files = index
        .get(session)
        .ok_or("receipt group session evidence is missing")?;
    if files.is_empty() {
        return Err("receipt group session evidence is missing".into());
    }
    let mut lines = Vec::new();
    let mut torn = false;
    for (file_index, path) in files.iter().enumerate() {
        let raw = read_regular(path, crate::util::MAX_VERIFIER_INPUT_BYTES)?;
        let complete = if raw.is_empty() || raw.ends_with(b"\n") {
            raw.as_slice()
        } else if allow_torn && file_index + 1 == files.len() {
            torn = true;
            let end = raw
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |pos| pos + 1);
            &raw[..end]
        } else {
            return Err("receipt group session has a torn segment".into());
        };
        let text = std::str::from_utf8(complete).map_err(|e| e.to_string())?;
        let part = read_entry_lines_text(text).map_err(|e| e.to_string())?;
        if part.is_empty() {
            // Go reads an empty file or a lone torn fragment as no entries.
            continue;
        }
        let (_, start) = parse_evidence_filename(
            &path
                .file_name()
                .ok_or("invalid evidence file name")?
                .to_string_lossy(),
        )
        .ok_or("invalid evidence file name")?;
        if part[0].entry.get("seq").and_then(Value::as_u64) != Some(start)
            || start != lines.len() as u64
        {
            return Err("receipt group session segment sequence mismatch".into());
        }
        if part
            .iter()
            .any(|line| line.entry.get("session_id").and_then(Value::as_str) != Some(session))
        {
            return Err("receipt group session segment owner mismatch".into());
        }
        lines.extend(part);
    }
    if let Some(err) = verify_recorder_chain(
        &lines
            .iter()
            .map(|line| line.line.as_str())
            .collect::<Vec<_>>(),
    ) {
        return Err(format!("receipt group session recorder chain: {err}"));
    }
    Ok((lines, torn))
}

fn read_group_session_lines(
    dir: &Path,
    session: &str,
    allow_torn: bool,
) -> Result<Vec<RecorderLine>, String> {
    read_group_session(dir, session, allow_torn).map(|(lines, _)| lines)
}

fn verify_shard(
    dir: &Path,
    open: &ReceiptGroupOpen,
    open_hash: &str,
    index: usize,
    shard: &ReceiptGroupShard,
) -> Result<ReceiptGroupShardHead, String> {
    let lines = read_group_session_lines(dir, &shard.session_id, false)?;
    if lines.is_empty() {
        return Err("receipt group shard is empty".into());
    }
    if let Some(err) =
        verify_recorder_chain(&lines.iter().map(|x| x.line.as_str()).collect::<Vec<_>>())
    {
        return Err(format!("recorder chain: {err}"));
    }
    let gate = json!({"group_id":open.group_id,"shard_index":index,"session_id":shard.session_id,"open_manifest_sha256":open_hash,"signer_key":open.signer_key,"previous_group_id":open.previous_group_id,"previous_open_manifest_sha256":open.previous_open_manifest_sha256});
    if lines[0].entry.get("type").and_then(Value::as_str) != Some("receipt_group_v1")
        || lines[0].entry.get("detail") != Some(&gate)
    {
        return Err(format!(
            "shard {index} first recorder entry differs from signed gate"
        ));
    }
    if lines
        .get(1)
        .and_then(|e| e.entry.get("type"))
        .and_then(Value::as_str)
        != Some("checkpoint")
    {
        return Err("group gate is not covered by the next checkpoint".into());
    }
    let cloned = strip_leading_gate(clone_lines(&lines));
    let typed = extract_typed_from_lines(cloned).map_err(|e| e.to_string())?;
    let mut receipts = typed.action.clone();
    if receipts.is_empty() {
        receipts = typed.evidence.clone();
    }
    let chain = verify_chain_with_options(&receipts, &open.signer_key, false);
    if !chain.valid {
        return Err(format!(
            "signed receipt chain failed: {}",
            chain.error.unwrap_or_default()
        ));
    }
    if !typed.action.is_empty() && !typed.evidence.is_empty() {
        let evidence = verify_chain_with_options(&typed.evidence, &open.signer_key, false);
        if !evidence.valid {
            return Err(format!(
                "signed evidence receipt chain failed: {}",
                evidence.error.unwrap_or_default()
            ));
        }
    }
    let mut open_receipt = None;
    let mut close_hash = None;
    for (i, r) in receipts.iter().enumerate() {
        let control = r
            .get("action_record")
            .and_then(|a| a.get("session_control"))
            .or_else(|| r.get("payload").and_then(|p| p.get("session_control")));
        if i == 0 {
            let binding = control
                .and_then(|c| c.get("open"))
                .and_then(|o| o.get("group_binding"));
            if binding != Some(&gate) {
                return Err("signed session open differs from group gate".into());
            }
            open_receipt = Some(r.clone());
        }
        if control.and_then(|c| c.get("kind")).and_then(Value::as_str) == Some("session_close") {
            close_hash = Some(receipt_hash(r));
        }
    }
    let run = open_receipt
        .as_ref()
        .and_then(|r| {
            r.pointer("/action_record/session_control/open/run_nonce")
                .or_else(|| r.pointer("/payload/session_control/open/run_nonce"))
        })
        .and_then(Value::as_str)
        .ok_or("signed session open lacks AEL run nonce")?;
    let mut rooted = None;
    let mut checkpoint_hash = None;
    let mut close_seen = false;
    let mut root_entry_hash = None;
    let mut last_was_final_checkpoint = false;
    let mut entries_after_root = 0usize;
    for line in &lines {
        let typ = line.entry.get("type").and_then(Value::as_str).unwrap_or("");
        if rooted.is_some() {
            entries_after_root += 1;
            if typ != "checkpoint"
                || line.entry.get("prev_hash").and_then(Value::as_str) != root_entry_hash.as_deref()
                || last_was_final_checkpoint
            {
                return Err("evidence follows transcript root outside final checkpoint".into());
            }
            last_was_final_checkpoint = true;
        }
        if line.entry.get("type").and_then(Value::as_str) == Some("action_receipt") {
            let control = line
                .entry
                .pointer("/detail/action_record/session_control/kind")
                .and_then(Value::as_str);
            if control == Some("session_close") {
                close_seen = true;
            }
        }
        if typ == "transcript_root" {
            if rooted.is_some() || !close_seen {
                return Err("transcript root must follow one signed session close".into());
            }
            let root = line
                .entry
                .get("detail")
                .ok_or("transcript root lacks detail")?;
            if root.get("session_id").and_then(Value::as_str) != Some(shard.session_id.as_str())
                || root.get("final_seq").and_then(Value::as_u64) != Some(chain.final_seq)
                || root.get("root_hash").and_then(Value::as_str) != Some(chain.root_hash.as_str())
                || root.get("receipt_count").and_then(Value::as_u64)
                    != Some(chain.receipt_count as u64)
            {
                return Err("transcript root differs from signed chain".into());
            }
            let hash = line
                .entry
                .get("hash")
                .and_then(Value::as_str)
                .ok_or("transcript root lacks hash")?
                .to_string();
            rooted = Some(hash.clone());
            root_entry_hash = Some(hash);
            last_was_final_checkpoint = false;
        }
        if typ == "checkpoint" {
            verify_checkpoint(line, &open.signer_key)?;
            checkpoint_hash = line
                .entry
                .get("hash")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
    }
    if entries_after_root != 1 || !last_was_final_checkpoint || lines.len() < 5 {
        return Err("group shard lacks final root checkpoint".into());
    }
    let ael = verify_ael_run(dir, run, &open.signer_key)?;
    Ok(ReceiptGroupShardHead {
        shard_index: index,
        session_id: shard.session_id.clone(),
        final_chain_seq: chain.final_seq,
        final_chain_hash: chain.root_hash,
        receipt_count: chain.receipt_count as u64,
        session_close_hash: close_hash.ok_or("group shard has no signed session close")?,
        transcript_root_hash: rooted.ok_or("group shard has no transcript root")?,
        checkpoint_hash: checkpoint_hash.ok_or("group shard has no final checkpoint")?,
        native_ael_final_seq: ael.0,
        native_ael_final_hash: ael.1,
        native_ael_record_count: ael.2,
    })
}

fn verify_open_shard(
    dir: &Path,
    open: &ReceiptGroupOpen,
    open_hash: &str,
    index: usize,
    shard: &ReceiptGroupShard,
) -> Result<(), String> {
    let lines = read_group_session_lines(dir, &shard.session_id, true)?;
    let Some(first) = lines.first() else {
        return Err("receipt group shard has no opening gate".into());
    };
    let gate = json!({"group_id":open.group_id,"shard_index":index,"session_id":shard.session_id,"open_manifest_sha256":open_hash,"signer_key":open.signer_key,"previous_group_id":open.previous_group_id,"previous_open_manifest_sha256":open.previous_open_manifest_sha256});
    if first.entry.get("type").and_then(Value::as_str) != Some("receipt_group_v1")
        || first.entry.get("detail") != Some(&gate)
    {
        return Err("incomplete shard gate differs from signed opening".into());
    }
    if lines.len() > 1 && lines[1].entry.get("type").and_then(Value::as_str) != Some("checkpoint") {
        return Err("incomplete shard gate lacks its checkpoint".into());
    }
    if let Some(err) =
        verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>())
    {
        return Err(format!("incomplete shard recorder chain: {err}"));
    }
    let typed = extract_typed_from_lines(strip_leading_gate(lines)).map_err(|e| e.to_string())?;
    for (is_action, receipts) in [(true, &typed.action), (false, &typed.evidence)] {
        if receipts.is_empty() {
            continue;
        }
        let result = verify_chain_with_options(receipts, &open.signer_key, false);
        if !result.valid {
            return Err(format!(
                "incomplete shard signed chain invalid: {}",
                result.error.unwrap_or_default()
            ));
        }
        // Only the v1 action chain starts with the signed session_open; a v2
        // evidence chain carries no opening to bind to the gate.
        if let Some(first) = receipts.first().filter(|_| is_action) {
            let binding = first
                .pointer("/action_record/session_control/open/group_binding")
                .or_else(|| first.pointer("/payload/session_control/open/group_binding"));
            if binding != Some(&gate) {
                return Err("incomplete shard signed open differs from gate".into());
            }
        }
    }
    Ok(())
}

// verify_prefix_integrity applies what Go's recovery prefix verifier checks on
// every entry of an unclosed predecessor: the gate is covered by the next
// checkpoint and every checkpoint is signed by the group signer.
fn verify_prefix_integrity(lines: &[RecorderLine], signer: &str) -> Result<(), String> {
    let gate_hash = lines
        .first()
        .and_then(|line| line.entry.get("hash"))
        .and_then(Value::as_str);
    let covering = lines.get(1);
    if gate_hash.is_none()
        || covering
            .and_then(|line| line.entry.get("type"))
            .and_then(Value::as_str)
            != Some("checkpoint")
        || covering
            .and_then(|line| line.entry.get("prev_hash"))
            .and_then(Value::as_str)
            != gate_hash
    {
        return Err("predecessor group gate lacks covering checkpoint".into());
    }
    for line in lines {
        if line.entry.get("type").and_then(Value::as_str) == Some("checkpoint") {
            verify_checkpoint(line, signer)
                .map_err(|e| format!("predecessor checkpoint signature failed: {e}"))?;
        }
    }
    Ok(())
}

// strip_leading_gate drops the group gate from the front of a session, the only
// place Go's group recorder walker accepts one. A gate anywhere else stays in
// the list, where the receipt extractor rejects it as an unknown entry type.
fn strip_leading_gate(mut lines: Vec<RecorderLine>) -> Vec<RecorderLine> {
    if lines
        .first()
        .and_then(|line| line.entry.get("type"))
        .and_then(Value::as_str)
        == Some("receipt_group_v1")
    {
        lines.remove(0);
    }
    lines
}

fn clone_lines(lines: &[RecorderLine]) -> Vec<RecorderLine> {
    lines.to_vec()
}

fn verify_checkpoint(line: &RecorderLine, signer: &str) -> Result<(), String> {
    let prev = line
        .entry
        .get("prev_hash")
        .and_then(Value::as_str)
        .ok_or("checkpoint missing prev_hash")?;
    let sig = line
        .entry
        .pointer("/detail/signature")
        .and_then(Value::as_str)
        .ok_or("checkpoint missing signature")?;
    let key_bytes = hex::decode(signer).map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| "invalid signer key length")?,
    )
    .map_err(|e| e.to_string())?;
    let sig_bytes = hex::decode(sig).map_err(|e| e.to_string())?;
    key.verify(
        prev.as_bytes(),
        &Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn verify_ael_run(root: &Path, run: &str, signer: &str) -> Result<(u64, String, u64), String> {
    verify_ael_records(root, run, signer, true)
}

const MAX_AEL_RECORD_BYTES: usize = 1 << 20;

fn verify_ael_records(
    root: &Path,
    run: &str,
    signer: &str,
    require_close: bool,
) -> Result<(u64, String, u64), String> {
    if !hex_exact(run, 32) {
        return Err("invalid native AEL run nonce".into());
    }
    let pubkey = hex::decode(signer).map_err(|e| e.to_string())?;
    let kid = sha256_hex(&pubkey);
    let base = root.join("ael").join(run);
    for p in [
        root.join("ael"),
        base.clone(),
        base.join("keys"),
        base.join("recorders"),
    ] {
        let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("native AEL directory missing or redirected".into());
        }
    }
    let manifest = read_regular(&base.join("manifest.json"), 4096)?;
    let want=format!("{{\"ael_format\":1,\"coverage\":\"mediated-only\",\"custody\":\"same-process\",\"recorders\":[{{\"file\":\"recorders/pipelock.jsonl\",\"id\":\"pipelock\",\"key\":\"{kid}\",\"run\":\"{run}\"}}],\"runs\":[\"{run}\"]}}");
    if manifest != want.as_bytes() {
        return Err("native AEL manifest differs from required layout".into());
    }
    let published = read_regular(&base.join("keys").join(format!("{kid}.pub")), 128)?;
    if published
        != base64::engine::general_purpose::STANDARD
            .encode(&pubkey)
            .as_bytes()
    {
        return Err("native AEL published key differs from trusted signer".into());
    }
    let raw = read_regular(&base.join("recorders/pipelock.jsonl"), 256 << 20)?;
    let key = VerifyingKey::from_bytes(&pubkey.try_into().map_err(|_| "invalid AEL key")?)
        .map_err(|e| e.to_string())?;
    let mut prev = "0".repeat(64);
    let mut count = 0u64;
    let mut closed = false;
    for line in raw.split_inclusive(|b| *b == b'\n') {
        // Go reads each record through a 1 MiB buffer: a terminated line may be
        // at most 1 MiB including its newline, and an unterminated fragment must
        // still fit the buffer. The bound applies before any trimming, so a
        // blank line cannot slip past it.
        let terminated = line.last() == Some(&b'\n');
        if line.len() > MAX_AEL_RECORD_BYTES || (!terminated && line.len() >= MAX_AEL_RECORD_BYTES)
        {
            return Err("native AEL stream has torn or oversized line".into());
        }
        if line.last() != Some(&b'\n') && !require_close && !closed {
            break;
        }
        if line.last() != Some(&b'\n') {
            return Err("native AEL stream is torn or continues after close".into());
        }
        let text = std::str::from_utf8(&line[..line.len() - 1]).map_err(|e| e.to_string())?;
        let text = trim_go_space(text);
        if text.is_empty() {
            continue;
        }
        if closed {
            return Err("native AEL stream continues after close".into());
        }
        let (p, s) = text
            .split_once('.')
            .ok_or("invalid native AEL compact record")?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .map_err(|e| e.to_string())?;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| e.to_string())?;
        key.verify(
            &payload,
            &Signature::from_slice(&sig).map_err(|e| e.to_string())?,
        )
        .map_err(|_| "native AEL signature verification failed")?;
        reject_duplicate_keys(std::str::from_utf8(&payload).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let val: Value = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
        if go_json_bytes(&val).map_err(|e| e.to_string())? != payload {
            return Err("native AEL payload is not canonical".into());
        }
        if val.get("v").and_then(Value::as_u64) != Some(1)
            || val.get("recorder").and_then(Value::as_str) != Some("pipelock")
            || val.get("run").and_then(Value::as_str) != Some(run)
            || val.get("key").and_then(Value::as_str) != Some(kid.as_str())
            || val.get("prev").and_then(Value::as_str) != Some(prev.as_str())
            || val.get("seq").and_then(Value::as_u64) != Some(count)
        {
            return Err("native AEL record breaks run binding or chain".into());
        }
        let typ = val
            .get("type")
            .and_then(Value::as_str)
            .ok_or("AEL record lacks type")?;
        let allowed: &[&str] = match typ {
            "open" if count == 0 => &[
                "v", "type", "run", "recorder", "key", "prev", "seq", "ts", "hmax", "htol",
            ],
            "activity" => &[
                "v", "type", "run", "recorder", "key", "prev", "seq", "ts", "event",
            ],
            "heartbeat" => &["v", "type", "run", "recorder", "key", "prev", "seq", "ts"],
            "close" => &[
                "v", "type", "run", "recorder", "key", "prev", "seq", "ts", "count", "head",
            ],
            _ => return Err("invalid native AEL lifecycle or record type".into()),
        };
        let fields = val.as_object().ok_or("AEL payload must be an object")?;
        if fields.len() != allowed.len()
            || fields
                .keys()
                .any(|field| !allowed.contains(&field.as_str()))
        {
            return Err("native AEL record fields differ from type schema".into());
        }
        let stamp = val
            .get("ts")
            .and_then(Value::as_str)
            .ok_or("AEL timestamp missing")?;
        if !canonical_time(stamp) {
            return Err("native AEL timestamp is not canonical UTC RFC3339Nano".into());
        }
        if typ == "open" {
            let hmax = val
                .get("hmax")
                .and_then(Value::as_i64)
                .ok_or("AEL hmax invalid")?;
            let htol = val
                .get("htol")
                .and_then(Value::as_i64)
                .ok_or("AEL htol invalid")?;
            if hmax < 0 || htol < 0 || htol > hmax {
                return Err("native AEL heartbeat bounds invalid".into());
            }
        }
        if typ == "activity" {
            let event = val
                .get("event")
                .and_then(Value::as_object)
                .ok_or("AEL event invalid")?;
            if event.len() != 3
                || event
                    .get("class")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                || event
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty()
                || !matches!(
                    event.get("dir").and_then(Value::as_str),
                    Some("in" | "out" | "internal")
                )
            {
                return Err("native AEL event invalid".into());
            }
        }
        if count == 0 && typ != "open" || count > 0 && typ == "open" {
            return Err("invalid native AEL lifecycle".into());
        }
        if typ == "close"
            && (val.get("count").and_then(Value::as_u64) != Some(count + 1)
                || val.get("head").and_then(Value::as_str) != Some(prev.as_str()))
        {
            return Err("native AEL close head differs".into());
        }
        let hash = Sha256::digest(&payload);
        prev = hex::encode(hash);
        count += 1;
        closed = typ == "close";
    }
    if require_close && (!closed || count < 2) {
        return Err("native AEL run has no signed close".into());
    }
    Ok((count.saturating_sub(1), prev, count))
}

fn verify_ael_inventory(
    dir: &Path,
    open: &ReceiptGroupOpen,
    trusted: &[String],
    incomplete: bool,
) -> Result<(bool, bool), String> {
    let ael_root = dir.join("ael");
    let mut present = BTreeSet::new();
    for entry in fs::read_dir(&ael_root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !hex_exact(&name, 32) || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!("invalid native AEL run directory {name:?}"));
        }
        present.insert(name);
    }
    let mut claims = BTreeSet::new();
    let session_files = indexed_session_files(dir)?;
    for shard in &open.shards {
        if incomplete && !session_files.contains_key(&shard.session_id) {
            continue;
        }
        let lines = read_group_session_lines(dir, &shard.session_id, incomplete)?;
        let run = lines
            .iter()
            .find_map(|line| {
                let r = line.entry.get("detail")?;
                r.pointer("/action_record/session_control/open/run_nonce")
                    .or_else(|| r.pointer("/payload/session_control/open/run_nonce"))
                    .and_then(Value::as_str)
            })
            .ok_or("group shard has no signed native AEL owner")?;
        if !claims.insert(run.to_string()) {
            return Err(duplicate_signed_ael_run_error(run));
        }
        if !present.contains(run) {
            return Err(format!("native AEL run {run} is missing"));
        }
    }
    // A directory may contain predecessor and legacy sessions as well as the
    // group being checked. Index their signed openings before checking runs.
    if !open.previous_group_id.is_empty() {
        let raw = bounded_read(
            dir,
            &format!("receipt-group-{}-open.json", open.previous_group_id),
        )?;
        let predecessor: ReceiptGroupOpen = strict_artifact(&raw)?;
        validate_open(&predecessor, &open.previous_group_id)?;
        verify_signed(
            OPEN_DOMAIN,
            &predecessor,
            &predecessor.signature,
            &predecessor.signer_key,
            trusted,
        )?;
    }
    let mut owners = BTreeMap::new();
    for session in indexed_session_files(dir)?.keys() {
        // Go tolerates an unterminated final write only for a legacy session,
        // the predecessor group, or (while the group is open) this group.
        let (lines, torn) = read_group_session(dir, session, true)?;
        if lines.is_empty() {
            return Err("empty receipt session inventory file".into());
        }
        if let Some(err) =
            verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>())
        {
            return Err(format!("receipt session inventory recorder chain: {err}"));
        }
        let gate = if lines[0].entry.get("type").and_then(Value::as_str) == Some("receipt_group_v1")
        {
            let gate = lines[0]
                .entry
                .get("detail")
                .ok_or("receipt group gate has no detail")?;
            let group_id = gate
                .get("group_id")
                .and_then(Value::as_str)
                .ok_or("receipt group gate has no group ID")?;
            let raw = bounded_read(dir, &format!("receipt-group-{group_id}-open.json"))?;
            let owner: ReceiptGroupOpen = strict_artifact(&raw)?;
            validate_open(&owner, group_id)?;
            verify_signed(
                OPEN_DOMAIN,
                &owner,
                &owner.signature,
                &owner.signer_key,
                trusted,
            )?;
            let index = gate
                .get("shard_index")
                .and_then(Value::as_u64)
                .ok_or("receipt group gate has no shard index")? as usize;
            let member = owner
                .shards
                .get(index)
                .ok_or("receipt group gate shard index out of range")?;
            let expected = json!({"group_id":owner.group_id,"shard_index":index,"session_id":member.session_id,"open_manifest_sha256":sha256_hex(&raw),"signer_key":owner.signer_key,"previous_group_id":owner.previous_group_id,"previous_open_manifest_sha256":owner.previous_open_manifest_sha256});
            if member.session_id != *session || gate != &expected {
                return Err("receipt group gate is not owned by a signed opening".into());
            }
            Some(gate)
        } else {
            None
        };
        if torn {
            let owner_group = gate
                .and_then(|value| value.get("group_id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !owner_group.is_empty()
                && owner_group != open.previous_group_id
                && !(incomplete && owner_group == open.group_id)
            {
                return Err("receipt group session has a torn tail in another group".into());
            }
        }
        // Go walks each inventory session's whole v1 chain against the trusted
        // set (a group shard against its opening signer), so a forged or
        // untrusted receipt anywhere in a neighbor or legacy session fails the
        // group, not only its session_open.
        let typed = extract_typed_from_lines(strip_leading_gate(lines.clone()))
            .map_err(|e| e.to_string())?;
        if !typed.action.is_empty() {
            let pin = match gate {
                Some(gate) => gate
                    .get("signer_key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                None => trusted.join(","),
            };
            let walked = verify_chain_with_options(&typed.action, &pin, false);
            if !walked.valid {
                return Err(format!(
                    "inventory receipt session {session:?} chain invalid: {}",
                    walked.error.unwrap_or_default()
                ));
            }
        }
        let mut signed_open_seen = false;
        for line in &lines {
            let entry = &line.entry;
            // Go counts only action_receipt entries as signed receipts here; a
            // decision entry's detail is not a receipt, however it is shaped.
            if entry.get("type").and_then(Value::as_str) != Some("action_receipt") {
                continue;
            }
            let Some(receipt) = entry.get("detail") else {
                continue;
            };
            let kind = receipt
                .pointer("/action_record/session_control/kind")
                .or_else(|| receipt.pointer("/payload/session_control/kind"))
                .and_then(Value::as_str);
            if kind != Some("session_open") {
                continue;
            }
            if signed_open_seen {
                return Err("receipt session has multiple signed native AEL openings".into());
            }
            signed_open_seen = true;
            let signer = receipt
                .get("signer_key")
                .and_then(Value::as_str)
                .ok_or("signed session owner lacks signer key")?;
            if !trusted.iter().any(|key| key.eq_ignore_ascii_case(signer))
                || !verify_chain_with_options(std::slice::from_ref(receipt), signer, false).valid
            {
                return Err("native AEL run has no signed session owner".into());
            }
            let run = receipt
                .pointer("/action_record/session_control/open/run_nonce")
                .or_else(|| receipt.pointer("/payload/session_control/open/run_nonce"))
                .and_then(Value::as_str);
            let Some(run) = run else {
                if gate.is_some() {
                    return Err("group shard has no signed native AEL owner".into());
                }
                continue;
            };
            if !hex_exact(run, 32) {
                return Err("native AEL run has no signed session owner".into());
            }
            let binding = receipt
                .pointer("/action_record/session_control/open/group_binding")
                .or_else(|| receipt.pointer("/payload/session_control/open/group_binding"));
            if binding != gate {
                return Err("signed session open disagrees with recorder group gate".into());
            }
            let owner_group = gate
                .and_then(|value| value.get("group_id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let completed = lines.iter().any(|line| {
                line.entry.get("type").and_then(Value::as_str) == Some("transcript_root")
                    || (line.entry.get("type").and_then(Value::as_str) == Some("action_receipt")
                        && line
                            .entry
                            .get("detail")
                            .and_then(|detail| {
                                detail
                                    .pointer("/action_record/session_control/kind")
                                    .or_else(|| detail.pointer("/payload/session_control/kind"))
                            })
                            .and_then(Value::as_str)
                            == Some("session_close"))
            });
            if owners
                .insert(
                    run.to_string(),
                    (
                        signer.to_string(),
                        owner_group.to_string(),
                        completed,
                        session.clone(),
                    ),
                )
                .is_some()
            {
                return Err(duplicate_signed_ael_run_error(run));
            }
        }
    }
    for run in owners.keys() {
        if !present.contains(run) {
            return Err(format!(
                "native AEL run {run:?} claimed by a signed session_open is missing"
            ));
        }
    }
    let signed_sessions = open.shards.iter().map(|shard| shard.session_id.as_str());
    let claimed_sessions = owners.values().filter_map(|(_, group_id, _, session)| {
        (group_id == &open.group_id).then_some(session.as_str())
    });
    check_group_ael_membership(signed_sessions, claimed_sessions, incomplete)?;
    let mut open_tail = false;
    let mut neighbor_open_tail = false;
    for run in present {
        let Some((signer, group_id, completed, _session)) = owners.get(&run) else {
            return Err(format!("native AEL run {run} has no signed session owner"));
        };
        verify_ael_records(dir, &run, signer, *completed)
            .map_err(|err| format!("native AEL run {run} invalid: {err}"))?;
        if !completed {
            if group_id == &open.group_id {
                open_tail = true;
            } else {
                neighbor_open_tail = true;
            }
        }
    }
    Ok((open_tail, neighbor_open_tail))
}

fn check_group_ael_membership<'a>(
    signed: impl IntoIterator<Item = &'a str>,
    claimed: impl IntoIterator<Item = &'a str>,
    incomplete: bool,
) -> Result<(), String> {
    let signed_sessions: BTreeSet<&str> = signed.into_iter().collect();
    let mut grouped_sessions = BTreeSet::new();
    for session in claimed {
        if !signed_sessions.contains(session) {
            return Err(format!("receipt group native AEL claim session {session:?} is outside signed shard membership"));
        }
        if !grouped_sessions.insert(session) {
            return Err(format!(
                "receipt group native AEL session {session:?} has duplicate claims"
            ));
        }
    }
    if !incomplete && grouped_sessions != signed_sessions {
        return Err(format!(
            "receipt group native AEL claims = {}, want {}",
            grouped_sessions.len(),
            signed_sessions.len()
        ));
    }
    Ok(())
}

fn duplicate_signed_ael_run_error(run: &str) -> String {
    format!("duplicate signed native AEL run {run}")
}

#[cfg(test)]
mod membership_vectors {
    use super::{check_group_ael_membership, duplicate_signed_ael_run_error, read_bounded_stream};
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        signed_sessions: Vec<String>,
        claimed_sessions: Vec<String>,
        incomplete: bool,
        error: String,
    }

    #[test]
    fn shared_signed_shard_ael_membership_vectors() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../../receipt-group-membership-vectors.json"))
                .unwrap();
        assert_eq!(cases.len(), 5);
        for case in cases {
            let result = check_group_ael_membership(
                case.signed_sessions.iter().map(String::as_str),
                case.claimed_sessions.iter().map(String::as_str),
                case.incomplete,
            );
            match result {
                Ok(()) => assert!(case.error.is_empty(), "{}", case.name),
                Err(error) => assert!(
                    error.contains(&case.error) && !case.error.is_empty(),
                    "{}: {error}",
                    case.name
                ),
            }
        }
    }

    #[derive(Deserialize)]
    struct StreamCase {
        name: String,
        initial_size: usize,
        limit: u64,
        data: String,
        error: String,
    }

    #[derive(Deserialize)]
    struct DuplicateRun {
        run: String,
        error: String,
    }

    #[derive(Deserialize)]
    struct StreamVectors {
        bounded_stream: Vec<StreamCase>,
        duplicate_run: DuplicateRun,
    }

    #[test]
    fn shared_ael_stream_and_duplicate_run_vectors() {
        let vectors: StreamVectors =
            serde_json::from_str(include_str!("../../receipt-group-stream-vectors.json")).unwrap();
        for case in vectors.bounded_stream {
            assert!(case.initial_size <= case.limit as usize, "{}", case.name);
            let result = read_bounded_stream(Cursor::new(case.data.as_bytes()), case.limit);
            if case.error.is_empty() {
                assert_eq!(result.unwrap(), case.data.as_bytes(), "{}", case.name);
            } else {
                assert!(result.unwrap_err().contains(&case.error), "{}", case.name);
            }
        }
        assert!(duplicate_signed_ael_run_error(&vectors.duplicate_run.run)
            .contains(&vectors.duplicate_run.error));
    }
}

fn verify_transition(
    dir: &Path,
    open: &ReceiptGroupOpen,
    open_hash: &str,
    trusted: &[String],
) -> Result<(), String> {
    let pred_raw = bounded_read(
        dir,
        &format!("receipt-group-{}-open.json", open.previous_group_id),
    )?;
    let pred: ReceiptGroupOpen = strict_artifact(&pred_raw)?;
    validate_open(&pred, &open.previous_group_id)?;
    verify_signed(
        OPEN_DOMAIN,
        &pred,
        &pred.signature,
        &pred.signer_key,
        trusted,
    )?;
    if sha256_hex(&pred_raw) != open.previous_open_manifest_sha256 {
        return Err("predecessor open digest differs".into());
    }
    let transition_raw = bounded_read(
        dir,
        &format!("receipt-group-{}-transition.json", open.group_id),
    )?;
    let tr: ReceiptGroupTransition = strict_artifact(&transition_raw)?;
    let pred_close_path = dir.join(format!("receipt-group-{}-close.json", pred.group_id));
    let pred_close_raw = match fs::symlink_metadata(&pred_close_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("stat predecessor close: {err}")),
        Ok(_) => Some(bounded_read(
            dir,
            &format!("receipt-group-{}-close.json", pred.group_id),
        )?),
    };
    let close_hash = pred_close_raw
        .as_deref()
        .map(sha256_hex)
        .unwrap_or_default();
    if tr.version != 1
        || tr.kind != "receipt_group_transition"
        || tr.new_group_id != open.group_id
        || tr.new_open_manifest_sha256 != open_hash
        || tr.previous_group_id != pred.group_id
        || tr.previous_open_manifest_sha256 != open.previous_open_manifest_sha256
        || tr.previous_close_manifest_sha256 != close_hash
        || tr.signer_key != open.signer_key
        || !canonical_time(&tr.created_at)
        || tr.predecessors.len() != pred.shards.len()
    {
        return Err("signed transition does not bind predecessor and successor".into());
    }
    verify_signed(
        TRANSITION_DOMAIN,
        &tr,
        &tr.signature,
        &tr.signer_key,
        trusted,
    )?;
    let pred_heads = pred_close_raw
        .map(|raw| {
            let c: ReceiptGroupClose = strict_artifact(&raw)?;
            validate_close(&c, &pred, &open.previous_open_manifest_sha256)?;
            verify_signed(CLOSE_DOMAIN, &c, &c.signature, &c.signer_key, trusted)?;
            Ok::<_, String>(c.shards)
        })
        .transpose()?;
    for (i, p) in tr.predecessors.iter().enumerate() {
        if p.shard_index != i || p.session_id != pred.shards[i].session_id {
            return Err("transition predecessor shard identity differs".into());
        }
        if let Some(heads) = &pred_heads {
            let actual = verify_shard(
                dir,
                &pred,
                &open.previous_open_manifest_sha256,
                i,
                &pred.shards[i],
            )?;
            if p.final_chain_seq != heads[i].final_chain_seq
                || p.final_chain_hash != heads[i].final_chain_hash
                || !p.recovery_seal_sha256.is_empty()
                || actual != heads[i]
            {
                return Err("closed predecessor transition head differs".into());
            }
        } else if p.recovery_seal_sha256.is_empty() {
            require_writer_gone(dir, &p.session_id, i)?;
            verify_complete_prefix(dir, &pred, &open.previous_open_manifest_sha256, i, p)?;
        } else {
            require_writer_gone(dir, &p.session_id, i)?;
            let seal_name = format!("chain-link-{}.json", p.session_id);
            let raw = bounded_read(dir, &seal_name)?;
            if sha256_hex(&raw) != p.recovery_seal_sha256 {
                return Err("recovery seal digest differs".into());
            }
            let seal: RecoverySeal = decode_seal(&raw)?;
            if seal.predecessor_signer_key != pred.signer_key {
                return Err("recovery seal predecessor signer differs from group opening".into());
            }
            verify_recovery_seal(
                dir,
                &seal,
                RecoverySealContext {
                    transition: &tr,
                    predecessor: &pred,
                    predecessor_open_hash: &open.previous_open_manifest_sha256,
                    successor: open,
                    index: i,
                    trusted,
                },
            )?;
        }
    }
    verify_transitions_referencing(dir, &open.previous_open_manifest_sha256, trusted, false)?;
    Ok(())
}

// require_writer_gone mirrors Go's EvidenceRunWriterGone for a predecessor with
// no signed close: the run's lifetime lock must exist and no live writer may
// hold it. A missing lock cannot prove the writer exited, so it fails closed,
// as does a platform with no advisory lock.
fn require_writer_gone(dir: &Path, session: &str, index: usize) -> Result<(), String> {
    let path = dir.join(format!("writer-{session}.lock"));
    let fail = |why: String| {
        Err(format!(
            "incomplete predecessor shard {index}: probe receipt group predecessor writer: {why}"
        ))
    };
    let checked = match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_file() => meta,
        Ok(_) => return fail("predecessor writer lock is not a regular file".into()),
        Err(err) => return fail(format!("opening evidence file for writer probe: {err}")),
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(err) => return fail(format!("opening evidence file for writer probe: {err}")),
        };
        // The lock must be the regular file checked above, not one swapped in
        // before the open: a probe of another inode proves nothing.
        match file.metadata() {
            Ok(opened)
                if opened.file_type().is_file()
                    && opened.dev() == checked.dev()
                    && opened.ino() == checked.ino() => {}
            Ok(_) => return fail("predecessor writer lock changed during open".into()),
            Err(err) => return fail(format!("probing evidence writer lock: {err}")),
        }
        let fd = file.as_raw_fd();
        // SAFETY: fd is a valid descriptor owned by `file` for this whole call.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            return if err.kind() == std::io::ErrorKind::WouldBlock {
                Err(format!(
                    "incomplete predecessor shard {index}: receipt group predecessor writer still present"
                ))
            } else {
                fail(format!("probing evidence writer lock: {err}"))
            };
        }
        // SAFETY: same descriptor; the probe lock is released before returning.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fail("platform cannot prove predecessor writer is gone".into())
    }
}

fn verify_group_artifact_names(dir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("receipt-group-") {
            continue;
        }
        let rest = &name["receipt-group-".len()..];
        let Some((id, phase_json)) = rest.split_once('-') else {
            return Err("malformed receipt group artifact name".into());
        };
        let phase = phase_json
            .strip_suffix(".json")
            .ok_or("malformed receipt group artifact extension")?;
        if !hex_exact(id, 32) || !matches!(phase, "open" | "close" | "transition") {
            return Err("unknown receipt group artifact name".into());
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("receipt group artifact is not a regular file".into());
        }
    }
    Ok(())
}

fn verify_transitions_referencing(
    dir: &Path,
    predecessor_open_hash: &str,
    trusted: &[String],
    verify_links: bool,
) -> Result<(), String> {
    let mut matches = 0;
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("receipt-group-") || !name.ends_with("-transition.json") {
            continue;
        }
        let raw = bounded_read(dir, &name)?;
        let tr: ReceiptGroupTransition = strict_artifact(&raw)?;
        if tr.new_group_id != name["receipt-group-".len()..name.len() - "-transition.json".len()] {
            return Err("receipt group transition file identity differs".into());
        }
        let refers_to_open = tr.previous_open_manifest_sha256 == predecessor_open_hash;
        let own_key = [tr.signer_key.clone()];
        let keys = if refers_to_open { trusted } else { &own_key };
        verify_signed(TRANSITION_DOMAIN, &tr, &tr.signature, &tr.signer_key, keys)?;
        if !refers_to_open {
            continue;
        }
        matches += 1;
        if matches > 1 {
            return Err("multiple successor transitions name one receipt group".into());
        }
        if !verify_links {
            continue;
        }
        let successor_raw =
            bounded_read(dir, &format!("receipt-group-{}-open.json", tr.new_group_id))?;
        let successor: ReceiptGroupOpen = strict_artifact(&successor_raw)?;
        validate_open(&successor, &tr.new_group_id)?;
        verify_signed(
            OPEN_DOMAIN,
            &successor,
            &successor.signature,
            &successor.signer_key,
            trusted,
        )?;
        let open_hash = sha256_hex(&successor_raw);
        verify_transition(dir, &successor, &open_hash, trusted)?;
    }
    Ok(())
}

struct RecoverySealContext<'a> {
    transition: &'a ReceiptGroupTransition,
    predecessor: &'a ReceiptGroupOpen,
    predecessor_open_hash: &'a str,
    successor: &'a ReceiptGroupOpen,
    index: usize,
    trusted: &'a [String],
}

fn verify_recovery_seal(
    dir: &Path,
    seal: &RecoverySeal,
    context: RecoverySealContext<'_>,
) -> Result<(), String> {
    let RecoverySealContext {
        transition: tr,
        predecessor,
        predecessor_open_hash,
        successor,
        index,
        trusted,
    } = context;
    if seal.kind != "recovery_seal"
        || seal.version != 1
        || seal.predecessor_session != tr.predecessors[index].session_id
        || seal.successor_session != successor.shards[index % successor.shards.len()].session_id
        || seal.successor_signer_key != successor.signer_key
        || !canonical_time(&seal.observed_at)
        || parse_evidence_filename(&seal.shard).map(|(session, _)| session)
            != Some(seal.predecessor_session.clone())
        || !hex_exact(&seal.shard_sha256, 64)
        || !hex_exact(&seal.successor_open_hash, 64)
    {
        return Err(format!(
            "recovery seal binding or header invalid for shard {index}"
        ));
    }
    if !trusted.iter().any(|k| k == &seal.successor_signer_key) {
        return Err("recovery seal signer is not trusted".into());
    }
    let claim = &tr.predecessors[index];
    if seal.predecessor_tail_seq != claim.final_chain_seq
        || seal.predecessor_tail_hash != claim.final_chain_hash
    {
        return Err("recovery seal receipt head differs from transition claim".into());
    }
    let mut unsigned = serde_json::to_value(seal).map_err(|e| e.to_string())?;
    unsigned
        .as_object_mut()
        .ok_or("recovery seal is not object")?
        .remove("signature");
    let preimage = [
        b"pipelock-recovery-seal-v1\0".as_slice(),
        &go_json_bytes(&unsigned).map_err(|e| e.to_string())?,
    ]
    .concat();
    let key_bytes = hex::decode(&seal.successor_signer_key).map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| "invalid recovery signer")?,
    )
    .map_err(|e| e.to_string())?;
    let sighex = seal
        .signature
        .strip_prefix("ed25519:")
        .ok_or("invalid recovery seal signature")?;
    key.verify(
        &preimage,
        &Signature::from_slice(&hex::decode(sighex).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let path = dir.join(&seal.shard);
    let raw = read_regular(&path, crate::util::MAX_VERIFIER_INPUT_BYTES)?;
    if raw.len() as u64 != seal.shard_size
        || sha256_hex(&raw) != seal.shard_sha256
        || seal.damage_offset >= raw.len() as u64
    {
        return Err("recovery seal shard digest or bounds differ".into());
    }
    let offset = seal.damage_offset as usize;
    if offset > 0 && raw[offset - 1] != b'\n' {
        return Err("recovery seal damage offset is not a line boundary".into());
    }
    let session_index = indexed_session_files(dir)?;
    let files = session_index
        .get(&seal.predecessor_session)
        .ok_or("recovery seal predecessor evidence is missing")?;
    if files.last().and_then(|file| file.file_name()) != Some(std::ffi::OsStr::new(&seal.shard)) {
        return Err("recovery seal shard is not the last predecessor segment".into());
    }
    let mut prefix = Vec::new();
    let mut found = false;
    for file in files {
        if file
            .file_name()
            .is_some_and(|name| name == seal.shard.as_str())
        {
            prefix.extend_from_slice(&raw[..offset]);
            found = true;
            break;
        }
        let part = read_regular(file, crate::util::MAX_VERIFIER_INPUT_BYTES)?;
        if !part.ends_with(b"\n") {
            return Err("recovery seal predecessor has an earlier torn segment".into());
        }
        prefix.extend_from_slice(&part);
    }
    if !found {
        return Err("recovery seal shard is not in predecessor session".into());
    }
    let prefix = std::str::from_utf8(&prefix).map_err(|e| e.to_string())?;
    let lines = read_entry_lines_text(prefix).map_err(|e| e.to_string())?;
    if lines.is_empty()
        || verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>())
            .is_some()
    {
        return Err("recovery seal complete prefix chain invalid".into());
    }
    let last = lines.last().unwrap();
    if last.entry.get("seq").and_then(Value::as_u64) != Some(seal.last_good_seq)
        || last.entry.get("hash").and_then(Value::as_str) != Some(seal.last_good_hash.as_str())
    {
        return Err("recovery seal last-good head differs from prefix".into());
    }
    let gate = json!({"group_id":predecessor.group_id,"shard_index":index,"session_id":seal.predecessor_session,"open_manifest_sha256":predecessor_open_hash,"signer_key":predecessor.signer_key,"previous_group_id":predecessor.previous_group_id,"previous_open_manifest_sha256":predecessor.previous_open_manifest_sha256});
    if lines[0].entry.get("type").and_then(Value::as_str) != Some("receipt_group_v1")
        || lines[0].entry.get("detail") != Some(&gate)
    {
        return Err("recovery seal predecessor group gate differs".into());
    }
    verify_prefix_integrity(&lines, &predecessor.signer_key)?;
    let mut receipt_lines = strip_leading_gate(lines);
    let typed =
        extract_typed_from_lines(std::mem::take(&mut receipt_lines)).map_err(|e| e.to_string())?;
    if !typed.action.is_empty() && !typed.evidence.is_empty() {
        let evidence =
            verify_chain_with_options(&typed.evidence, &seal.predecessor_signer_key, false);
        if !evidence.valid {
            return Err(format!(
                "recovery seal v2 prefix invalid: {}",
                evidence.error.unwrap_or_default()
            ));
        }
    }
    let rs = if typed.action.is_empty() {
        typed.evidence
    } else {
        typed.action
    };
    let cr = verify_chain_with_options(&rs, &seal.predecessor_signer_key, false);
    if !cr.valid
        || cr.final_seq != seal.predecessor_tail_seq
        || cr.root_hash != seal.predecessor_tail_hash
    {
        return Err("recovery seal signed receipt prefix differs".into());
    }
    let successor_lines = read_group_session_lines(dir, &seal.successor_session, true)?;
    let successor_receipts =
        extract_typed_from_lines(strip_leading_gate(successor_lines)).map_err(|e| e.to_string())?;
    let first = successor_receipts
        .action
        .first()
        .or(successor_receipts.evidence.first())
        .ok_or("recovery successor has no opening receipt")?;
    if receipt_hash(first) != seal.successor_open_hash {
        return Err("recovery seal successor opening hash differs".into());
    }
    Ok(())
}

fn verify_complete_prefix(
    dir: &Path,
    open: &ReceiptGroupOpen,
    open_hash: &str,
    index: usize,
    claim: &ReceiptGroupPredecessor,
) -> Result<(), String> {
    let session = &open.shards[index].session_id;
    let lines = read_group_session_lines(dir, session, false)?;
    if lines.is_empty()
        || verify_recorder_chain(&lines.iter().map(|l| l.line.as_str()).collect::<Vec<_>>())
            .is_some()
    {
        return Err("unsealed predecessor recorder chain invalid".into());
    }
    let gate = json!({"group_id":open.group_id,"shard_index":index,"session_id":session,"open_manifest_sha256":open_hash,"signer_key":open.signer_key,"previous_group_id":open.previous_group_id,"previous_open_manifest_sha256":open.previous_open_manifest_sha256});
    if lines[0].entry.get("type").and_then(Value::as_str) != Some("receipt_group_v1")
        || lines[0].entry.get("detail") != Some(&gate)
    {
        return Err("unsealed predecessor group gate differs".into());
    }
    verify_prefix_integrity(&lines, &open.signer_key)?;
    let rs = extract_typed_from_lines(strip_leading_gate(lines)).map_err(|e| e.to_string())?;
    for chain_receipts in [&rs.action, &rs.evidence] {
        if chain_receipts.is_empty() {
            continue;
        }
        let verified = verify_chain_with_options(chain_receipts, &open.signer_key, false);
        if !verified.valid {
            return Err(format!(
                "unsealed predecessor receipt chain invalid: {}",
                verified.error.unwrap_or_default()
            ));
        }
    }
    let receipts = if rs.action.is_empty() {
        rs.evidence
    } else {
        rs.action
    };
    let chain = verify_chain_with_options(&receipts, &open.signer_key, false);
    if !chain.valid
        || chain.final_seq != claim.final_chain_seq
        || chain.root_hash != claim.final_chain_hash
    {
        return Err("unsealed predecessor signed chain differs from transition".into());
    }
    let first = receipts
        .first()
        .ok_or("unsealed predecessor has no signed opening")?;
    let binding = first
        .pointer("/action_record/session_control/open/group_binding")
        .or_else(|| first.pointer("/payload/session_control/open/group_binding"));
    let gate = json!({"group_id":open.group_id,"shard_index":index,"session_id":session,"open_manifest_sha256":open_hash,"signer_key":open.signer_key,"previous_group_id":open.previous_group_id,"previous_open_manifest_sha256":open.previous_open_manifest_sha256});
    if binding != Some(&gate) {
        return Err("unsealed predecessor signed open differs from group gate".into());
    }
    Ok(())
}

fn decode_seal(raw: &[u8]) -> Result<RecoverySeal, String> {
    let text = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    reject_duplicate_keys(text).map_err(|e| e.to_string())?;
    serde_json::from_str(text).map_err(|e| format!("decode recovery seal: {e}"))
}

fn bounded_read(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    if name.contains('/') || name.contains('\\') {
        return Err("invalid artifact basename".into());
    }
    let p = dir.join(name);
    let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_GROUP_FILE {
        return Err("invalid receipt group artifact file".into());
    }
    read_regular(&p, MAX_GROUP_FILE)
}

/// Open a path already checked with `symlink_metadata` without following a
/// symlink or blocking on a FIFO swapped in after the check (Go opens evidence
/// with O_NONBLOCK and O_NOFOLLOW), then require the descriptor to be the same
/// regular file as the checked path.
fn open_checked_regular(path: &Path, before: &fs::Metadata) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() {
        return Err("evidence artifact is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err("evidence artifact changed during open".into());
        }
    }
    #[cfg(not(unix))]
    let _ = before;
    Ok(file)
}

fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > max {
        return Err("evidence artifact is not a bounded regular file".into());
    }
    let raw = read_bounded_stream(open_checked_regular(path, &before)?, max)?;
    let after = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !after.is_file()
        || after.file_type().is_symlink()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("evidence artifact changed during read".into());
    }
    Ok(raw)
}

fn read_bounded_stream(reader: impl Read, max: u64) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    reader
        .take(max + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > max {
        return Err("evidence artifact exceeds size limit during read".into());
    }
    Ok(raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InventoryFingerprint {
    xor: [u8; 32],
    count: u64,
}

fn inventory_fingerprint(dir: &Path) -> Result<InventoryFingerprint, String> {
    let mut out = InventoryFingerprint {
        xor: [0; 32],
        count: 0,
    };
    fingerprint_tree(dir, dir, &mut out)?;
    Ok(out)
}

fn fingerprint_tree(
    root: &Path,
    current: &Path,
    out: &mut InventoryFingerprint,
) -> Result<(), String> {
    for e in fs::read_dir(current).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        let path = e.path();
        let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if m.file_type().is_symlink() {
            return Err("symlink in receipt group inventory".into());
        }
        let mt = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let rel = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        let kind = if m.is_dir() {
            b"dir".as_slice()
        } else {
            b"file".as_slice()
        };
        let size = m.len().to_be_bytes();
        let modified = mt.to_be_bytes();
        let digest = Sha256::digest([rel.as_bytes(), kind, &size, &modified].concat());
        for (dst, src) in out.xor.iter_mut().zip(digest) {
            *dst ^= src;
        }
        out.count = out
            .count
            .checked_add(1)
            .ok_or("inventory entry count overflow")?;
        if m.is_dir() {
            fingerprint_tree(root, &path, out)?;
        }
    }
    Ok(())
}

fn hex_exact(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn canonical_time(s: &str) -> bool {
    let Some((date, clock)) = s.split_once('T') else {
        return false;
    };
    let Some((year, rest)) = date.split_once('-') else {
        return false;
    };
    let Some((month, day)) = rest.split_once('-') else {
        return false;
    };
    let Some((hms, zone)) = clock.strip_suffix('Z').map(|x| (x, "Z")) else {
        return false;
    };
    let _ = zone;
    let Some((hour, rest)) = hms.split_once(':') else {
        return false;
    };
    let Some((minute, sec)) = rest.split_once(':') else {
        return false;
    };
    let (second, fraction, has_dot) = match sec.split_once('.') {
        Some((s, f)) => (s, f, true),
        None => (sec, "", false),
    };
    // Go's RFC3339Nano writer emits ASCII digits only and never a bare '.'.
    // str::parse::<u32> would accept a leading '+', so check digits first.
    if has_dot && fraction.is_empty() {
        return false;
    }
    if [year, month, day, hour, minute, second]
        .iter()
        .any(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let nums = [year, month, day, hour, minute, second]
        .iter()
        .map(|v| v.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>();
    let Some(n) = nums else { return false };
    let (y, m, d, h, mi, se) = (n[0], n[1], n[2], n[3], n[4], n[5]);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    year.len() == 4
        && month.len() == 2
        && day.len() == 2
        && hour.len() == 2
        && minute.len() == 2
        && second.len() == 2
        && y > 0
        && d > 0
        && d <= days
        && h < 24
        && mi < 60
        && se < 60
        && (fraction.is_empty()
            || fraction.len() <= 9
                && fraction.bytes().all(|b| b.is_ascii_digit())
                && !fraction.ends_with('0'))
}

#[cfg(test)]
mod canonical_time_vectors {
    use super::canonical_time;

    #[test]
    fn accepts_go_rfc3339nano_and_rejects_non_canonical_forms() {
        for good in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.5Z",
            "2026-02-28T23:59:59.123456789Z",
            "2024-02-29T00:00:00Z",
        ] {
            assert!(canonical_time(good), "{good}");
        }
        for bad in [
            "+026-+1-+1T+1:+1:+1Z",
            "2026-01-01T+0:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00.50Z",
            "2026-01-01T00:00:00.1234567890Z",
            "2026-01-01T00:00:00.+5Z",
            "2026-1-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-01-01T00:00:00+00:00",
            "２０２６-01-01T00:00:00Z",
        ] {
            assert!(!canonical_time(bad), "{bad}");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::mpsc;
    use std::time::Duration;

    // A path swapped to a FIFO after the regular-file check must fail closed
    // promptly instead of blocking the verifier on the open.
    #[test]
    fn fifo_swapped_in_after_the_check_fails_closed_without_blocking() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("plk-fifo-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let regular = dir.join("regular");
        fs::write(&regular, b"x\n").unwrap();
        let fifo = dir.join("swapped");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let checked = fs::symlink_metadata(&regular).unwrap();
        let (tx, rx) = mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(open_checked_regular(&path, &checked).map(|_| ()));
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("open blocked on a FIFO");
        assert!(outcome.is_err());
        let (tx, rx) = mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular(&path, 1024));
        });
        // read_regular's own lstat refuses the FIFO outright.
        assert!(rx
            .recv_timeout(Duration::from_secs(5))
            .expect("read blocked on a FIFO")
            .is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}

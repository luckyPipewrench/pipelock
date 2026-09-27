// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Restart continuity across the receipt chains of one base, ported from the
//! Go reference `internal/receipt/chain_set.go` and `chain_link.go`. Every
//! Pipelock process run writes its own chain, `<base>.run.<32hex>`, and a
//! restart may publish a signed link file `chain-link-<predecessor>.json`
//! naming the exact tail it continues. [`verify_base`] verifies every chain of
//! a base and every link file that names one, with the same findings Go
//! reports.
//!
//! One Go check is not ported: the recorder file's own entry hash chain (Go
//! finding `outer_chain_broken`). The SDK verifiers check the receipt chain
//! inside the recorder file, in this mode as in single-session mode.

use crate::chain::{receipt_hash, verify_chain_with_options};
use crate::recorder::extract_typed_receipts;
use crate::rotation::{
    canonical_utc_timestamp, verify_chain_with_endorsements, verify_rotation_endorsement,
    RotationEndorsement,
};
use crate::types::{ChainResult, Receipt};
use crate::util::{read_verifier_bytes, reject_duplicate_keys, string_at, u64_at};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const FINDING_CORRUPT_CHAIN: &str = "corrupt_chain";
pub const FINDING_INVALID_LINK: &str = "invalid_link";
pub const FINDING_LINK_NAME_MISMATCH: &str = "link_name_mismatch";
pub const FINDING_DANGLING_LINK: &str = "dangling_link";
pub const FINDING_PREDECESSOR_UNVERIFIED: &str = "predecessor_unverified";
pub const FINDING_LINK_TAIL_MISMATCH: &str = "link_tail_mismatch";
pub const FINDING_APPENDED_AFTER_LINK: &str = "appended_after_link";
pub const FINDING_DOUBLE_SUCCESSOR: &str = "double_successor";
pub const FINDING_UNTRUSTED_SUCCESSOR_KEY: &str = "untrusted_successor_key";

pub const LINK_TRUST_SAME_KEY: &str = "same_key";
pub const LINK_TRUST_TRUSTED_KEY: &str = "trusted_key";
pub const LINK_TRUST_ENDORSED: &str = "endorsed";

const RUN_INFIX: &str = ".run.";
const EVIDENCE_PREFIX: &str = "evidence-";
const EVIDENCE_SUFFIX: &str = ".jsonl";
const CHAIN_LINK_FILE_PREFIX: &str = "chain-link-";
const CHAIN_LINK_FILE_SUFFIX: &str = ".json";
const CHAIN_LINK_VERSION: i64 = 1;
const CHAIN_LINK_DOMAIN: &str = "pipelock-chain-link-v1\0";
const SIGNATURE_PREFIX: &str = "ed25519:";
const MAX_CHAIN_LINK_FILE_BYTES: u64 = 64 << 10;
const APPENDED_AFTER_LINK: &str = "entries were appended to the predecessor after the linked tail";

const CHAIN_LINK_FIELDS: [&str; 9] = [
    "version",
    "predecessor_session",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "linked_at",
    "signature",
];

/// A run session's signed statement that it continues exactly one earlier
/// chain of the same base. Mirrors Go's `ChainLink`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChainLink {
    pub version: i64,
    pub predecessor_session: String,
    pub predecessor_tail_seq: u64,
    pub predecessor_tail_hash: String,
    pub predecessor_signer_key: String,
    pub successor_session: String,
    pub successor_signer_key: String,
    pub linked_at: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct BaseChain {
    pub session: String,
    pub legacy: bool,
    pub receipts: usize,
    pub final_seq: u64,
    pub tail_hash: String,
    pub signer_key: String,
    pub link: Option<ChainLink>,
    pub link_file: Option<String>,
    pub link_trust: String,
    pub valid: bool,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BaseFinding {
    pub kind: String,
    pub session: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct BaseReport {
    pub base: String,
    pub chains: Vec<BaseChain>,
    pub findings: Vec<BaseFinding>,
}

impl BaseReport {
    /// True when every chain verified and every link file held. It says
    /// nothing about unlinked runs; see [`BaseReport::unlinked`].
    pub fn healthy(&self) -> bool {
        self.findings.is_empty()
    }

    /// Every chain no link file continues into. An unlinked chain is
    /// reported, never a finding: first runs, concurrent runs, and runs by
    /// older binaries are honestly unlinked, and so is a run whose link file
    /// was deleted. A healthy report is therefore not proof of continuity.
    pub fn unlinked(&self) -> Vec<String> {
        self.chains
            .iter()
            .filter(|c| c.link.is_none())
            .map(|c| c.session.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaseVerifyOptions {
    pub trusted_keys: Vec<String>,
    pub endorsements: Vec<RotationEndorsement>,
}

pub fn run_session_base(session: &str) -> Option<&str> {
    match session.find(RUN_INFIX) {
        Some(idx) if idx > 0 => Some(&session[..idx]),
        _ => None,
    }
}

fn is_base_chain(session: &str, base: &str) -> bool {
    session == base || run_session_base(session) == Some(base)
}

/// Mirrors Go `evidencename.Parse`: the session is everything between
/// `evidence-` and the LAST dash, and a sequence that is not a u64 parses
/// as 0.
pub fn parse_evidence_filename(name: &str) -> Option<(String, u64)> {
    let rest = name
        .strip_prefix(EVIDENCE_PREFIX)?
        .strip_suffix(EVIDENCE_SUFFIX)?;
    let last_dash = rest.rfind('-')?;
    let digits = &rest[last_dash + 1..];
    let seq = if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits.parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    Some((rest[..last_dash].to_string(), seq))
}

type EvidenceIndex = BTreeMap<String, Vec<PathBuf>>;

fn index_recorder_files(dir: &Path) -> Result<EvidenceIndex, String> {
    let mut shards: BTreeMap<String, Vec<(u64, String, PathBuf)>> = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|err| format!("reading evidence directory: {err}"))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("reading evidence directory: {err}"))?;
        let is_dir = entry
            .file_type()
            .map_err(|err| format!("reading evidence directory: {err}"))?
            .is_dir();
        let name = entry.file_name().to_string_lossy().to_string();
        if is_dir || !name.ends_with(EVIDENCE_SUFFIX) {
            continue;
        }
        let Some((session, seq)) = parse_evidence_filename(&name) else {
            continue;
        };
        shards
            .entry(session)
            .or_default()
            .push((seq, name, entry.path()));
    }
    Ok(shards
        .into_iter()
        .map(|(session, mut list)| {
            list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            (session, list.into_iter().map(|(_, _, path)| path).collect())
        })
        .collect())
}

/// Refuses two distinct shard names that start the same session at the same
/// sequence, as Go's `evidencename.CheckNoDuplicateSeqStart` does.
fn index_files<'a>(ix: &'a EvidenceIndex, session: &str) -> Result<&'a [PathBuf], String> {
    let files = ix.get(session).map_or(&[][..], Vec::as_slice);
    for pair in files.windows(2) {
        let prev = pair[0].file_name().map(|n| n.to_string_lossy().to_string());
        let cur = pair[1].file_name().map(|n| n.to_string_lossy().to_string());
        if let (Some(prev), Some(cur)) = (prev, cur) {
            if let (Some(p), Some(c)) = (
                parse_evidence_filename(&prev),
                parse_evidence_filename(&cur),
            ) {
                if p == c {
                    return Err(format!(
                        "ambiguous evidence shard sequence start: {prev} and {cur} both start session \"{}\" at sequence {}",
                        c.0, c.1
                    ));
                }
            }
        }
    }
    Ok(files)
}

/// Lists the legacy base session and every run session of `base` in `dir`,
/// sorted.
pub fn resolve_base_sessions(dir: &Path, base: &str) -> Result<Vec<String>, String> {
    Ok(index_recorder_files(dir)?
        .into_keys()
        .filter(|s| is_base_chain(s, base))
        .collect())
}

/// Returns one session's receipts in shard order, as the action-receipt and
/// evidence-receipt subsequences.
pub fn read_session_receipts(
    dir: &Path,
    session: &str,
) -> Result<(Vec<Receipt>, Vec<Receipt>), String> {
    let ix = index_recorder_files(dir)?;
    let mut action = Vec::new();
    let mut evidence = Vec::new();
    for file in index_files(&ix, session)? {
        let extracted = extract_typed_receipts(file).map_err(|err| err.to_string())?;
        action.extend(extracted.action);
        evidence.extend(extracted.evidence);
    }
    Ok((action, evidence))
}

fn chain_link_file_predecessor(name: &str) -> Option<&str> {
    let pred = name
        .strip_prefix(CHAIN_LINK_FILE_PREFIX)?
        .strip_suffix(CHAIN_LINK_FILE_SUFFIX)?;
    (!pred.is_empty()).then_some(pred)
}

/// Go's `unicode.IsSpace`, used by `strings.TrimSpace`.
fn is_go_space(ch: char) -> bool {
    matches!(ch, '\t'..='\r' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// Encodes a string exactly as Go's `encoding/json` does: HTML-sensitive
/// characters and U+2028/U+2029 are escaped, `\b \f \n \r \t` use their
/// short escapes (Go 1.22 and later), and other control characters use
/// `\u00XX`.
fn go_json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn chain_link_digest(l: &ChainLink) -> Vec<u8> {
    let canonical = format!(
        "{{\"version\":{},\"predecessor_session\":{},\"predecessor_tail_seq\":{},\"predecessor_tail_hash\":{},\"predecessor_signer_key\":{},\"successor_session\":{},\"successor_signer_key\":{},\"linked_at\":{}}}",
        l.version,
        go_json_string(&l.predecessor_session),
        l.predecessor_tail_seq,
        go_json_string(&l.predecessor_tail_hash),
        go_json_string(&l.predecessor_signer_key),
        go_json_string(&l.successor_session),
        go_json_string(&l.successor_signer_key),
        go_json_string(&l.linked_at),
    );
    let mut out = CHAIN_LINK_DOMAIN.as_bytes().to_vec();
    out.extend_from_slice(canonical.as_bytes());
    out
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Go folds these all-ASCII field names case-insensitively: ASCII letters
/// fold, and so do the two non-ASCII letters that fold to ASCII.
fn go_fold_key(key: &str) -> String {
    key.chars()
        .map(|ch| match ch {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// Applies the decoding rules of Go's `UnmarshalChainLink`: duplicate keys,
/// case-folded aliases, unknown fields, and trailing tokens are rejected; a
/// JSON null leaves the zero value; numbers must fit their Go type.
fn decode_chain_link(text: &str) -> Result<ChainLink, String> {
    reject_duplicate_keys(text).map_err(|err| format!("unmarshal chain link: {err}"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|err| format!("unmarshal chain link: {err}"))?;
    let empty = serde_json::Map::new();
    let obj = match &value {
        Value::Null => &empty,
        Value::Object(obj) => obj,
        _ => return Err("unmarshal chain link: not a JSON object".to_string()),
    };
    for key in obj.keys() {
        if CHAIN_LINK_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if let Some(name) = CHAIN_LINK_FIELDS
            .iter()
            .find(|name| go_fold_key(key) == **name)
        {
            return Err(format!(
                "unmarshal chain link: case-folded key: \"{key}\" aliases \"{name}\""
            ));
        }
        return Err(format!(
            "unmarshal chain link: json: unknown field \"{key}\""
        ));
    }
    let string = |field: &str| -> Result<String, String> {
        match obj.get(field) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("unmarshal chain link: {field} must be a string")),
        }
    };
    let tail_seq = match obj.get("predecessor_tail_seq") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) if n.is_u64() => n.as_u64().unwrap_or(0),
        Some(_) => {
            return Err(
                "unmarshal chain link: predecessor_tail_seq must be an unsigned integer"
                    .to_string(),
            )
        }
    };
    let version = match obj.get("version") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(-1),
        Some(_) => return Err("unmarshal chain link: version must be an integer".to_string()),
    };
    Ok(ChainLink {
        version,
        predecessor_session: string("predecessor_session")?,
        predecessor_tail_seq: tail_seq,
        predecessor_tail_hash: string("predecessor_tail_hash")?,
        predecessor_signer_key: string("predecessor_signer_key")?,
        successor_session: string("successor_session")?,
        successor_signer_key: string("successor_signer_key")?,
        linked_at: string("linked_at")?,
        signature: string("signature")?,
    })
}

/// Mirrors Go's `VerifyChainLink`: structure, then the successor-key
/// signature over the domain-separated canonical fields.
pub fn verify_chain_link(l: &ChainLink) -> Result<(), String> {
    if l.version != CHAIN_LINK_VERSION {
        return Err(format!("unsupported chain link version {}", l.version));
    }
    if l.predecessor_session.chars().all(is_go_space)
        || l.successor_session.chars().all(is_go_space)
    {
        return Err("chain link sessions must be non-empty".to_string());
    }
    if l.predecessor_session == l.successor_session {
        return Err("chain link must not name its own session as predecessor".to_string());
    }
    if !valid_lower_hex(&l.predecessor_signer_key, 32) {
        return Err("chain link predecessor_signer_key is invalid".to_string());
    }
    if !valid_lower_hex(&l.successor_signer_key, 32) {
        return Err("chain link successor_signer_key is invalid".to_string());
    }
    if !valid_lower_hex(&l.predecessor_tail_hash, 32) {
        return Err("chain link predecessor_tail_hash is invalid".to_string());
    }
    if !canonical_utc_timestamp(&l.linked_at) || l.linked_at == "0001-01-01T00:00:00Z" {
        return Err("chain link linked_at must be canonical UTC RFC3339Nano".to_string());
    }
    if l.signature.is_empty() {
        return Err("chain link signature is empty".to_string());
    }
    let sig_hex = l.signature.strip_prefix(SIGNATURE_PREFIX).ok_or_else(|| {
        format!("invalid chain link signature format: missing {SIGNATURE_PREFIX} prefix")
    })?;
    let sig = hex::decode(sig_hex)
        .ok()
        .filter(|b| b.len() == 64)
        .ok_or("invalid chain link signature")?;
    let key: [u8; 32] = hex::decode(&l.successor_signer_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid successor_signer_key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| "invalid successor_signer_key".to_string())?;
    let signature =
        Signature::from_slice(&sig).map_err(|_| "invalid chain link signature".to_string())?;
    verifying_key
        .verify_strict(&chain_link_digest(l), &signature)
        .map_err(|_| "chain link signature verification failed".to_string())
}

fn read_chain_link_file(path: &Path) -> Result<ChainLink, String> {
    let info = fs::symlink_metadata(path).map_err(|err| format!("stat chain link file: {err}"))?;
    if !info.file_type().is_file() {
        return Err("chain link file is not a regular file".to_string());
    }
    if info.len() > MAX_CHAIN_LINK_FILE_BYTES {
        return Err(format!(
            "chain link file exceeds {MAX_CHAIN_LINK_FILE_BYTES} bytes"
        ));
    }
    let bytes = read_verifier_bytes(path).map_err(|err| format!("read chain link file: {err}"))?;
    if bytes.len() as u64 > MAX_CHAIN_LINK_FILE_BYTES {
        return Err(format!(
            "chain link file exceeds {MAX_CHAIN_LINK_FILE_BYTES} bytes"
        ));
    }
    let text = String::from_utf8_lossy(&bytes);
    let link = decode_chain_link(&text)?;
    verify_chain_link(&link)?;
    Ok(link)
}

struct ChainLinkRecord {
    name: String,
    name_pred: String,
    link: Result<ChainLink, String>,
}

fn read_chain_link_files(dir: &Path) -> Result<Vec<ChainLinkRecord>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| format!("listing chain link files: {err}"))? {
        let entry = entry.map_err(|err| format!("listing chain link files: {err}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if chain_link_file_predecessor(&name).is_some() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| ChainLinkRecord {
            name_pred: chain_link_file_predecessor(&name)
                .unwrap_or_default()
                .to_string(),
            link: read_chain_link_file(&dir.join(&name)),
            name,
        })
        .collect())
}

fn chain_seq(receipt: &Receipt) -> u64 {
    u64_at(receipt, &["action_record", "chain_seq"]).unwrap_or(0)
}

fn signer_key(receipt: &Receipt) -> &str {
    string_at(receipt, &["signer_key"]).unwrap_or("")
}

/// Mirrors Go's `VerifyCrossChainEndorsement`: the endorsement must verify,
/// be signed by the link's predecessor key, name the successor key, and bind
/// the predecessor session and its exact linked tail.
pub fn verify_cross_chain_endorsement(e: &RotationEndorsement, link: &ChainLink) -> bool {
    verify_rotation_endorsement(e).is_ok()
        && e.session_id == link.predecessor_session
        && e.prior_signer_key == link.predecessor_signer_key
        && e.new_signer_key == link.successor_signer_key
        && e.prior_final_seq == link.predecessor_tail_seq
        && e.prior_tail_hash == link.predecessor_tail_hash
}

/// Returns `Ok` when `link` names the exact tail of `receipts`, or the
/// reason it does not (`APPENDED_AFTER_LINK` when it names an earlier
/// receipt).
fn check_linked_tail(receipts: &[Receipt], link: &ChainLink) -> Result<(), String> {
    let last = &receipts[receipts.len() - 1];
    let last_hash = receipt_hash(last);
    if chain_seq(last) == link.predecessor_tail_seq && last_hash == link.predecessor_tail_hash {
        if signer_key(last) != link.predecessor_signer_key {
            return Err("link predecessor key does not sign the linked tail".to_string());
        }
        return Ok(());
    }
    for r in receipts[..receipts.len() - 1].iter().rev() {
        if receipt_hash(r) == link.predecessor_tail_hash
            && chain_seq(r) == link.predecessor_tail_seq
        {
            return Err(APPENDED_AFTER_LINK.to_string());
        }
    }
    Err(format!(
        "link names tail seq {} hash {}, predecessor tail is seq {} hash {}",
        link.predecessor_tail_seq,
        link.predecessor_tail_hash,
        chain_seq(last),
        last_hash
    ))
}

struct BaseChainData {
    chain: BaseChain,
    receipts: Vec<Receipt>,
}

fn chain_acceptable(res: &ChainResult) -> bool {
    res.valid
        || (res.failure_kind.as_deref() == Some("lifecycle_missing_open") && res.integrity_verified)
}

/// Verifies every chain of `base` in `dir` and every link file that names a
/// chain of `base`, mirroring Go's `VerifyBase` (non links-only mode). An
/// error means the directory could not be enumerated; a caller must treat
/// that as incomplete, never as healthy.
pub fn verify_base(dir: &Path, base: &str, opts: &BaseVerifyOptions) -> Result<BaseReport, String> {
    let ix = index_recorder_files(dir)?;
    let sessions: Vec<String> = ix
        .keys()
        .filter(|s| is_base_chain(s, base))
        .cloned()
        .collect();
    let links = read_chain_link_files(dir)?;
    let mut findings: Vec<BaseFinding> = Vec::new();
    let mut add = |kind: &str, session: &str, detail: String| {
        findings.push(BaseFinding {
            kind: kind.to_string(),
            session: session.to_string(),
            detail,
        });
    };

    let scoped: Vec<&ChainLinkRecord> = links
        .iter()
        .filter(|lf| {
            is_base_chain(&lf.name_pred, base)
                || lf.link.as_ref().is_ok_and(|l| {
                    is_base_chain(&l.predecessor_session, base)
                        || is_base_chain(&l.successor_session, base)
                })
        })
        .collect();

    let mut data: HashMap<String, BaseChainData> = HashMap::new();
    for s in &sessions {
        let mut d = BaseChainData {
            chain: BaseChain {
                session: s.clone(),
                legacy: s == base,
                receipts: 0,
                final_seq: 0,
                tail_hash: String::new(),
                signer_key: String::new(),
                link: None,
                link_file: None,
                link_trust: String::new(),
                valid: false,
                error: String::new(),
            },
            receipts: Vec::new(),
        };
        load_base_chain(&ix, &mut d, &mut add);
        data.insert(s.clone(), d);
    }

    let mut successors: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for lf in scoped {
        let link = match &lf.link {
            Err(err) => {
                add(
                    FINDING_INVALID_LINK,
                    &lf.name_pred,
                    format!("link file {}: {err}", lf.name),
                );
                continue;
            }
            Ok(link) => link,
        };
        if link.predecessor_session != lf.name_pred {
            add(
                FINDING_LINK_NAME_MISMATCH,
                &lf.name_pred,
                format!(
                    "link file {} names predecessor \"{}\"",
                    lf.name, link.predecessor_session
                ),
            );
        }
        successors
            .entry(link.predecessor_session.clone())
            .or_default()
            .push(link.successor_session.clone());
        if !is_base_chain(&link.predecessor_session, base) {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: predecessor \"{}\" is not a chain of \"{base}\"",
                    lf.name, link.predecessor_session
                ),
            );
            continue;
        }
        if run_session_base(&link.successor_session) != Some(base) {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor is not a run chain of \"{base}\"",
                    lf.name
                ),
            );
            continue;
        }
        let Some(sd) = data.get_mut(&link.successor_session) else {
            add(
                FINDING_DANGLING_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor \"{}\" not found",
                    lf.name, link.successor_session
                ),
            );
            continue;
        };
        if let Some(existing) = &sd.chain.link {
            add(
                FINDING_INVALID_LINK,
                &link.successor_session,
                format!(
                    "link file {}: successor already continues \"{}\"",
                    lf.name, existing.predecessor_session
                ),
            );
            continue;
        }
        sd.chain.link = Some(link.clone());
        sd.chain.link_file = Some(lf.name.clone());
    }

    // An endorsement vouches for a successor key only once the chain holding
    // the endorsing key has itself verified, so chains resolve in dependency
    // order; a cycle never reaches a verified root and stays unendorsed.
    let mut endorsed: HashSet<String> = HashSet::new();
    let mut endorsable: HashSet<String> = HashSet::new();
    let mut cross_used: HashSet<usize> = HashSet::new();
    for s in &sessions {
        let Some(link) = &data[s].chain.link else {
            continue;
        };
        if link.successor_signer_key == link.predecessor_signer_key {
            continue;
        }
        if let Some(i) = opts
            .endorsements
            .iter()
            .position(|e| verify_cross_chain_endorsement(e, link))
        {
            endorsable.insert(s.clone());
            cross_used.insert(i);
        }
    }
    let verify = |s: &str,
                  is_endorsed: bool,
                  data: &mut HashMap<String, BaseChainData>,
                  add: &mut dyn FnMut(&str, &str, String)| {
        let d = data.get_mut(s).expect("session loaded");
        let own: Vec<RotationEndorsement> = opts
            .endorsements
            .iter()
            .enumerate()
            .filter(|(i, e)| {
                e.session_id == s && !cross_used.contains(i) && !binds_final_receipt(e, &d.chain)
            })
            .map(|(_, e)| e.clone())
            .collect();
        verify_base_chain(d, &opts.trusted_keys, &own, is_endorsed, add);
    };
    let mut resolved: HashSet<String> = HashSet::new();
    let mut pending: Vec<String> = sessions.clone();
    let mut progress = true;
    while progress && !pending.is_empty() {
        progress = false;
        let mut waiting = Vec::new();
        for s in &pending {
            if endorsable.contains(s) {
                let link = data[s]
                    .chain
                    .link
                    .clone()
                    .expect("endorsable chain is linked");
                let pred_session = &link.predecessor_session;
                if data.contains_key(pred_session) && !resolved.contains(pred_session) {
                    waiting.push(s.clone());
                    continue;
                }
                let ok = data.get(pred_session).is_some_and(|pred| {
                    pred.chain.valid
                        && !pred.receipts.is_empty()
                        && check_linked_tail(&pred.receipts, &link).is_ok()
                });
                if ok {
                    endorsed.insert(s.clone());
                }
            }
            verify(s, endorsed.contains(s), &mut data, &mut add);
            resolved.insert(s.clone());
            progress = true;
        }
        pending = waiting;
    }
    for s in &pending {
        verify(s, endorsed.contains(s), &mut data, &mut add);
    }

    for s in &sessions {
        check_base_link(&mut data, s, opts, endorsed.contains(s), &mut add);
    }
    for (p, succ) in &successors {
        if succ.len() > 1 {
            add(
                FINDING_DOUBLE_SUCCESSOR,
                p,
                format!(
                    "continued by {} link files: [{}]",
                    succ.len(),
                    succ.join(" ")
                ),
            );
        }
    }
    let chains = sessions
        .iter()
        .map(|s| data.remove(s).expect("session loaded").chain)
        .collect();
    Ok(BaseReport {
        base: base.to_string(),
        chains,
        findings,
    })
}

fn load_base_chain(
    ix: &EvidenceIndex,
    d: &mut BaseChainData,
    add: &mut dyn FnMut(&str, &str, String),
) {
    let s = d.chain.session.clone();
    let loaded = index_files(ix, &s).and_then(|files| {
        let mut receipts = Vec::new();
        for file in files {
            receipts.extend(
                extract_typed_receipts(file)
                    .map_err(|err| err.to_string())?
                    .action,
            );
        }
        Ok(receipts)
    });
    match loaded {
        Err(err) => {
            d.chain.error = err.clone();
            add(FINDING_CORRUPT_CHAIN, &s, err);
        }
        Ok(receipts) => {
            d.receipts = receipts;
            let Some(last) = d.receipts.last() else {
                d.chain.valid = true;
                return;
            };
            d.chain.receipts = d.receipts.len();
            d.chain.signer_key = signer_key(&d.receipts[0]).to_string();
            d.chain.final_seq = chain_seq(last);
            d.chain.tail_hash = receipt_hash(last);
        }
    }
}

fn verify_base_chain(
    d: &mut BaseChainData,
    trusted: &[String],
    own: &[RotationEndorsement],
    is_endorsed: bool,
    add: &mut dyn FnMut(&str, &str, String),
) {
    if !d.chain.error.is_empty() || d.receipts.is_empty() {
        return;
    }
    let mut keys = trusted.to_vec();
    if is_endorsed && !trusted.is_empty() {
        if let Some(link) = &d.chain.link {
            keys.push(link.successor_signer_key.clone());
        }
    }
    let joined = keys.join(",");
    let res = if own.is_empty() {
        verify_chain_with_options(&d.receipts, &joined, keys.is_empty())
    } else {
        verify_chain_with_endorsements(&d.receipts, &d.chain.session, own, &joined)
    };
    if !chain_acceptable(&res) {
        d.chain.valid = false;
        d.chain.error = res
            .error
            .unwrap_or_else(|| "chain verification failed".to_string());
        add(
            FINDING_CORRUPT_CHAIN,
            &d.chain.session,
            d.chain.error.clone(),
        );
        return;
    }
    d.chain.valid = true;
}

fn check_base_link(
    data: &mut HashMap<String, BaseChainData>,
    s: &str,
    opts: &BaseVerifyOptions,
    is_endorsed: bool,
    add: &mut dyn FnMut(&str, &str, String),
) {
    let Some(link) = data[s].chain.link.clone() else {
        return;
    };
    if let Some(first) = data[s].receipts.first() {
        if signer_key(first) != link.successor_signer_key {
            add(
                FINDING_INVALID_LINK,
                s,
                "link successor key does not sign the chain".to_string(),
            );
        }
    }
    let Some(pred) = data.get(&link.predecessor_session) else {
        add(
            FINDING_DANGLING_LINK,
            s,
            format!("predecessor \"{}\" not found", link.predecessor_session),
        );
        return;
    };
    if !pred.chain.valid || pred.receipts.is_empty() {
        add(
            FINDING_PREDECESSOR_UNVERIFIED,
            s,
            format!(
                "predecessor \"{}\" did not verify",
                link.predecessor_session
            ),
        );
        return;
    }
    if let Err(err) = check_linked_tail(&pred.receipts, &link) {
        let kind = if err == APPENDED_AFTER_LINK {
            FINDING_APPENDED_AFTER_LINK
        } else {
            FINDING_LINK_TAIL_MISMATCH
        };
        add(
            kind,
            &link.predecessor_session,
            format!("linked by {s}: {err}"),
        );
    }
    let trust = if link.successor_signer_key == link.predecessor_signer_key {
        LINK_TRUST_SAME_KEY
    } else if opts.trusted_keys.contains(&link.successor_signer_key) {
        LINK_TRUST_TRUSTED_KEY
    } else if is_endorsed {
        LINK_TRUST_ENDORSED
    } else {
        add(
            FINDING_UNTRUSTED_SUCCESSOR_KEY,
            s,
            "successor key differs from predecessor key and is neither trusted nor endorsed"
                .to_string(),
        );
        ""
    };
    if let Some(d) = data.get_mut(s) {
        d.chain.link_trust = trust.to_string();
    }
}

/// True when `e` hands off from `c`'s last receipt, which only a
/// cross-chain endorsement does.
fn binds_final_receipt(e: &RotationEndorsement, c: &BaseChain) -> bool {
    !c.tail_hash.is_empty() && e.prior_final_seq == c.final_seq && e.prior_tail_hash == c.tail_hash
}

/// Narrows the operator's endorsements and keys to one chain, as Go's
/// verify-receipt does: an endorsement that authorizes a key change across a
/// link is placed by the link check, never handed to either chain.
pub fn chain_scoped_trust(
    report: &BaseReport,
    session: &str,
    trusted_keys: &[String],
    endorsements: &[RotationEndorsement],
) -> (Vec<String>, Vec<RotationEndorsement>) {
    let own = endorsements
        .iter()
        .filter(|e| {
            e.session_id == session
                && !report.chains.iter().any(|c| {
                    c.link
                        .as_ref()
                        .is_some_and(|l| verify_cross_chain_endorsement(e, l))
                })
        })
        .cloned()
        .collect();
    let mut keys = trusted_keys.to_vec();
    for c in &report.chains {
        if c.session == session && c.link_trust == LINK_TRUST_ENDORSED {
            if let Some(link) = &c.link {
                keys = trusted_keys.to_vec();
                keys.push(link.successor_signer_key.clone());
            }
        }
    }
    (keys, own)
}

#[cfg(test)]
mod go_json_escape_tests {
    use super::{decode_chain_link, go_json_string, verify_chain_link};
    use std::path::PathBuf;

    // Written by the Go conformance test from encoding/json itself, so this
    // holds the link encoder to Go's bytes rather than to a recollection.
    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/testdata/go-json-escapes")
            .join(name);
        std::fs::read_to_string(path).expect("read fixture")
    }

    #[test]
    fn link_encoder_writes_every_ascii_character_and_line_separators_as_go_does() {
        let table: serde_json::Value = serde_json::from_str(&fixture("table.json")).expect("parse");
        let entries = table["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 130);
        for entry in entries {
            let cp = entry["codepoint"].as_str().expect("codepoint");
            let ch = char::from_u32(u32::from_str_radix(cp, 16).expect("hex")).expect("char");
            let got = hex::encode(go_json_string(&ch.to_string()));
            assert_eq!(got, entry["go_json_hex"].as_str().expect("hex"), "U+{cp}");
        }
    }

    #[test]
    fn a_go_signed_chain_link_whose_sessions_need_every_escape_verifies() {
        let raw = fixture("chain-link.json");
        verify_chain_link(&decode_chain_link(&raw).expect("decode")).expect("verify");
        let changed = raw.replacen(r"proxy.run.b\b\f", r"proxy.run.b\b", 1);
        assert_ne!(changed, raw, "fixture shape changed");
        let edited = decode_chain_link(&changed).expect("decode edited");
        assert!(verify_chain_link(&edited).is_err());
    }
}

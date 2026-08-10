// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::aarp::envelope::validate_timestamp;
use crate::canonical::go_json_bytes;
use crate::chain::{receipt_hash, verify_chain};
use crate::types::{ChainResult, Receipt};
use crate::util::{decode_hex, Result, VerifierError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const ENDORSEMENT_VERSION: u64 = 1;
const ENDORSEMENT_DOMAIN: &[u8] = b"pipelock-rotation-endorsement-v1\0";
const SIGNATURE_PREFIX: &str = "ed25519:";
const MAX_ENDORSEMENT_BYTES: u64 = 64 << 10;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationEndorsement {
    pub version: u64,
    pub session_id: String,
    pub prior_signer_key: String,
    pub prior_final_seq: u64,
    pub prior_tail_hash: String,
    pub new_signer_key: String,
    pub rotated_at: String,
    pub endorsement: String,
}

#[derive(Serialize)]
struct CanonicalRotationEndorsement<'a> {
    version: u64,
    session_id: &'a str,
    prior_signer_key: &'a str,
    prior_final_seq: u64,
    prior_tail_hash: &'a str,
    new_signer_key: &'a str,
    rotated_at: &'a str,
}

fn invalid(message: impl Into<String>) -> VerifierError {
    VerifierError::Invalid(message.into())
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value.chars().all(|ch| ch.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

fn canonical_utc_timestamp(value: &str) -> bool {
    if !value.ends_with('Z') || validate_timestamp(value, "rotated_at").is_err() {
        return false;
    }
    let bytes = value.as_bytes();
    let parse_pair = |start: usize| {
        std::str::from_utf8(&bytes[start..start + 2])
            .ok()
            .and_then(|part| part.parse::<u8>().ok())
    };
    let year = std::str::from_utf8(&bytes[0..4])
        .ok()
        .and_then(|part| part.parse::<u16>().ok());
    let Some((year, month, day, hour, minute, second)) = year
        .zip(parse_pair(5))
        .zip(parse_pair(8))
        .zip(parse_pair(11))
        .zip(parse_pair(14))
        .zip(parse_pair(17))
        .map(|(((((year, month), day), hour), minute), second)| {
            (year, month, day, hour, minute, second)
        })
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day == 0
        || day > days[usize::from(month - 1)]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }
    let Some(time) = value.split('T').nth(1) else {
        return false;
    };
    let Some(clock) = time.strip_suffix('Z') else {
        return false;
    };
    let Some((_, fraction)) = clock.split_once('.') else {
        return true;
    };
    !fraction.is_empty()
        && fraction.len() <= 9
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && !fraction.ends_with('0')
}

fn endorsement_digest(endorsement: &RotationEndorsement) -> Result<[u8; 32]> {
    let canonical = CanonicalRotationEndorsement {
        version: endorsement.version,
        session_id: &endorsement.session_id,
        prior_signer_key: &endorsement.prior_signer_key,
        prior_final_seq: endorsement.prior_final_seq,
        prior_tail_hash: &endorsement.prior_tail_hash,
        new_signer_key: &endorsement.new_signer_key,
        rotated_at: &endorsement.rotated_at,
    };
    let encoded = go_json_bytes(&canonical)
        .map_err(|err| invalid(format!("marshal rotation endorsement: {err}")))?;
    let mut hasher = Sha256::new();
    hasher.update(ENDORSEMENT_DOMAIN);
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

pub fn verify_rotation_endorsement(endorsement: &RotationEndorsement) -> Result<()> {
    if endorsement.version != ENDORSEMENT_VERSION {
        return Err(invalid(format!(
            "unsupported rotation endorsement version {}",
            endorsement.version
        )));
    }
    if endorsement.session_id.trim().is_empty() {
        return Err(invalid("rotation endorsement session_id is empty"));
    }
    if !valid_lower_hex(&endorsement.prior_signer_key, 32) {
        return Err(invalid("rotation endorsement prior_signer_key is invalid"));
    }
    if !valid_lower_hex(&endorsement.new_signer_key, 32) {
        return Err(invalid("rotation endorsement new_signer_key is invalid"));
    }
    if endorsement.prior_signer_key == endorsement.new_signer_key {
        return Err(invalid(
            "rotation endorsement successor key must differ from prior key",
        ));
    }
    if !valid_lower_hex(&endorsement.prior_tail_hash, 32) {
        return Err(invalid("rotation endorsement prior_tail_hash is invalid"));
    }
    if !canonical_utc_timestamp(&endorsement.rotated_at) {
        return Err(invalid(
            "rotation endorsement rotated_at must be canonical UTC RFC3339Nano",
        ));
    }
    let signature_hex = endorsement
        .endorsement
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or_else(|| {
            invalid(format!(
                "invalid endorsement signature format: missing {SIGNATURE_PREFIX} prefix"
            ))
        })?;
    let public_bytes =
        decode_hex(&endorsement.prior_signer_key, 32, "prior_signer_key").map_err(invalid)?;
    let signature_bytes = decode_hex(signature_hex, 64, "endorsement").map_err(invalid)?;
    let public_array: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| invalid("invalid prior_signer_key"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_array).map_err(|err| invalid(err.to_string()))?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|err| invalid(err.to_string()))?;
    verifying_key
        .verify_strict(&endorsement_digest(endorsement)?, &signature)
        .map_err(|_| invalid("rotation endorsement signature verification failed"))
}

fn open_rotation_endorsement(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

pub fn load_rotation_endorsement_file(path: &Path) -> Result<RotationEndorsement> {
    let file = open_rotation_endorsement(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|err| VerifierError::Runtime(format!("stat {}: {err}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(invalid("rotation endorsement must be a regular file"));
    }
    let mut reader = file.take(MAX_ENDORSEMENT_BYTES + 1);
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    if data.len() as u64 > MAX_ENDORSEMENT_BYTES {
        return Err(invalid(format!(
            "rotation endorsement exceeds {MAX_ENDORSEMENT_BYTES} bytes"
        )));
    }
    let endorsement: RotationEndorsement = serde_json::from_slice(&data)
        .map_err(|err| invalid(format!("unmarshal rotation endorsement: {err}")))?;
    verify_rotation_endorsement(&endorsement)?;
    Ok(endorsement)
}

fn fail(mut base: ChainResult, message: impl Into<String>) -> ChainResult {
    base.valid = false;
    base.failure_kind = None;
    base.error = Some(message.into());
    base
}

fn session_open(receipt: &Receipt) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let control = receipt.get("action_record")?.get("session_control")?;
    if control.get("kind")?.as_str()? != "session_open" {
        return None;
    }
    control.get("open")?.as_object()
}

fn signed_recorder_session_error(session_id: &str, receipts: &[Receipt]) -> Option<String> {
    let first_boundary = receipts
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, receipt)| {
            receipt
                .get("action_record")
                .and_then(|record| record.get("key_transition"))
                .is_some()
        })
        .map_or(receipts.len(), |(index, _)| index);
    let mut root_open_found = false;
    for (index, receipt) in receipts.iter().enumerate() {
        let Some(open) = session_open(receipt) else {
            continue;
        };
        let recorder_session = open
            .get("recorder_session")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if recorder_session != session_id {
            return Some(format!(
                "signed recorder session {recorder_session:?} does not match endorsement session {session_id:?}"
            ));
        }
        if index < first_boundary {
            root_open_found = true;
        }
    }
    (!root_open_found)
        .then(|| "root receipt segment has no signed session_open recorder binding".to_string())
}

pub fn verify_chain_with_endorsements(
    receipts: &[Receipt],
    session_id: &str,
    endorsements: &[RotationEndorsement],
    root_key_hex: &str,
) -> ChainResult {
    if session_id.trim().is_empty() {
        return ChainResult {
            valid: false,
            integrity_verified: false,
            failure_kind: None,
            receipt_count: receipts.len(),
            final_seq: 0,
            root_hash: String::new(),
            error: Some(
                "rotation endorsement verification requires a recorder session ID".to_string(),
            ),
            broken_at_seq: None,
        };
    }
    if receipts.is_empty() {
        return ChainResult {
            valid: false,
            integrity_verified: false,
            failure_kind: None,
            receipt_count: 0,
            final_seq: 0,
            root_hash: String::new(),
            error: Some(if endorsements.is_empty() {
                "empty chain".to_string()
            } else {
                "rotation endorsements supplied for an empty receipt chain".to_string()
            }),
            broken_at_seq: None,
        };
    }
    let mut authorized_signer = receipts[0]
        .get("signer_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    for receipt in &receipts[1..] {
        let signer = receipt
            .get("signer_key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let transition = receipt
            .get("action_record")
            .and_then(|record| record.get("key_transition"))
            .is_some();
        if !transition && signer != authorized_signer {
            return ChainResult {
                valid: false,
                integrity_verified: false,
                failure_kind: None,
                receipt_count: receipts.len(),
                final_seq: 0,
                root_hash: String::new(),
                error: Some("signer key changed without a key_transition boundary".to_string()),
                broken_at_seq: None,
            };
        }
        if transition {
            authorized_signer = signer;
        }
    }
    let all_keys = receipts
        .iter()
        .filter_map(|receipt| receipt.get("signer_key")?.as_str())
        .map(str::to_ascii_lowercase)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    let base = verify_chain(receipts, &all_keys);
    let lifecycle_only_failure = !base.valid
        && base.integrity_verified
        && base.failure_kind.as_deref() == Some("lifecycle_missing_open");
    if !base.valid && !lifecycle_only_failure {
        return base;
    }
    let roots = root_key_hex
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<HashSet<_>>();
    if roots.is_empty() {
        return fail(
            base,
            "rotation endorsement verification requires at least one trusted root key",
        );
    }
    let first_key = receipts[0]
        .get("signer_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !roots.contains(&first_key) {
        return fail(base, "genesis signer key is not in the trusted root set");
    }
    if let Some(error) = signed_recorder_session_error(session_id, receipts) {
        return fail(base, error);
    }
    for endorsement in endorsements {
        if let Err(err) = verify_rotation_endorsement(endorsement) {
            return fail(base, err.to_string());
        }
    }

    let mut used = HashSet::new();
    for index in 1..receipts.len() {
        let boundary = &receipts[index];
        if boundary
            .get("action_record")
            .and_then(|record| record.get("key_transition"))
            .is_none()
        {
            continue;
        }
        let prior = &receipts[index - 1];
        let successor = boundary
            .get("signer_key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let prior_key = prior
            .get("signer_key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let prior_seq = prior
            .get("action_record")
            .and_then(|record| record.get("chain_seq"))
            .and_then(serde_json::Value::as_u64);
        let prior_hash = receipt_hash(prior);
        let matches = endorsements
            .iter()
            .enumerate()
            .filter(|(endorsement_index, endorsement)| {
                !used.contains(endorsement_index)
                    && endorsement.session_id == session_id
                    && endorsement.prior_signer_key == prior_key
                    && Some(endorsement.prior_final_seq) == prior_seq
                    && endorsement.prior_tail_hash == prior_hash
                    && endorsement.new_signer_key == successor
            })
            .map(|(endorsement_index, _)| endorsement_index)
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return fail(
                base,
                "multiple rotation endorsements match one receipt boundary",
            );
        }
        let Some(endorsement_index) = matches.first() else {
            return fail(base, "rotation endorsement does not match receipt boundary");
        };
        used.insert(*endorsement_index);
    }
    if used.len() != endorsements.len() {
        return fail(
            base,
            "unused rotation endorsement does not match a required boundary",
        );
    }
    base
}

use crate::canonical::{canonicalize_jcs_value, canonicalize_receipt};
use crate::signing::{
    normalize_evidence_receipt, verify_receipt, verify_receipt_with_options,
    UNPINNED_RECEIPT_BANNER,
};
use crate::types::{ChainResult, Receipt, Totals};
use crate::util::sha256_hex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const GENESIS_HASH: &str = "genesis";
pub const GENESIS_SESSION_OPEN_PREFIX: &str = "g1:";
const SESSION_OPEN_GENESIS_LABEL: &str = "pipelock.receipt.session_open.v1";
const EVIDENCE_RECORD_TYPE: &str = "evidence_receipt_v2";

pub fn receipt_hash(receipt: &Receipt) -> String {
    if receipt
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        == Some(EVIDENCE_RECORD_TYPE)
    {
        return sha256_hex(
            &canonicalize_jcs_value(receipt).expect("validated evidence receipt canonicalizes"),
        );
    }
    sha256_hex(&canonicalize_receipt(receipt))
}

/// Verify receipt ordering, signatures, and prev-hash linkage.
///
/// When expected_key_hex is empty, the first receipt's signer_key pins the chain key.
/// Callers that require external trust must pass a non-empty expected key.
pub fn verify_chain(receipts: &[Receipt], expected_key_hex: &str) -> ChainResult {
    verify_chain_with_options(receipts, expected_key_hex, false)
}

pub fn verify_chain_with_options(
    receipts: &[Receipt],
    expected_key_hex: &str,
    allow_unpinned: bool,
) -> ChainResult {
    if receipts.is_empty() {
        return ChainResult {
            valid: true,
            receipt_count: 0,
            final_seq: 0,
            root_hash: String::new(),
            error: None,
            broken_at_seq: None,
        };
    }

    if receipts[0]
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        == Some(EVIDENCE_RECORD_TYPE)
    {
        return verify_evidence_chain(receipts, expected_key_hex, allow_unpinned);
    }

    let trusted_keys = parse_trusted_keys(expected_key_hex);
    if trusted_keys.is_empty() && !allow_unpinned {
        return broken(0, UNPINNED_RECEIPT_BANNER.to_string());
    }

    let first_key = receipts[0]
        .get("signer_key")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !trusted_keys.is_empty() && !trusted_keys.contains(&first_key) {
        return broken(
            0,
            format!("signer key {first_key} is not in the trusted set"),
        );
    }

    let mut state = ChainWalkState {
        cur_key: first_key,
        segment_start_index: 0,
        segment_base_seq: 0,
        segment_receipt_count: 0,
        prev_hash: String::new(),
        prior_segment_seq: None,
        active_run_nonce: None,
        active_open_nonce: None,
        opened_runs: HashSet::new(),
        closed_runs: HashSet::new(),
    };
    if state.cur_key.is_empty() && allow_unpinned {
        state.cur_key = receipts[0]
            .get("signer_key")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
    }

    for (index, receipt) in receipts.iter().enumerate() {
        let Some(seq) = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_seq"))
            .and_then(|value| value.as_u64())
        else {
            return broken(
                index as u64,
                format!("seq {index}: missing or invalid chain_seq"),
            );
        };
        let chain_prev_hash = receipt
            .get("action_record")
            .and_then(|record| record.get("chain_prev_hash"))
            .and_then(|value| value.as_str());
        if index == 0 {
            if receipt
                .get("action_record")
                .and_then(|record| record.get("key_transition"))
                .is_some()
            {
                return broken(
                    seq,
                    format!("seq {seq}: chain starts at a key_transition segment without the prior segment"),
                );
            }
            if let Some(result) = validate_action_genesis(receipt, chain_prev_hash, seq) {
                return result;
            }
            state.segment_base_seq = seq;
        } else if let Some(marker) = receipt
            .get("action_record")
            .and_then(|record| record.get("key_transition"))
        {
            if let Some(result) = state.start_rotated_segment(RotationContext {
                receipt,
                marker,
                seq,
                index,
                chain_prev_hash,
                trusted_keys: &trusted_keys,
                allow_unpinned,
            }) {
                return result;
            }
        } else {
            if seq == 0 {
                return broken(
                    seq,
                    format!("seq {seq}: unexpected seq 0 without a key_transition boundary"),
                );
            }
            let expected_seq = state.segment_base_seq + (index - state.segment_start_index) as u64;
            if seq != expected_seq {
                return broken(seq, format!("seq gap: expected {expected_seq}, got {seq}"));
            }
            if chain_prev_hash != Some(state.prev_hash.as_str()) {
                return broken(seq, format!("seq {seq}: chain_prev_hash mismatch"));
            }
        }
        if let Err(err) = verify_receipt_with_options(receipt, &state.cur_key, allow_unpinned) {
            return broken(seq, format!("seq {seq}: signature: {err}"));
        }
        let expected_seq = state.segment_base_seq + (index - state.segment_start_index) as u64;
        if seq != expected_seq {
            return broken(seq, format!("seq gap: expected {expected_seq}, got {seq}"));
        }
        state.segment_receipt_count += 1;
        if let Some(result) = validate_closed_run(receipt, seq, &state) {
            return result;
        }
        if let Some(result) = validate_session_control_state(receipt, seq, index as u64, &mut state)
        {
            return result;
        }
        if let Some(open) = session_open(receipt) {
            state.active_run_nonce = open
                .get("run_nonce")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            state.active_open_nonce = open
                .get("open_nonce")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            if let Some(run_nonce) = state.active_run_nonce.clone() {
                state.opened_runs.insert(run_nonce.clone());
                state.closed_runs.remove(&run_nonce);
            }
        } else if session_close(receipt).is_some() {
            if let Some(run_nonce) = state.active_run_nonce.clone() {
                state.closed_runs.insert(run_nonce);
            }
            state.active_run_nonce = None;
            state.active_open_nonce = None;
        }
        state.prev_hash = receipt_hash(receipt);
        state.prior_segment_seq = Some(seq);
    }

    ChainResult {
        valid: true,
        receipt_count: receipts.len(),
        final_seq: receipts
            .last()
            .and_then(|receipt| receipt.get("action_record"))
            .and_then(|record| record.get("chain_seq"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        root_hash: state.prev_hash,
        error: None,
        broken_at_seq: None,
    }
}

pub fn compute_session_open_genesis(open: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    fn frame(h: &mut Sha256, data: &[u8]) {
        h.update((data.len() as u64).to_be_bytes());
        h.update(data);
    }
    fn text_field<'a>(open: &'a serde_json::Value, name: &str) -> &'a [u8] {
        open.get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .as_bytes()
    }

    frame(&mut h, SESSION_OPEN_GENESIS_LABEL.as_bytes());
    frame(&mut h, text_field(open, "run_nonce"));
    frame(&mut h, text_field(open, "open_nonce"));
    frame(&mut h, text_field(open, "recorder_session"));
    frame(&mut h, text_field(open, "policy_hash"));
    frame(&mut h, text_field(open, "signer_key_epoch"));
    let hb_secs = open
        .get("heartbeat_seconds")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        .max(0) as u64;
    frame(&mut h, &hb_secs.to_be_bytes());
    frame(&mut h, text_field(open, "genesis_anchor_head"));
    frame(&mut h, text_field(open, "genesis_anchor_log"));
    frame(&mut h, text_field(open, "posture_capsule_sha256"));
    frame(&mut h, text_field(open, "containment_nonce"));
    frame(&mut h, text_field(open, "contained_uid"));

    format!("{GENESIS_SESSION_OPEN_PREFIX}{}", hex::encode(h.finalize()))
}

fn validate_action_genesis(
    receipt: &Receipt,
    chain_prev_hash: Option<&str>,
    seq: u64,
) -> Option<ChainResult> {
    let open = session_open(receipt);
    let Some(chain_prev_hash) = chain_prev_hash else {
        return Some(broken(seq, format!("seq {seq}: chain_prev_hash mismatch")));
    };
    if chain_prev_hash.starts_with(GENESIS_SESSION_OPEN_PREFIX) {
        let Some(open) = open else {
            return Some(broken(
                seq,
                format!("seq {seq}: g1 chain_prev_hash requires session_control.open"),
            ));
        };
        if seq != 0 {
            return Some(broken(
                seq,
                format!("seq {seq}: bound session_open genesis must be chain_seq 0"),
            ));
        }
        let computed = compute_session_open_genesis(open);
        if chain_prev_hash != computed {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open genesis hash mismatch"),
            ));
        }
        if open
            .get("genesis_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            != computed
        {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open genesis_hash mismatch"),
            ));
        }
        if open
            .get("chain_open_seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            != seq
        {
            return Some(broken(
                seq,
                format!("seq {seq}: session_open chain_open_seq does not match receipt chain_seq"),
            ));
        }
        if !open
            .get("prior_chain_head")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .is_empty()
            || open
                .get("prior_chain_seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                != 0
        {
            return Some(broken(
                seq,
                format!("seq {seq}: bound genesis session_open must not carry prior chain tail"),
            ));
        }
        return None;
    }
    if chain_prev_hash != GENESIS_HASH {
        return Some(broken(
            seq,
            format!(
                "seq {seq}: genesis receipt chain_prev_hash must be genesis or a bound session_open g1 hash"
            ),
        ));
    }
    if open.is_some() {
        return Some(broken(
            seq,
            format!("seq {seq}: session_open on legacy genesis must use bound g1 chain_prev_hash"),
        ));
    }
    None
}

fn session_open(receipt: &Receipt) -> Option<&serde_json::Value> {
    let ctrl = receipt.get("action_record")?.get("session_control")?;
    if ctrl.get("kind").and_then(serde_json::Value::as_str) != Some("session_open") {
        return None;
    }
    ctrl.get("open").filter(|open| open.is_object())
}

fn session_close(receipt: &Receipt) -> Option<&serde_json::Value> {
    let ctrl = receipt.get("action_record")?.get("session_control")?;
    if ctrl.get("kind").and_then(serde_json::Value::as_str) != Some("session_close") {
        return None;
    }
    ctrl.get("close").filter(|close| close.is_object())
}

fn parse_trusted_keys(expected_key_hex: &str) -> HashSet<String> {
    expected_key_hex
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn validate_closed_run(receipt: &Receipt, seq: u64, state: &ChainWalkState) -> Option<ChainResult> {
    if session_open(receipt).is_some() {
        return None;
    }
    let run_nonce = receipt
        .get("action_record")
        .and_then(|record| record.get("run_nonce"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if run_nonce.is_empty() {
        return None;
    }
    if !state.opened_runs.contains(run_nonce) {
        return Some(broken(
            seq,
            format!("seq {seq}: run_nonce first receipt is not a matching session_open"),
        ));
    }
    if state.closed_runs.contains(run_nonce) {
        return Some(broken(
            seq,
            format!("seq {seq}: record observed after session_close"),
        ));
    }
    None
}

struct ChainWalkState {
    cur_key: String,
    segment_start_index: usize,
    segment_base_seq: u64,
    segment_receipt_count: u64,
    prev_hash: String,
    prior_segment_seq: Option<u64>,
    active_run_nonce: Option<String>,
    active_open_nonce: Option<String>,
    opened_runs: HashSet<String>,
    closed_runs: HashSet<String>,
}

struct RotationContext<'a> {
    receipt: &'a Receipt,
    marker: &'a serde_json::Value,
    seq: u64,
    index: usize,
    chain_prev_hash: Option<&'a str>,
    trusted_keys: &'a HashSet<String>,
    allow_unpinned: bool,
}

impl ChainWalkState {
    fn start_rotated_segment(&mut self, ctx: RotationContext<'_>) -> Option<ChainResult> {
        let receipt = ctx.receipt;
        let marker = ctx.marker;
        let seq = ctx.seq;
        if seq != 0 {
            return Some(broken(
                seq,
                format!("seq {seq}: key_transition marker on a non-genesis receipt (seq != 0)"),
            ));
        }
        if marker
            .get("prior_chain_hash")
            .and_then(serde_json::Value::as_str)
            != Some(self.prev_hash.as_str())
        {
            return Some(broken(
				seq,
				format!("seq {seq}: key_transition prior_chain_hash does not match actual prior tail hash"),
			));
        }
        if ctx.chain_prev_hash != Some(self.prev_hash.as_str()) {
            return Some(broken(
                seq,
                format!(
                    "seq {seq}: segment-genesis chain_prev_hash does not match prior tail hash"
                ),
            ));
        }
        if marker
            .get("prior_signer_key")
            .and_then(serde_json::Value::as_str)
            != Some(self.cur_key.as_str())
        {
            return Some(broken(
                seq,
                format!(
                    "seq {seq}: key_transition prior_signer_key does not match prior segment key"
                ),
            ));
        }
        if marker
            .get("prior_chain_seq")
            .and_then(serde_json::Value::as_u64)
            != self.prior_segment_seq
        {
            return Some(broken(
				seq,
				format!("seq {seq}: key_transition prior_chain_seq does not match prior segment final seq"),
			));
        }
        let signer_key = receipt
            .get("signer_key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if ctx.trusted_keys.is_empty() {
            if !ctx.allow_unpinned || signer_key != self.cur_key {
                return Some(broken(
                    seq,
                    format!("seq {seq}: signer key {signer_key} is not in the trusted set"),
                ));
            }
        } else if !ctx.trusted_keys.contains(&signer_key) {
            return Some(broken(
                seq,
                format!("seq {seq}: signer key {signer_key} is not in the trusted set"),
            ));
        }
        self.cur_key = signer_key;
        self.segment_start_index = ctx.index;
        self.segment_base_seq = 0;
        self.segment_receipt_count = 0;
        None
    }
}

fn validate_session_control_state(
    receipt: &Receipt,
    seq: u64,
    index: u64,
    state: &mut ChainWalkState,
) -> Option<ChainResult> {
    let ctrl = receipt.get("action_record")?.get("session_control")?;
    let kind = ctrl.get("kind").and_then(serde_json::Value::as_str);
    // Count non-null payloads, matching the authoritative Go verifier (which
    // counts non-nil pointer fields) and the TS/Python verifiers. An explicit
    // JSON `null` payload is treated as absent, not present, so all four
    // verifiers agree on `payloads != 1` for any input, not just Go-emitted
    // receipts (Go's omitempty means it never serializes a null payload).
    let payload_count = ["open", "heartbeat", "close"]
        .iter()
        .filter(|name| ctrl.get(*name).is_some_and(|value| !value.is_null()))
        .count();
    if payload_count != 1 {
        return Some(broken(
            seq,
            format!("seq {seq}: session_control must carry exactly one payload"),
        ));
    }
    let action_run_nonce = receipt
        .get("action_record")
        .and_then(|record| record.get("run_nonce"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if action_run_nonce.is_empty() {
        return Some(broken(
            seq,
            format!("seq {seq}: session_control receipt missing run_nonce"),
        ));
    }
    let control_run_nonce = match kind {
        Some("session_open") => ctrl
            .get("open")
            .and_then(|payload| payload.get("run_nonce"))
            .and_then(serde_json::Value::as_str),
        Some("heartbeat") => ctrl
            .get("heartbeat")
            .and_then(|payload| payload.get("run_nonce"))
            .and_then(serde_json::Value::as_str),
        Some("session_close") => ctrl
            .get("close")
            .and_then(|payload| payload.get("run_nonce"))
            .and_then(serde_json::Value::as_str),
        _ => None,
    };
    if control_run_nonce != Some(action_run_nonce) {
        return Some(broken(
            seq,
            format!("seq {seq}: session_control run_nonce mismatch"),
        ));
    }
    match kind {
        Some("session_open") if index > 0 => {
            let open = ctrl.get("open")?;
            let run_nonce = open
                .get("run_nonce")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if state.opened_runs.contains(run_nonce) {
                return Some(broken(
                    seq,
                    format!("seq {seq}: duplicate session_open for run_nonce"),
                ));
            }
            if open
                .get("chain_open_seq")
                .and_then(serde_json::Value::as_u64)
                != Some(seq)
            {
                return Some(broken(
                    seq,
                    format!(
                        "seq {seq}: session_open chain_open_seq does not match receipt chain_seq"
                    ),
                ));
            }
            if open
                .get("prior_chain_head")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                != state.prev_hash
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_open prior_chain_head does not match chain tail"),
                ));
            }
            if open
                .get("prior_chain_seq")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                != state.prior_segment_seq.unwrap_or(0)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_open prior_chain_seq does not match previous seq"),
                ));
            }
        }
        Some("heartbeat") => {
            let heartbeat = ctrl.get("heartbeat")?;
            let Some(active_run_nonce) = state.active_run_nonce.as_deref() else {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat has no active session_open"),
                ));
            };
            let Some(active_open_nonce) = state.active_open_nonce.as_deref() else {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat has no active session_open"),
                ));
            };
            if heartbeat
                .get("run_nonce")
                .and_then(serde_json::Value::as_str)
                != Some(active_run_nonce)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat run_nonce mismatch"),
                ));
            }
            if heartbeat
                .get("open_nonce")
                .and_then(serde_json::Value::as_str)
                != Some(active_open_nonce)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat open_nonce mismatch"),
                ));
            }
            if heartbeat
                .get("chain_head")
                .and_then(serde_json::Value::as_str)
                != Some(state.prev_hash.as_str())
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat chain_head mismatch"),
                ));
            }
            if heartbeat
                .get("chain_seq_head")
                .and_then(serde_json::Value::as_u64)
                != Some(seq - 1)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: heartbeat chain_seq_head mismatch"),
                ));
            }
        }
        Some("session_close") => {
            let close = ctrl.get("close")?;
            let Some(active_run_nonce) = state.active_run_nonce.as_deref() else {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close has no active session_open"),
                ));
            };
            let Some(active_open_nonce) = state.active_open_nonce.as_deref() else {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close has no active session_open"),
                ));
            };
            if close.get("run_nonce").and_then(serde_json::Value::as_str) != Some(active_run_nonce)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close run_nonce mismatch"),
                ));
            }
            if close.get("open_nonce").and_then(serde_json::Value::as_str)
                != Some(active_open_nonce)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close open_nonce mismatch"),
                ));
            }
            if close.get("root_hash").and_then(serde_json::Value::as_str)
                != Some(state.prev_hash.as_str())
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close root_hash mismatch"),
                ));
            }
            if close.get("final_seq").and_then(serde_json::Value::as_u64) != Some(seq) {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close final_seq mismatch"),
                ));
            }
            if close
                .get("receipt_count")
                .and_then(serde_json::Value::as_u64)
                != Some(state.segment_receipt_count)
            {
                return Some(broken(
                    seq,
                    format!("seq {seq}: session_close receipt_count mismatch"),
                ));
            }
        }
        _ => {}
    }
    None
}

fn verify_evidence_chain(
    receipts: &[Receipt],
    expected_key_hex: &str,
    allow_unpinned: bool,
) -> ChainResult {
    let key_hex = expected_key_hex.to_ascii_lowercase();
    if key_hex.is_empty() && !allow_unpinned {
        return broken(0, UNPINNED_RECEIPT_BANNER.to_string());
    }
    let signer_id = signer_key_id(&receipts[0]);
    let mut prev_hash = GENESIS_HASH.to_string();
    for (index, receipt) in receipts.iter().enumerate() {
        let seq = receipt
            .get("chain_seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(index as u64);
        if receipt
            .get("record_type")
            .and_then(serde_json::Value::as_str)
            != Some(EVIDENCE_RECORD_TYPE)
        {
            return broken(seq, format!("seq {seq}: mixed receipt record_type"));
        }
        let verify_result = if key_hex.is_empty() {
            normalize_evidence_receipt(receipt)
        } else {
            verify_receipt(receipt, &key_hex)
        };
        if let Err(err) = verify_result {
            return broken(seq, format!("seq {seq}: signature: {err}"));
        }
        if signer_key_id(receipt) != signer_id {
            return broken(
                seq,
                format!("seq {seq}: signer_key_id breaks chain signer {signer_id}"),
            );
        }
        if seq != index as u64 {
            return broken(seq, format!("seq gap: expected {index}, got {seq}"));
        }
        let chain_prev_hash = receipt
            .get("chain_prev_hash")
            .and_then(serde_json::Value::as_str);
        if chain_prev_hash != Some(prev_hash.as_str()) {
            return broken(seq, format!("seq {seq}: chain_prev_hash mismatch"));
        }
        prev_hash = receipt_hash(receipt);
    }

    ChainResult {
        valid: true,
        receipt_count: receipts.len(),
        final_seq: receipts
            .last()
            .and_then(|receipt| receipt.get("chain_seq"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        root_hash: prev_hash,
        error: None,
        broken_at_seq: None,
    }
}

fn signer_key_id(receipt: &Receipt) -> String {
    receipt
        .get("signature")
        .and_then(|value| value.get("signer_key_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
}

pub fn compute_totals(receipts: &[Receipt]) -> Totals {
    let mut totals = Totals::zero();
    for receipt in receipts {
        let verdict = receipt
            .get("action_record")
            .and_then(|record| record.get("verdict"))
            .and_then(|value| value.as_str())
            .unwrap_or("");
        totals.add_verdict(verdict);
    }
    totals
}

fn broken(seq: u64, error: String) -> ChainResult {
    ChainResult {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: String::new(),
        error: Some(error),
        broken_at_seq: Some(seq),
    }
}

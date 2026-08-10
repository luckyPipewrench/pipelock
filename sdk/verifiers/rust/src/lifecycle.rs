// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::types::{ChainResult, Receipt};
use std::collections::HashMap;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleReport {
    pub status: String,
    pub reason: String,
}

#[derive(Default)]
struct RunState {
    opened: bool,
    closed: bool,
    intents: HashMap<String, u64>,
    outcomes: HashMap<String, u64>,
    saw_heartbeat: bool,
    last_heartbeat: u64,
    heartbeat_gap: bool,
    last_durability: Option<DurabilitySnapshot>,
    durability_drop: bool,
}

#[derive(Clone, Copy)]
struct DurabilitySnapshot {
    fsync_errors_gated: Option<u64>,
    durability_blocks: Option<u64>,
}

// analyze_lifecycle mirrors the Go verifier's packet-level lifecycle verdict.
// It deliberately reports an open but otherwise valid run as LIMITED rather
// than rejecting the packet: integrity and a clean session close answer
// different questions.
pub fn analyze_lifecycle(receipts: &[Receipt], chain: &ChainResult) -> LifecycleReport {
    if receipts.is_empty() {
        return report("UNVERIFIED", "no_receipts");
    }
    let missing_open = !chain.valid
        && chain.integrity_verified
        && chain.failure_kind.as_deref() == Some("lifecycle_missing_open");
    if !chain.valid && !missing_open {
        return report("BROKEN", "chain_broken");
    }
    if missing_open {
        return report("UNVERIFIED", "no_open");
    }
    if !receipts
        .iter()
        .any(|receipt| session_control(receipt).is_some())
    {
        return report("UNVERIFIED", "no_lifecycle");
    }

    let mut runs = HashMap::<String, RunState>::new();
    for receipt in receipts {
        let Some(record) = receipt.get("action_record") else {
            continue;
        };
        let control = session_control(receipt);
        let run_nonce = run_nonce_for(record, control);
        if run_nonce.is_empty() {
            return report("BROKEN", "chain_broken");
        }
        let state = runs.entry(run_nonce).or_default();
        match record
            .get("decision_phase")
            .and_then(serde_json::Value::as_str)
        {
            Some("intent") => increment(
                &mut state.intents,
                record
                    .get("action_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            ),
            Some("outcome") => increment(
                &mut state.outcomes,
                record
                    .get("action_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            ),
            _ => {}
        }

        let Some(control) = control else {
            continue;
        };
        match control.get("kind").and_then(serde_json::Value::as_str) {
            Some("session_open") => {
                state.opened = true;
                state.closed = false;
            }
            Some("session_close") => {
                let Some(close) = control.get("close").and_then(serde_json::Value::as_object)
                else {
                    return report("BROKEN", "chain_broken");
                };
                let action_run_nonce = record
                    .get("run_nonce")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if action_run_nonce.is_empty()
                    || close.get("run_nonce").and_then(serde_json::Value::as_str)
                        != Some(action_run_nonce)
                {
                    return report("BROKEN", "chain_broken");
                }
                state.closed = true;
                if !apply_durability(state, control.get("close")) {
                    return report("BROKEN", "chain_broken");
                }
            }
            Some("heartbeat") | Some("session_heartbeat") => {
                let Some(heartbeat) = control
                    .get("heartbeat")
                    .and_then(serde_json::Value::as_object)
                else {
                    return report("BROKEN", "chain_broken");
                };
                let action_run_nonce = record
                    .get("run_nonce")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if action_run_nonce.is_empty()
                    || heartbeat
                        .get("run_nonce")
                        .and_then(serde_json::Value::as_str)
                        != Some(action_run_nonce)
                {
                    return report("BROKEN", "chain_broken");
                }
                let beat = heartbeat.get("beat").map(lifecycle_counter);
                let Some(beat) = beat else {
                    if !apply_durability(state, control.get("heartbeat")) {
                        return report("BROKEN", "chain_broken");
                    }
                    continue;
                };
                let Some(beat) = beat else {
                    return report("BROKEN", "chain_broken");
                };
                if (state.saw_heartbeat && beat != state.last_heartbeat + 1)
                    || (!state.saw_heartbeat && beat != 1)
                {
                    state.heartbeat_gap = true;
                }
                state.saw_heartbeat = true;
                state.last_heartbeat = beat;
                if !apply_durability(state, control.get("heartbeat")) {
                    return report("BROKEN", "chain_broken");
                }
            }
            _ => {}
        }
    }

    runs.values()
        .map(assess_run)
        .reduce(worse)
        .unwrap_or_else(|| report("UNVERIFIED", "no_lifecycle"))
}

fn apply_durability(state: &mut RunState, value: Option<&serde_json::Value>) -> bool {
    let snapshot = DurabilitySnapshot {
        fsync_errors_gated: match value.and_then(|value| value.get("fsync_errors_gated")) {
            Some(value) => match lifecycle_counter(value) {
                Some(value) => Some(value),
                None => return false,
            },
            None => None,
        },
        durability_blocks: match value.and_then(|value| value.get("durability_blocks")) {
            Some(value) => match lifecycle_counter(value) {
                Some(value) => Some(value),
                None => return false,
            },
            None => None,
        },
    };
    if let Some(previous) = state.last_durability {
        if snapshot
            .fsync_errors_gated
            .zip(previous.fsync_errors_gated)
            .is_some_and(|(current, previous)| current < previous)
            || snapshot
                .durability_blocks
                .zip(previous.durability_blocks)
                .is_some_and(|(current, previous)| current < previous)
        {
            state.durability_drop = true;
        }
    }
    state.last_durability = Some(snapshot);
    true
}

fn lifecycle_counter(value: &serde_json::Value) -> Option<u64> {
    value.as_u64().filter(|value| *value <= MAX_SAFE_INTEGER)
}

fn session_control(receipt: &Receipt) -> Option<&serde_json::Map<String, serde_json::Value>> {
    receipt
        .get("action_record")
        .and_then(|record| record.get("session_control"))
        .and_then(serde_json::Value::as_object)
}

fn run_nonce_for(
    record: &serde_json::Value,
    control: Option<&serde_json::Map<String, serde_json::Value>>,
) -> String {
    if let Some(run_nonce) = record.get("run_nonce").and_then(serde_json::Value::as_str) {
        if !run_nonce.is_empty() {
            return run_nonce.to_string();
        }
    }
    let Some(control) = control else {
        return String::new();
    };
    let payload = match control.get("kind").and_then(serde_json::Value::as_str) {
        Some("session_open") => control.get("open"),
        Some("heartbeat") | Some("session_heartbeat") => control.get("heartbeat"),
        Some("session_close") => control.get("close"),
        _ => None,
    };
    payload
        .and_then(|payload| payload.get("run_nonce"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn increment(values: &mut HashMap<String, u64>, key: &str) {
    *values.entry(key.to_string()).or_default() += 1;
}

fn assess_run(state: &RunState) -> LifecycleReport {
    if !state.opened {
        // An observed run nonce without its own session_open contradicts the
        // transcript. UNVERIFIED/no_open is reserved for the chain verifier's
        // explicit, integrity-proven lifecycle_missing_open failure kind above.
        return report("BROKEN", "chain_broken");
    }
    if state.outcomes.iter().any(|(action_id, outcomes)| {
        *outcomes > 0 && state.intents.get(action_id).unwrap_or(&0) == &0
    }) {
        return report("BROKEN", "chain_broken");
    }
    if state
        .intents
        .iter()
        .any(|(action_id, intents)| state.outcomes.get(action_id).unwrap_or(&0) < intents)
    {
        return report("LIMITED", "open_action");
    }
    if state.durability_drop {
        return report("BROKEN", "chain_broken");
    }
    if state.heartbeat_gap {
        return report("LIMITED", "heartbeat_gap");
    }
    if !state.closed {
        return report("LIMITED", "abnormal_end");
    }
    report("LIMITED", "bounded_closed")
}

fn report(status: &str, reason: &str) -> LifecycleReport {
    LifecycleReport {
        status: status.to_string(),
        reason: reason.to_string(),
    }
}

fn worse(current: LifecycleReport, next: LifecycleReport) -> LifecycleReport {
    let current_key = (
        status_severity(&current.status),
        reason_severity(&current.reason),
    );
    let next_key = (status_severity(&next.status), reason_severity(&next.reason));
    if next_key > current_key {
        next
    } else {
        current
    }
}

fn status_severity(status: &str) -> u8 {
    match status {
        "BROKEN" => 3,
        "UNVERIFIED" => 2,
        "LIMITED" => 1,
        _ => 0,
    }
}

fn reason_severity(reason: &str) -> u8 {
    match reason {
        "chain_broken" => 100,
        "no_open" => 80,
        "no_lifecycle" | "recorder_disabled" | "no_receipts" => 70,
        "open_action" => 50,
        "heartbeat_gap" => 40,
        "abnormal_end" => 30,
        "bounded_closed" => 10,
        _ => 0,
    }
}

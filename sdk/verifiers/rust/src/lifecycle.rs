// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use crate::types::{ChainResult, Receipt};
use std::collections::HashMap;

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
}

// analyze_lifecycle mirrors the Go verifier's packet-level lifecycle verdict.
// It deliberately reports an open but otherwise valid run as LIMITED rather
// than rejecting the packet: integrity and a clean session close answer
// different questions.
pub fn analyze_lifecycle(receipts: &[Receipt], chain: &ChainResult) -> LifecycleReport {
    if receipts.is_empty() {
        return report("UNVERIFIED", "no_receipts");
    }
    if !chain.valid {
        return report("BROKEN", "chain_broken");
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
            continue;
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
            Some("session_close") => state.closed = true,
            Some("session_heartbeat") => {
                if let Some(beat) = control
                    .get("heartbeat")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|heartbeat| heartbeat.get("beat"))
                    .and_then(serde_json::Value::as_u64)
                {
                    if (state.saw_heartbeat && beat != state.last_heartbeat + 1)
                        || (!state.saw_heartbeat && beat != 1)
                    {
                        state.heartbeat_gap = true;
                    }
                    state.saw_heartbeat = true;
                    state.last_heartbeat = beat;
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
        Some("session_heartbeat") => control.get("heartbeat"),
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
        return report("UNVERIFIED", "no_open");
    }
    if state
        .outcomes
        .iter()
        .any(|(action_id, outcomes)| state.intents.get(action_id).unwrap_or(&0) < outcomes)
    {
        return report("BROKEN", "chain_broken");
    }
    if state
        .intents
        .iter()
        .any(|(action_id, intents)| state.outcomes.get(action_id).unwrap_or(&0) < intents)
    {
        return report("LIMITED", "open_action");
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

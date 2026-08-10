// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import type { ChainResult, LifecycleReason, LifecycleStatus, Receipt } from "./types.js";

export interface LifecycleReport {
  status: LifecycleStatus;
  reason: LifecycleReason;
}

interface RunState {
  opened: boolean;
  closed: boolean;
  intents: Map<string, number>;
  outcomes: Map<string, number>;
  sawHeartbeat: boolean;
  lastHeartbeat: number;
  heartbeatGap: boolean;
  lastDurability?: DurabilitySnapshot;
  durabilityDrop: boolean;
}

interface DurabilitySnapshot {
  fsyncErrorsGated?: number;
  durabilityBlocks?: number;
}

const limited: LifecycleStatus = "LIMITED";
const broken: LifecycleStatus = "BROKEN";
const unverified: LifecycleStatus = "UNVERIFIED";

// analyzeLifecycle mirrors the Go verifier's packet-level lifecycle verdict.
// It deliberately reports an open but otherwise valid run as LIMITED rather
// than rejecting the packet: integrity and a clean session close answer
// different questions.
export function analyzeLifecycle(receipts: Receipt[], chain: ChainResult): LifecycleReport {
  if (receipts.length === 0) return { status: unverified, reason: "no_receipts" };
  const missingOpen =
    !chain.valid &&
    chain.integrity_verified === true &&
    chain.failure_kind === "lifecycle_missing_open";
  if (!chain.valid && !missingOpen) return { status: broken, reason: "chain_broken" };
  if (missingOpen) return { status: unverified, reason: "no_open" };
  const controls = receipts.filter((receipt) => sessionControl(receipt) !== undefined);
  if (controls.length === 0) return { status: unverified, reason: "no_lifecycle" };

  const runs = new Map<string, RunState>();
  const stateFor = (runNonce: string): RunState => {
    let state = runs.get(runNonce);
    if (state === undefined) {
      state = {
        opened: false,
        closed: false,
        intents: new Map<string, number>(),
        outcomes: new Map<string, number>(),
        sawHeartbeat: false,
        lastHeartbeat: 0,
        heartbeatGap: false,
        durabilityDrop: false,
      };
      runs.set(runNonce, state);
    }
    return state;
  };

  for (const receipt of receipts) {
    const record = receipt.action_record;
    if (record === undefined) continue;
    const control = sessionControl(receipt);
    const runNonce = runNonceFor(record, control);
    if (runNonce === "") return { status: broken, reason: "chain_broken" };
    const state = stateFor(runNonce);

    if (record.decision_phase === "intent") increment(state.intents, record.action_id ?? "");
    if (record.decision_phase === "outcome") increment(state.outcomes, record.action_id ?? "");

    if (control === undefined) continue;
    const kind = control["kind"];
    if (kind === "session_open") {
      state.opened = true;
      state.closed = false;
      continue;
    }
    if (kind === "session_close") {
      const close = objectField(control, "close");
      if (
        close === undefined ||
        typeof record.run_nonce !== "string" ||
        record.run_nonce === "" ||
        close["run_nonce"] !== record.run_nonce
      ) {
        return { status: broken, reason: "chain_broken" };
      }
      state.closed = true;
      if (!applyDurability(state, close)) {
        return { status: broken, reason: "chain_broken" };
      }
      continue;
    }
    if (kind === "heartbeat" || kind === "session_heartbeat") {
      const heartbeat = objectField(control, "heartbeat");
      if (
        heartbeat === undefined ||
        typeof record.run_nonce !== "string" ||
        record.run_nonce === "" ||
        heartbeat["run_nonce"] !== record.run_nonce
      ) {
        return { status: broken, reason: "chain_broken" };
      }
      const beat = heartbeat?.["beat"];
      if (beat !== undefined && !validCounter(beat)) {
        return { status: broken, reason: "chain_broken" };
      }
      if (beat !== undefined) {
        if (
          (state.sawHeartbeat && beat !== state.lastHeartbeat + 1) ||
          (!state.sawHeartbeat && beat !== 1)
        ) {
          state.heartbeatGap = true;
        }
        state.sawHeartbeat = true;
        state.lastHeartbeat = beat;
      }
      if (!applyDurability(state, heartbeat)) return { status: broken, reason: "chain_broken" };
    }
  }

  let report: LifecycleReport | undefined;
  for (const state of runs.values()) {
    report = worse(report, assessRun(state));
  }
  return report ?? { status: unverified, reason: "no_lifecycle" };
}

function applyDurability(state: RunState, value: Record<string, unknown> | undefined): boolean {
  const fsyncErrorsGated = counter(value?.["fsync_errors_gated"]);
  const durabilityBlocks = counter(value?.["durability_blocks"]);
  if (fsyncErrorsGated === null || durabilityBlocks === null) return false;
  const snapshot: DurabilitySnapshot = {
    fsyncErrorsGated,
    durabilityBlocks,
  };
  if (
    state.lastDurability !== undefined &&
    ((snapshot.fsyncErrorsGated !== undefined &&
      state.lastDurability.fsyncErrorsGated !== undefined &&
      snapshot.fsyncErrorsGated < state.lastDurability.fsyncErrorsGated) ||
      (snapshot.durabilityBlocks !== undefined &&
        state.lastDurability.durabilityBlocks !== undefined &&
        snapshot.durabilityBlocks < state.lastDurability.durabilityBlocks))
  ) {
    state.durabilityDrop = true;
  }
  state.lastDurability = snapshot;
  return true;
}

function validCounter(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function counter(value: unknown): number | undefined | null {
  if (value === undefined) return undefined;
  return validCounter(value) ? value : null;
}

function sessionControl(receipt: Receipt): Record<string, unknown> | undefined {
  const value = receipt.action_record?.session_control;
  return value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

function objectField(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const field = value[key];
  return field !== null && typeof field === "object" && !Array.isArray(field)
    ? (field as Record<string, unknown>)
    : undefined;
}

function runNonceFor(
  record: NonNullable<Receipt["action_record"]>,
  control: Record<string, unknown> | undefined,
): string {
  if (typeof record.run_nonce === "string" && record.run_nonce !== "") return record.run_nonce;
  if (control === undefined) return "";
  const kind = control["kind"];
  const payload =
    kind === "session_open"
      ? objectField(control, "open")
      : kind === "heartbeat" || kind === "session_heartbeat"
        ? objectField(control, "heartbeat")
        : kind === "session_close"
          ? objectField(control, "close")
          : undefined;
  return typeof payload?.["run_nonce"] === "string" ? (payload["run_nonce"] as string) : "";
}

function increment(values: Map<string, number>, key: string): void {
  values.set(key, (values.get(key) ?? 0) + 1);
}

function assessRun(state: RunState): LifecycleReport {
  // An observed run nonce without its own session_open contradicts the
  // transcript. UNVERIFIED/no_open is reserved for the chain verifier's
  // explicit, integrity-proven lifecycle_missing_open failure kind above.
  if (!state.opened) return { status: broken, reason: "chain_broken" };
  for (const [actionID, outcomes] of state.outcomes) {
    if ((state.intents.get(actionID) ?? 0) === 0 && outcomes > 0)
      return { status: broken, reason: "chain_broken" };
  }
  for (const [actionID, intents] of state.intents) {
    if ((state.outcomes.get(actionID) ?? 0) < intents)
      return { status: limited, reason: "open_action" };
  }
  if (state.durabilityDrop) return { status: broken, reason: "chain_broken" };
  if (state.heartbeatGap) return { status: limited, reason: "heartbeat_gap" };
  if (!state.closed) return { status: limited, reason: "abnormal_end" };
  return { status: limited, reason: "bounded_closed" };
}

function worse(current: LifecycleReport | undefined, next: LifecycleReport): LifecycleReport {
  if (current === undefined) return next;
  const statusOrder: Record<LifecycleStatus, number> = {
    LIMITED: 1,
    UNVERIFIED: 2,
    BROKEN: 3,
  };
  const reasonOrder: Record<LifecycleReason, number> = {
    chain_broken: 100,
    no_open: 80,
    no_lifecycle: 70,
    recorder_disabled: 70,
    no_receipts: 70,
    open_action: 50,
    heartbeat_gap: 40,
    abnormal_end: 30,
    bounded_closed: 10,
  };
  if (statusOrder[next.status] > statusOrder[current.status]) return next;
  if (
    statusOrder[next.status] === statusOrder[current.status] &&
    reasonOrder[next.reason] > reasonOrder[current.reason]
  ) {
    return next;
  }
  return current;
}

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import type { ChainResult, Receipt } from "./types.js";
import { canonicalizeReceipt } from "./canonical.js";
import { canonicalizeBytes } from "./aarp/canonical.js";
import { sha256Hex } from "./util.js";
import { normalizeEvidenceReceipt, unpinnedReceiptBanner, verifyReceipt } from "./signing.js";

export const genesisHash = "genesis";
export const genesisSessionOpenPrefix = "g1:";
const sessionOpenGenesisLabel = "pipelock.receipt.session_open.v1";
const evidenceRecordType = "evidence_receipt_v2";

export function receiptHash(receipt: Receipt): string {
  if (receipt.record_type === evidenceRecordType) {
    return sha256Hex(canonicalizeBytes(receipt as Record<string, unknown>));
  }
  return sha256Hex(canonicalizeReceipt(receipt));
}

export interface VerifyChainOptions {
  allowUnpinned?: boolean;
}

export async function verifyChain(
  receipts: Receipt[],
  expectedKeyHex = "",
  options: VerifyChainOptions = {},
): Promise<ChainResult> {
  if (receipts.length === 0) {
    return { valid: true, receipt_count: 0, final_seq: 0, root_hash: "" };
  }

  if (receipts[0]?.record_type === evidenceRecordType) {
    return verifyEvidenceChain(receipts, expectedKeyHex, options);
  }

  const trustedKeys = parseTrustedKeys(expectedKeyHex);
  if (trustedKeys.size === 0 && options.allowUnpinned !== true) {
    return unpinnedChainResult(0);
  }
  const firstKey = (receipts[0]?.signer_key ?? "").toLowerCase();
  if (trustedKeys.size > 0 && !trustedKeys.has(firstKey)) {
    return broken(0, `signer key ${firstKey} is not in the trusted set`);
  }

  const state: ChainWalkState = {
    curKey: firstKey,
    segmentStartIndex: 0,
    segmentBaseSeq: 0,
    segmentReceiptCount: 0,
    prevHash: "",
    priorSegmentSeq: undefined,
    activeRunNonce: undefined,
    activeOpenNonce: undefined,
    openedRuns: new Set<string>(),
    closedRuns: new Set<string>(),
  };
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i] as Receipt;
    const rawSeq = receipt.action_record?.chain_seq;
    if (!Number.isInteger(rawSeq) || (rawSeq as number) < 0) {
      return broken(i, `seq ${i}: missing or invalid chain_seq`);
    }
    const seq = rawSeq as number;
    if (i === 0) {
      if (receipt.action_record?.key_transition !== undefined) {
        return broken(
          seq,
          `seq ${seq}: chain starts at a key_transition segment without the prior segment`,
        );
      }
      const genesisResult = validateActionGenesis(
        receipt,
        receipt.action_record?.chain_prev_hash,
        seq,
      );
      if (genesisResult !== undefined) return genesisResult;
      state.segmentBaseSeq = seq;
    } else if (receipt.action_record?.key_transition !== undefined) {
      const rotation = startRotatedSegment(
        receipt,
        seq,
        i,
        state,
        trustedKeys,
        options.allowUnpinned === true,
      );
      if (rotation !== undefined) return rotation;
    } else {
      if (seq === 0) {
        return broken(seq, `seq ${seq}: unexpected seq 0 without a key_transition boundary`);
      }
      const expectedSeq = state.segmentBaseSeq + (i - state.segmentStartIndex);
      if (seq !== expectedSeq) {
        return broken(seq, `seq gap: expected ${expectedSeq}, got ${seq}`);
      }
      if (receipt.action_record?.chain_prev_hash !== state.prevHash) {
        return broken(seq, `seq ${seq}: chain_prev_hash mismatch`);
      }
    }
    try {
      await verifyReceipt(receipt, state.curKey, { allowUnpinned: options.allowUnpinned });
    } catch (err) {
      return broken(seq, `seq ${seq}: signature: ${(err as Error).message}`);
    }
    const expectedSeq = state.segmentBaseSeq + (i - state.segmentStartIndex);
    if (seq !== expectedSeq) {
      return broken(seq, `seq gap: expected ${expectedSeq}, got ${seq}`);
    }
    state.segmentReceiptCount++;
    const closedRunResult = validateClosedRun(receipt, seq, state);
    if (closedRunResult !== undefined) return closedRunResult;
    const sessionControlResult = validateSessionControlState(receipt, seq, i, state);
    if (sessionControlResult !== undefined) return sessionControlResult;
    const open = sessionOpen(receipt);
    if (open !== undefined) {
      state.activeRunNonce = typeof open["run_nonce"] === "string" ? open["run_nonce"] : undefined;
      state.activeOpenNonce =
        typeof open["open_nonce"] === "string" ? open["open_nonce"] : undefined;
      if (state.activeRunNonce !== undefined) {
        state.openedRuns.add(state.activeRunNonce);
        state.closedRuns.delete(state.activeRunNonce);
      }
    } else if (sessionClose(receipt) !== undefined) {
      if (state.activeRunNonce !== undefined) state.closedRuns.add(state.activeRunNonce);
      state.activeRunNonce = undefined;
      state.activeOpenNonce = undefined;
    }
    state.prevHash = receiptHash(receipt);
    state.priorSegmentSeq = seq;
  }

  const last = receipts[receipts.length - 1] as Receipt;
  return {
    valid: true,
    receipt_count: receipts.length,
    final_seq: last.action_record?.chain_seq ?? 0,
    root_hash: state.prevHash,
  };
}

export function computeSessionOpenGenesis(open: Record<string, unknown>): string {
  const h = createHash("sha256");
  const frame = (data: Buffer): void => {
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(data.length), 0);
    h.update(len);
    h.update(data);
  };
  const textField = (name: string): Buffer => {
    const value = open[name];
    return Buffer.from(typeof value === "string" ? value : "", "utf8");
  };
  frame(Buffer.from(sessionOpenGenesisLabel, "utf8"));
  frame(textField("run_nonce"));
  frame(textField("open_nonce"));
  frame(textField("recorder_session"));
  frame(textField("policy_hash"));
  frame(textField("signer_key_epoch"));
  const hb = Buffer.alloc(8);
  const rawHeartbeatSeconds = open["heartbeat_seconds"];
  const heartbeatSeconds =
    typeof rawHeartbeatSeconds === "number" &&
    Number.isInteger(rawHeartbeatSeconds) &&
    rawHeartbeatSeconds > 0
      ? rawHeartbeatSeconds
      : 0;
  hb.writeBigUInt64BE(BigInt(heartbeatSeconds), 0);
  frame(hb);
  frame(textField("genesis_anchor_head"));
  frame(textField("genesis_anchor_log"));
  frame(textField("posture_capsule_sha256"));
  frame(textField("containment_nonce"));
  frame(textField("contained_uid"));
  return `${genesisSessionOpenPrefix}${h.digest("hex")}`;
}

function validateActionGenesis(
  receipt: Receipt,
  chainPrevHash: string | undefined,
  seq: number,
): ChainResult | undefined {
  const open = sessionOpen(receipt);
  if (chainPrevHash?.startsWith(genesisSessionOpenPrefix)) {
    if (open === undefined) {
      return broken(seq, `seq ${seq}: g1 chain_prev_hash requires session_control.open`);
    }
    if (seq !== 0) {
      return broken(seq, `seq ${seq}: bound session_open genesis must be chain_seq 0`);
    }
    const computed = computeSessionOpenGenesis(open);
    if (chainPrevHash !== computed) {
      return broken(seq, `seq ${seq}: session_open genesis hash mismatch`);
    }
    if (open["genesis_hash"] !== computed) {
      return broken(seq, `seq ${seq}: session_open genesis_hash mismatch`);
    }
    if (open["chain_open_seq"] !== seq) {
      return broken(
        seq,
        `seq ${seq}: session_open chain_open_seq does not match receipt chain_seq`,
      );
    }
    if ((open["prior_chain_head"] ?? "") !== "" || (open["prior_chain_seq"] ?? 0) !== 0) {
      return broken(seq, `seq ${seq}: bound genesis session_open must not carry prior chain tail`);
    }
    return undefined;
  }
  if (chainPrevHash !== genesisHash) {
    return broken(
      seq,
      `seq ${seq}: genesis receipt chain_prev_hash must be genesis or a bound session_open g1 hash`,
    );
  }
  if (open !== undefined) {
    return broken(
      seq,
      `seq ${seq}: session_open on legacy genesis must use bound g1 chain_prev_hash`,
    );
  }
  return undefined;
}

function sessionOpen(receipt: Receipt): Record<string, unknown> | undefined {
  const ctrl = receipt.action_record?.session_control;
  if (typeof ctrl !== "object" || ctrl === null || Array.isArray(ctrl)) return undefined;
  if ((ctrl as Record<string, unknown>)["kind"] !== "session_open") return undefined;
  const open = (ctrl as Record<string, unknown>)["open"];
  if (typeof open !== "object" || open === null || Array.isArray(open)) return undefined;
  return open as Record<string, unknown>;
}

function sessionClose(receipt: Receipt): Record<string, unknown> | undefined {
  const ctrl = receipt.action_record?.session_control;
  if (typeof ctrl !== "object" || ctrl === null || Array.isArray(ctrl)) return undefined;
  if ((ctrl as Record<string, unknown>)["kind"] !== "session_close") return undefined;
  const close = (ctrl as Record<string, unknown>)["close"];
  if (typeof close !== "object" || close === null || Array.isArray(close)) return undefined;
  return close as Record<string, unknown>;
}

function parseTrustedKeys(expectedKeyHex: string): Set<string> {
  return new Set(
    expectedKeyHex
      .split(",")
      .map((key) => key.trim().toLowerCase())
      .filter((key) => key !== ""),
  );
}

interface ChainWalkState {
  curKey: string;
  segmentStartIndex: number;
  segmentBaseSeq: number;
  segmentReceiptCount: number;
  prevHash: string;
  priorSegmentSeq: number | undefined;
  activeRunNonce: string | undefined;
  activeOpenNonce: string | undefined;
  openedRuns: Set<string>;
  closedRuns: Set<string>;
}

function startRotatedSegment(
  receipt: Receipt,
  seq: number,
  index: number,
  state: ChainWalkState,
  trustedKeys: Set<string>,
  allowUnpinned: boolean,
): ChainResult | undefined {
  const marker = receipt.action_record?.key_transition as Record<string, unknown> | undefined;
  if (seq !== 0) {
    return broken(seq, `seq ${seq}: key_transition marker on a non-genesis receipt (seq != 0)`);
  }
  if (marker?.["prior_chain_hash"] !== state.prevHash) {
    return broken(
      seq,
      `seq ${seq}: key_transition prior_chain_hash does not match actual prior tail hash`,
    );
  }
  if (receipt.action_record?.chain_prev_hash !== state.prevHash) {
    return broken(
      seq,
      `seq ${seq}: segment-genesis chain_prev_hash does not match prior tail hash`,
    );
  }
  if (marker?.["prior_signer_key"] !== state.curKey) {
    return broken(
      seq,
      `seq ${seq}: key_transition prior_signer_key does not match prior segment key`,
    );
  }
  if (marker?.["prior_chain_seq"] !== state.priorSegmentSeq) {
    return broken(
      seq,
      `seq ${seq}: key_transition prior_chain_seq does not match prior segment final seq`,
    );
  }
  const signerKey = (receipt.signer_key ?? "").toLowerCase();
  if (trustedKeys.size === 0) {
    if (!allowUnpinned || signerKey !== state.curKey) {
      return broken(seq, `seq ${seq}: signer key ${signerKey} is not in the trusted set`);
    }
  } else if (!trustedKeys.has(signerKey)) {
    return broken(seq, `seq ${seq}: signer key ${signerKey} is not in the trusted set`);
  }
  state.curKey = signerKey;
  state.segmentStartIndex = index;
  state.segmentBaseSeq = 0;
  state.segmentReceiptCount = 0;
  return undefined;
}

function validateClosedRun(
  receipt: Receipt,
  seq: number,
  state: ChainWalkState,
): ChainResult | undefined {
  if (sessionOpen(receipt) !== undefined) return undefined;
  const runNonce = receipt.action_record?.run_nonce;
  if (typeof runNonce !== "string" || runNonce === "") return undefined;
  if (!state.openedRuns.has(runNonce)) {
    return broken(seq, `seq ${seq}: run_nonce first receipt is not a matching session_open`);
  }
  if (state.closedRuns.has(runNonce)) {
    return broken(seq, `seq ${seq}: record observed after session_close`);
  }
  return undefined;
}

function validateSessionControlState(
  receipt: Receipt,
  seq: number,
  index: number,
  state: ChainWalkState,
): ChainResult | undefined {
  const ctrl = receipt.action_record?.session_control;
  if (typeof ctrl !== "object" || ctrl === null || Array.isArray(ctrl)) return undefined;
  const control = ctrl as Record<string, unknown>;
  const kind = control["kind"];
  const payloadCount = ["open", "heartbeat", "close"].filter(
    (name) => control[name] !== undefined && control[name] !== null,
  ).length;
  if (payloadCount !== 1) {
    return broken(seq, `seq ${seq}: session_control must carry exactly one payload`);
  }
  const actionRunNonce = receipt.action_record?.run_nonce;
  if (typeof actionRunNonce !== "string" || actionRunNonce === "") {
    return broken(seq, `seq ${seq}: session_control receipt missing run_nonce`);
  }
  let controlRunNonce: unknown;
  if (kind === "session_open") {
    const open = control["open"];
    if (typeof open === "object" && open !== null && !Array.isArray(open)) {
      controlRunNonce = (open as Record<string, unknown>)["run_nonce"];
    }
  } else if (kind === "heartbeat") {
    const heartbeat = control["heartbeat"];
    if (typeof heartbeat === "object" && heartbeat !== null && !Array.isArray(heartbeat)) {
      controlRunNonce = (heartbeat as Record<string, unknown>)["run_nonce"];
    }
  } else if (kind === "session_close") {
    const close = control["close"];
    if (typeof close === "object" && close !== null && !Array.isArray(close)) {
      controlRunNonce = (close as Record<string, unknown>)["run_nonce"];
    }
  }
  if (controlRunNonce !== actionRunNonce) {
    return broken(seq, `seq ${seq}: session_control run_nonce mismatch`);
  }
  if (kind === "session_open" && index > 0) {
    const open = control["open"];
    if (typeof open !== "object" || open === null || Array.isArray(open)) return undefined;
    const openRecord = open as Record<string, unknown>;
    const runNonce = typeof openRecord["run_nonce"] === "string" ? openRecord["run_nonce"] : "";
    if (state.openedRuns.has(runNonce)) {
      return broken(seq, `seq ${seq}: duplicate session_open for run_nonce`);
    }
    if (openRecord["chain_open_seq"] !== seq) {
      return broken(
        seq,
        `seq ${seq}: session_open chain_open_seq does not match receipt chain_seq`,
      );
    }
    if ((openRecord["prior_chain_head"] ?? "") !== state.prevHash) {
      return broken(seq, `seq ${seq}: session_open prior_chain_head does not match chain tail`);
    }
    if ((openRecord["prior_chain_seq"] ?? 0) !== (state.priorSegmentSeq ?? 0)) {
      return broken(seq, `seq ${seq}: session_open prior_chain_seq does not match previous seq`);
    }
    return undefined;
  }
  if (kind === "heartbeat") {
    const heartbeat = control["heartbeat"];
    if (typeof heartbeat !== "object" || heartbeat === null || Array.isArray(heartbeat)) {
      return undefined;
    }
    const heartbeatRecord = heartbeat as Record<string, unknown>;
    if (state.activeRunNonce === undefined || state.activeOpenNonce === undefined) {
      return broken(seq, `seq ${seq}: heartbeat has no active session_open`);
    }
    if (heartbeatRecord["run_nonce"] !== state.activeRunNonce) {
      return broken(seq, `seq ${seq}: heartbeat run_nonce mismatch`);
    }
    if (heartbeatRecord["open_nonce"] !== state.activeOpenNonce) {
      return broken(seq, `seq ${seq}: heartbeat open_nonce mismatch`);
    }
    if (heartbeatRecord["chain_head"] !== state.prevHash) {
      return broken(seq, `seq ${seq}: heartbeat chain_head mismatch`);
    }
    if (heartbeatRecord["chain_seq_head"] !== seq - 1) {
      return broken(seq, `seq ${seq}: heartbeat chain_seq_head mismatch`);
    }
  } else if (kind === "session_close") {
    const close = control["close"];
    if (typeof close !== "object" || close === null || Array.isArray(close)) return undefined;
    const closeRecord = close as Record<string, unknown>;
    if (state.activeRunNonce === undefined || state.activeOpenNonce === undefined) {
      return broken(seq, `seq ${seq}: session_close has no active session_open`);
    }
    if (closeRecord["run_nonce"] !== state.activeRunNonce) {
      return broken(seq, `seq ${seq}: session_close run_nonce mismatch`);
    }
    if (closeRecord["open_nonce"] !== state.activeOpenNonce) {
      return broken(seq, `seq ${seq}: session_close open_nonce mismatch`);
    }
    if (closeRecord["root_hash"] !== state.prevHash) {
      return broken(seq, `seq ${seq}: session_close root_hash mismatch`);
    }
    if (closeRecord["final_seq"] !== seq) {
      return broken(seq, `seq ${seq}: session_close final_seq mismatch`);
    }
    if (closeRecord["receipt_count"] !== state.segmentReceiptCount) {
      return broken(seq, `seq ${seq}: session_close receipt_count mismatch`);
    }
  }
  return undefined;
}

async function verifyEvidenceChain(
  receipts: Receipt[],
  expectedKeyHex: string,
  options: VerifyChainOptions,
): Promise<ChainResult> {
  const keyHex = expectedKeyHex.toLowerCase();
  if (keyHex === "" && options.allowUnpinned !== true) {
    return unpinnedChainResult(0);
  }
  const first = receipts[0];
  if (first === undefined) {
    return broken(0, "empty chain");
  }
  const signerID = signerKeyID(first);
  let prevHash = genesisHash;
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i];
    if (receipt === undefined) {
      return broken(i, `seq gap: expected ${i}, got missing receipt`);
    }
    const seq = receipt.chain_seq ?? 0;
    if (receipt.record_type !== evidenceRecordType) {
      return broken(seq, `seq ${seq}: mixed receipt record_type`);
    }
    try {
      if (keyHex === "") {
        normalizeEvidenceReceipt(receipt);
      } else {
        await verifyReceipt(receipt, keyHex);
      }
    } catch (err) {
      return broken(seq, `seq ${seq}: signature: ${(err as Error).message}`);
    }
    if (signerKeyID(receipt) !== signerID) {
      return broken(seq, `seq ${seq}: signer_key_id breaks chain signer ${signerID}`);
    }
    if (seq !== i) {
      return broken(seq, `seq gap: expected ${i}, got ${seq}`);
    }
    if (receipt.chain_prev_hash !== prevHash) {
      return broken(seq, `seq ${seq}: chain_prev_hash mismatch`);
    }
    prevHash = receiptHash(receipt);
  }
  const last = receipts[receipts.length - 1];
  if (last === undefined) {
    return broken(0, "empty chain");
  }
  return {
    valid: true,
    receipt_count: receipts.length,
    final_seq: last.chain_seq ?? 0,
    root_hash: prevHash,
  };
}

function signerKeyID(receipt: Receipt): string {
  const signature = receipt.signature;
  if (typeof signature === "object" && signature !== null) {
    const signer = signature["signer_key_id"];
    return typeof signer === "string" ? signer : "";
  }
  return "";
}

function unpinnedChainResult(seq: number): ChainResult {
  return broken(seq, unpinnedReceiptBanner);
}

function broken(seq: number, error: string): ChainResult {
  return {
    valid: false,
    receipt_count: 0,
    final_seq: 0,
    root_hash: "",
    broken_at_seq: seq,
    error,
  };
}

export function computeTotals(receipts: Receipt[]) {
  type VerdictBucket =
    | "allow"
    | "block"
    | "warn"
    | "ask"
    | "strip"
    | "forward"
    | "redirect"
    | "other";
  const totals: Record<VerdictBucket, number> = {
    allow: 0,
    block: 0,
    warn: 0,
    ask: 0,
    strip: 0,
    forward: 0,
    redirect: 0,
    other: 0,
  };
  for (const receipt of receipts) {
    const verdict = String(receipt.action_record?.verdict ?? "")
      .trim()
      .toLowerCase();
    if (Object.prototype.hasOwnProperty.call(totals, verdict)) {
      totals[verdict as VerdictBucket] += 1;
    } else {
      totals.other++;
    }
  }
  return totals;
}

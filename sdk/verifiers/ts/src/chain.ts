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

  let keyHex = expectedKeyHex;
  if (keyHex === "" && options.allowUnpinned !== true) {
    return unpinnedChainResult(0);
  }
  if (keyHex === "") keyHex = receipts[0]?.signer_key ?? "";

  let prevHash = "";
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i] as Receipt;
    const seq = receipt.action_record?.chain_seq;
    if (!Number.isInteger(seq) || (seq as number) < 0) {
      return broken(i, `seq ${i}: missing or invalid chain_seq`);
    }
    try {
      await verifyReceipt(receipt, keyHex, { allowUnpinned: options.allowUnpinned });
    } catch (err) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq as number,
        error: `seq ${seq as number}: signature: ${(err as Error).message}`,
      };
    }
    if (seq !== i) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq as number,
        error: `seq gap: expected ${i}, got ${seq}`,
      };
    }
    if (i === 0) {
      const genesisResult = validateActionGenesis(
        receipt,
        receipt.action_record?.chain_prev_hash,
        seq,
      );
      if (genesisResult !== undefined) return genesisResult;
    } else if (receipt.action_record?.chain_prev_hash !== prevHash) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq as number,
        error: `seq ${seq}: chain_prev_hash mismatch`,
      };
    }
    prevHash = receiptHash(receipt);
  }

  const last = receipts[receipts.length - 1] as Receipt;
  return {
    valid: true,
    receipt_count: receipts.length,
    final_seq: last.action_record?.chain_seq ?? 0,
    root_hash: prevHash,
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

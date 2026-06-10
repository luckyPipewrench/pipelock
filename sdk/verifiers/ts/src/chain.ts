import type { ChainResult, Receipt } from "./types.js";
import { canonicalizeReceipt } from "./canonical.js";
import { canonicalizeBytes } from "./aarp/canonical.js";
import { sha256Hex } from "./util.js";
import { normalizeEvidenceReceipt, unpinnedReceiptBanner, verifyReceipt } from "./signing.js";

export const genesisHash = "genesis";
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

  let prevHash = genesisHash;
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i] as Receipt;
    const seq = receipt.action_record?.chain_seq ?? 0;
    try {
      await verifyReceipt(receipt, keyHex, { allowUnpinned: options.allowUnpinned });
    } catch (err) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
        error: `seq ${seq}: signature: ${(err as Error).message}`,
      };
    }
    if (seq !== i) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
        error: `seq gap: expected ${i}, got ${seq}`,
      };
    }
    if (receipt.action_record?.chain_prev_hash !== prevHash) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
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

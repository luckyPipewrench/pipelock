import type { ChainResult, Receipt } from "./types.js";
import { canonicalizeReceipt } from "./canonical.js";
import { sha256Hex } from "./util.js";
import { verifyReceipt } from "./signing.js";

export const genesisHash = "genesis";

export function receiptHash(receipt: Receipt): string {
  return sha256Hex(canonicalizeReceipt(receipt));
}

export async function verifyChain(receipts: Receipt[], expectedKeyHex = ""): Promise<ChainResult> {
  if (receipts.length === 0) {
    return { valid: true, receipt_count: 0, final_seq: 0, root_hash: "" };
  }

  let keyHex = expectedKeyHex;
  if (keyHex === "") keyHex = receipts[0]?.signer_key ?? "";

  let prevHash = genesisHash;
  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i] as Receipt;
    const seq = receipt.action_record?.chain_seq ?? 0;
    try {
      await verifyReceipt(receipt, keyHex);
    } catch (err) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
        error: `seq ${seq}: signature: ${(err as Error).message}`
      };
    }
    if (seq !== i) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
        error: `seq gap: expected ${i}, got ${seq}`
      };
    }
    if (receipt.action_record?.chain_prev_hash !== prevHash) {
      return {
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        root_hash: "",
        broken_at_seq: seq,
        error: `seq ${seq}: chain_prev_hash mismatch`
      };
    }
    prevHash = receiptHash(receipt);
  }

  const last = receipts[receipts.length - 1] as Receipt;
  return {
    valid: true,
    receipt_count: receipts.length,
    final_seq: last.action_record?.chain_seq ?? 0,
    root_hash: prevHash
  };
}

export function computeTotals(receipts: Receipt[]) {
  type VerdictBucket = "allow" | "block" | "warn" | "ask" | "strip" | "forward" | "redirect" | "other";
  const totals: Record<VerdictBucket, number> = {
    allow: 0,
    block: 0,
    warn: 0,
    ask: 0,
    strip: 0,
    forward: 0,
    redirect: 0,
    other: 0
  };
  for (const receipt of receipts) {
    const verdict = String(receipt.action_record?.verdict ?? "").trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(totals, verdict)) {
      totals[verdict as VerdictBucket] += 1;
    } else {
      totals.other++;
    }
  }
  return totals;
}

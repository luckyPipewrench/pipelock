import { readFileSync } from "node:fs";
import * as path from "node:path";
import type { Receipt } from "./types.js";
import { normalizeEvidenceReceipt, unpinnedReceiptBanner, verifyReceipt } from "./signing.js";
import { parseJSON, rejectDuplicateKeys, resolveSignerKey } from "./util.js";

export interface ReceiptReport {
  path: string;
  valid: boolean;
  unpinned?: boolean;
  action_id?: string;
  verdict?: string;
  transport?: string;
  signer_key?: string;
  policy_hash?: string;
  chain_seq?: number;
  error?: string;
}

export async function runReceipt(
  pathname: string,
  signerKey: string,
  allowUnpinned = false,
): Promise<ReceiptReport> {
  const clean = path.normalize(pathname);
  const keyHex = resolveSignerKey(signerKey);
  const text = readFileSync(clean, "utf8");
  const report: ReceiptReport = {
    path: clean,
    valid: false,
  };
  try {
    // Reject duplicate object keys before parsing or populating report
    // metadata. Last-wins parsing would otherwise let attacker-controlled
    // duplicate values leak into the displayed rejection report.
    rejectDuplicateKeys(text);
  } catch (err) {
    report.error = (err as Error).message;
    return report;
  }
  const receipt = parseJSON<Receipt>(text, "receipt json");
  if (receipt.record_type === "evidence_receipt_v2") {
    const payload = receipt.payload as { verdict?: string; transport?: string } | undefined;
    report.action_id = receipt.event_id;
    report.verdict = payload?.verdict;
    report.transport = payload?.transport;
    report.signer_key = keyHex;
    report.policy_hash = receipt.policy_hash;
    report.chain_seq = receipt.chain_seq;
  } else {
    report.action_id = receipt.action_record?.action_id;
    report.verdict = receipt.action_record?.verdict;
    report.transport = receipt.action_record?.transport;
    report.signer_key = receipt.signer_key;
    report.policy_hash = receipt.action_record?.policy_hash;
    report.chain_seq = receipt.action_record?.chain_seq;
  }
  try {
    if (keyHex === "" && receipt.record_type === "evidence_receipt_v2") {
      normalizeEvidenceReceipt(receipt);
      report.unpinned = true;
      report.error = unpinnedReceiptBanner;
      report.valid = allowUnpinned;
      return report;
    }
    await verifyReceipt(receipt, keyHex, { allowUnpinned });
    if (keyHex === "") {
      report.unpinned = true;
      report.error = unpinnedReceiptBanner;
    }
    report.valid = true;
  } catch (err) {
    report.error = (err as Error).message;
    if (keyHex === "" && report.error === unpinnedReceiptBanner) {
      report.unpinned = true;
    }
  }
  return report;
}

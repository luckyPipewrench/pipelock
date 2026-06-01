import { readFileSync } from "node:fs";
import * as path from "node:path";
import type { Receipt } from "./types.js";
import { verifyReceipt } from "./signing.js";
import { parseJSON, rejectDuplicateKeys, resolveSignerKey } from "./util.js";

export interface ReceiptReport {
  path: string;
  valid: boolean;
  action_id?: string;
  verdict?: string;
  transport?: string;
  signer_key?: string;
  policy_hash?: string;
  chain_seq?: number;
  error?: string;
}

export async function runReceipt(pathname: string, signerKey: string): Promise<ReceiptReport> {
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
  report.action_id = receipt.action_record?.action_id;
  report.verdict = receipt.action_record?.verdict;
  report.transport = receipt.action_record?.transport;
  report.signer_key = receipt.signer_key;
  report.policy_hash = receipt.action_record?.policy_hash;
  report.chain_seq = receipt.action_record?.chain_seq;
  try {
    await verifyReceipt(receipt, keyHex);
    report.valid = true;
  } catch (err) {
    report.error = (err as Error).message;
  }
  return report;
}

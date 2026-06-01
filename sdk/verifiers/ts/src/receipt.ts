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
  const receipt = parseJSON<Receipt>(text, "receipt json");
  const report: ReceiptReport = {
    path: clean,
    valid: false,
    action_id: receipt.action_record?.action_id,
    verdict: receipt.action_record?.verdict,
    transport: receipt.action_record?.transport,
    signer_key: receipt.signer_key,
    policy_hash: receipt.action_record?.policy_hash,
    chain_seq: receipt.action_record?.chain_seq,
  };
  try {
    // Reject duplicate object keys before signature verification: last-wins
    // parsing would otherwise let a smuggled first-occurrence value diverge
    // from the signed value. Treated as an invalid receipt (exit 1), matching
    // the Go and Python verifiers.
    rejectDuplicateKeys(text);
    await verifyReceipt(receipt, keyHex);
    report.valid = true;
  } catch (err) {
    report.error = (err as Error).message;
  }
  return report;
}

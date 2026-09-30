// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import type { Receipt } from "./types.js";
import { secretEgressDecisionKind, validateSecretEgressSource } from "./secret-egress.js";
import { unpinnedReceiptBanner, verifyReceipt } from "./signing.js";
import { validateV1Receipt } from "./strict.js";
import {
  decodeUTF8,
  parseJSON,
  readVerifierBytes,
  rejectDuplicateKeys,
  resolveOperatorFilePath,
  resolveSignerKey,
} from "./util.js";

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
  const keyHex = resolveSignerKey(signerKey);
  const report: ReceiptReport = {
    path: pathname,
    valid: false,
  };
  let text: string;
  try {
    // A path that cannot be resolved is a failed verification with a report,
    // like a file that cannot be read, not an exception out of the verifier.
    const clean = resolveOperatorFilePath(pathname);
    report.path = clean;
    text = decodeUTF8(readVerifierBytes(clean), "receipt json");
  } catch (err) {
    report.error = (err as Error).message;
    return report;
  }
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
  try {
    validateSecretEgressSource(receipt, text);
  } catch (err) {
    report.error = (err as Error).message;
    return report;
  }
  // EV2-FU-1: reject unknown fields on a signed v1 receipt (the v2 evidence
  // receipt has its own schema). The only tolerated unknown surface is the
  // top-level ext bag.
  if (receipt.record_type !== "evidence_receipt_v2") {
    try {
      validateV1Receipt(receipt);
    } catch (err) {
      report.error = (err as Error).message;
      return report;
    }
  }
  if (receipt.record_type === "evidence_receipt_v2") {
    const payload = receipt.payload as
      { verdict?: string; transport?: string; decision?: { transport?: string } } | undefined;
    report.action_id = receipt.event_id;
    report.verdict = payload?.verdict;
    report.transport =
      receipt.payload_kind === secretEgressDecisionKind
        ? payload?.decision?.transport
        : payload?.transport;
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
      // With no pinned key the signature is still checked, against the
      // receipt's own declared signer: an edit after signing fails. That
      // proves nothing about who signed, so the receipt stays unpinned.
      await verifyReceipt(receipt, declaredSignerKey(receipt));
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

function declaredSignerKey(receipt: Receipt): string {
  const signature = receipt.signature;
  if (typeof signature === "object" && signature !== null) {
    const signer = (signature as Record<string, unknown>)["signer_key_id"];
    if (typeof signer === "string") return signer.toLowerCase();
  }
  return "";
}

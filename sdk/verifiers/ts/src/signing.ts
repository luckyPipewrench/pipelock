import * as ed25519 from "@noble/ed25519";
import type { ActionRecord, Receipt } from "./types.js";
import { canonicalizeActionRecord } from "./canonical.js";
import { decodeHex, sha256Hex } from "./util.js";

const signaturePrefix = "ed25519:";

const validActionTypes = new Set([
  "read",
  "derive",
  "write",
  "delegate",
  "authorize",
  "spend",
  "commit",
  "actuate",
  "unclassified"
]);

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value === "") throw new Error(`${name} is required`);
  return value;
}

function requireNumber(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return value;
}

export function validateActionRecord(actionRecord: ActionRecord | undefined): ActionRecord {
  if (!actionRecord || typeof actionRecord !== "object") throw new Error("action_record is required");
  if (actionRecord.version !== 1) {
    throw new Error(`unsupported action record version ${String(actionRecord.version)} (expected 1)`);
  }
  requireString(actionRecord.action_id, "action_id");
  const actionType = requireString(actionRecord.action_type, "action_type");
  if (!validActionTypes.has(actionType)) throw new Error(`invalid action_type ${actionType}`);
  requireString(actionRecord.timestamp, "timestamp");
  requireString(actionRecord.target, "target");
  requireString(actionRecord.verdict, "verdict");
  requireString(actionRecord.transport, "transport");
  requireString(actionRecord.chain_prev_hash, "chain_prev_hash");
  requireNumber(actionRecord.chain_seq, "chain_seq");
  return actionRecord;
}

export function normalizeReceipt(receipt: Receipt): Receipt {
  if (receipt.version !== 1) {
    throw new Error(`unsupported receipt version ${String(receipt.version)} (expected 1)`);
  }
  validateActionRecord(receipt.action_record);
  requireString(receipt.signature, "signature");
  requireString(receipt.signer_key, "signer_key");
  return receipt;
}

export async function verifyReceipt(receipt: Receipt, expectedKeyHex = ""): Promise<void> {
  normalizeReceipt(receipt);
  const signerKey = receipt.signer_key ?? "";
  const keyHex = expectedKeyHex === "" ? signerKey : expectedKeyHex;
  if (expectedKeyHex !== "" && signerKey !== expectedKeyHex) {
    throw new Error(`signer_key ${signerKey} does not match expected key ${expectedKeyHex}`);
  }

  const pubKey = decodeHex(keyHex, 32, "signer_key");
  const signature = receipt.signature ?? "";
  if (!signature.startsWith(signaturePrefix)) {
    throw new Error(`invalid signature format: missing ${signaturePrefix} prefix`);
  }
  const sig = decodeHex(signature.slice(signaturePrefix.length), 64, "signature");
  const digest = Buffer.from(sha256Hex(canonicalizeActionRecord(receipt.action_record as ActionRecord)), "hex");
  const ok = await ed25519.verifyAsync(sig, digest, pubKey);
  if (!ok) throw new Error("signature verification failed");
}

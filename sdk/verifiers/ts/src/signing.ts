import { createHash } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import type { ActionRecord, JSONObject, Receipt } from "./types.js";
import { canonicalizeActionRecord } from "./canonical.js";
import { canonicalizeBytes } from "./aarp/canonical.js";
import { decodeHex } from "./util.js";

const signaturePrefix = "ed25519:";
export const unpinnedReceiptBanner =
  "UNPINNED — signature is self-consistent but the signer was NOT checked against a trusted key";
const v2RecordType = "evidence_receipt_v2";
const v2ReceiptVersion = 2;
const v2SignatureAlgorithm = "ed25519";
const v2RequiredSignaturePurpose = "receipt-signing";
const v2JcsProfile = "pipelock-jcs-rfc8785-nfc-v1";
const v2JcsVersion = "rfc8785";
const v2HashAlg = "sha256";
const v2RedactionRulesetId = "pipelock-transform-v1";
const v2RedactionRulesetVersion = "1";
const v2RedactionRulesetHash =
  "sha256:541896788b42651a202448894583a847db9d1aa081c33a7e1f0512303d72527e";
const critCanonicalization = "canonicalization";
const critSourceSpans = "source_spans";

const v2PayloadKinds = new Set(["proxy_decision", "proxy_decision_with_spans"]);
const reservedV2PayloadKinds = new Set(["defer_opened", "defer_resolved"]);

const envelopeFields = new Set([
  "record_type",
  "receipt_version",
  "payload_kind",
  "canonicalization",
  "crit",
  "event_id",
  "timestamp",
  "principal",
  "actor",
  "delegation_chain",
  "signature",
  "chain_seq",
  "chain_prev_hash",
  "active_manifest_hash",
  "contract_hash",
  "policy_hash",
  "selector_id",
  "contract_generation",
  "payload",
]);

const canonicalizationFields = new Set([
  "jcs_profile",
  "jcs_version",
  "hash_alg",
  "sig_alg",
  "redaction_ruleset_id",
  "redaction_ruleset_version",
  "redaction_ruleset_hash",
]);

const signatureFields = new Set(["signer_key_id", "key_purpose", "algorithm", "signature"]);

const proxyDecisionFields = new Set([
  "action_type",
  "target",
  "verdict",
  "live_verdict",
  "transport",
  "policy_sources",
  "winning_source",
  "rule_id",
]);

const proxyDecisionWithSpansFields = new Set([...proxyDecisionFields, "source_spans"]);

const sourceSpanFields = new Set([
  "source_id",
  "source_kind",
  "normalized_view",
  "pipelock_binary_digest",
  "rules_bundle_digest",
  "transform_profile",
  "policy_hash",
  "rule_id",
  "bundle",
  "bundle_version",
  "char_offset",
  "char_length",
  "match_hash",
  "match_hash_alg",
  "match_class",
  "redacted_sample",
]);

const sourceKinds = new Set([
  "http_request_url",
  "http_response",
  "mcp_tool_result",
  "mcp_tool_args",
]);

const normalizedViews = new Set([
  "sanitized_target",
  "for_matching",
  "for_matching:invisible_spaced",
  "leetspeak:for_matching",
  "vowel_fold:for_matching",
  "for_matching:base64_decoded",
  "for_matching:hex_decoded",
  "dlp_normalized",
]);

const validActionTypes = new Set([
  "read",
  "derive",
  "write",
  "delegate",
  "authorize",
  "spend",
  "commit",
  "actuate",
  "unclassified",
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

function requireObject(value: unknown, name: string): JSONObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} is required`);
  }
  return value as JSONObject;
}

function rejectUnknownFields(
  obj: Record<string, unknown>,
  allowed: Set<string>,
  label: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw new Error(`${label}: unknown field ${key}`);
  }
}

function requireStringArray(value: unknown, name: string): string[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) => typeof item !== "string")
  ) {
    throw new Error(`${name} is required`);
  }
  return value as string[];
}

function validateCanonicalization(value: unknown): void {
  const canonicalization = requireObject(value, "canonicalization");
  rejectUnknownFields(canonicalization, canonicalizationFields, "canonicalization");
  if (
    requireString(canonicalization["jcs_profile"], "canonicalization.jcs_profile") !== v2JcsProfile
  ) {
    throw new Error("canonicalization.jcs_profile is invalid");
  }
  if (
    requireString(canonicalization["jcs_version"], "canonicalization.jcs_version") !== v2JcsVersion
  ) {
    throw new Error("canonicalization.jcs_version is invalid");
  }
  if (requireString(canonicalization["hash_alg"], "canonicalization.hash_alg") !== v2HashAlg) {
    throw new Error("canonicalization.hash_alg is invalid");
  }
  if (
    requireString(canonicalization["sig_alg"], "canonicalization.sig_alg") !== v2SignatureAlgorithm
  ) {
    throw new Error("canonicalization.sig_alg is invalid");
  }
  if (
    requireString(
      canonicalization["redaction_ruleset_id"],
      "canonicalization.redaction_ruleset_id",
    ) !== v2RedactionRulesetId
  ) {
    throw new Error("canonicalization.redaction_ruleset_id is invalid");
  }
  if (
    requireString(
      canonicalization["redaction_ruleset_version"],
      "canonicalization.redaction_ruleset_version",
    ) !== v2RedactionRulesetVersion
  ) {
    throw new Error("canonicalization.redaction_ruleset_version is invalid");
  }
  if (
    requireString(
      canonicalization["redaction_ruleset_hash"],
      "canonicalization.redaction_ruleset_hash",
    ) !== v2RedactionRulesetHash
  ) {
    throw new Error("canonicalization.redaction_ruleset_hash is invalid");
  }
}

function validateCrit(value: unknown, payloadKind: string): void {
  const crit = requireStringArray(value, "crit");
  const seen = new Set<string>();
  let hasCanonicalization = false;
  let hasSourceSpans = false;
  for (const name of crit) {
    if (name === "") throw new Error("crit has an empty name");
    if (seen.has(name)) throw new Error(`crit has duplicate ${name}`);
    seen.add(name);
    if (name === critCanonicalization) {
      hasCanonicalization = true;
    } else if (name === critSourceSpans) {
      hasSourceSpans = true;
    } else {
      throw new Error(`crit has unknown field ${name}`);
    }
  }
  if (!hasCanonicalization) throw new Error("crit must include canonicalization");
  if (payloadKind === "proxy_decision_with_spans" && !hasSourceSpans) {
    throw new Error("crit must include source_spans");
  }
  if (payloadKind !== "proxy_decision_with_spans" && hasSourceSpans) {
    throw new Error(`crit source_spans is invalid for ${payloadKind}`);
  }
}

function requireSHA256Digest(value: unknown, name: string): void {
  const digest = requireString(value, name);
  if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) throw new Error(`${name} must be sha256:<64 hex>`);
}

function requireHMACMatchHash(value: unknown, name: string): void {
  const digest = requireString(value, name);
  if (!/^hmac-sha256:[0-9a-f]{64}$/u.test(digest)) {
    throw new Error(`${name} must be hmac-sha256:<64 hex>`);
  }
}

function requireTransformProfile(value: unknown, name: string): void {
  const profile = requireString(value, name);
  if (!/^pipelock-transform-v[0-9]+$/u.test(profile)) {
    throw new Error(`${name} must be pipelock-transform-vN`);
  }
}

function validNormalizedView(view: string): boolean {
  const prefix = "dlp_normalized:";
  return normalizedViews.has(view) || (view.startsWith(prefix) && view.length > prefix.length);
}

function offsetsAllowedForView(view: string): boolean {
  return (
    view === "sanitized_target" || view === "dlp_normalized" || view.startsWith("dlp_normalized:")
  );
}

function validateProxyDecisionBase(payload: JSONObject): void {
  requireString(payload["action_type"], "action_type");
  requireString(payload["target"], "target");
  requireString(payload["verdict"], "verdict");
  requireString(payload["transport"], "transport");
  requireStringArray(payload["policy_sources"], "policy_sources");
  requireString(payload["winning_source"], "winning_source");
}

function validateProxyDecisionPayload(payload: JSONObject): void {
  rejectUnknownFields(payload, proxyDecisionFields, "payload");
  validateProxyDecisionBase(payload);
}

function validateSourceSpan(spanValue: unknown, index: number): void {
  const span = requireObject(spanValue, `source_spans[${index}]`);
  rejectUnknownFields(span, sourceSpanFields, `source_spans[${index}]`);
  const sourceKind = requireString(span["source_kind"], `source_spans[${index}].source_kind`);
  if (!sourceKinds.has(sourceKind))
    throw new Error(`source_spans[${index}].source_kind is invalid`);
  const normalizedView = requireString(
    span["normalized_view"],
    `source_spans[${index}].normalized_view`,
  );
  if (!validNormalizedView(normalizedView)) {
    throw new Error(`source_spans[${index}].normalized_view is invalid`);
  }
  requireString(span["source_id"], `source_spans[${index}].source_id`);
  requireSHA256Digest(
    span["pipelock_binary_digest"],
    `source_spans[${index}].pipelock_binary_digest`,
  );
  requireSHA256Digest(span["rules_bundle_digest"], `source_spans[${index}].rules_bundle_digest`);
  requireTransformProfile(span["transform_profile"], `source_spans[${index}].transform_profile`);
  requireSHA256Digest(span["policy_hash"], `source_spans[${index}].policy_hash`);
  requireString(span["rule_id"], `source_spans[${index}].rule_id`);
  requireHMACMatchHash(span["match_hash"], `source_spans[${index}].match_hash`);
  if (
    requireString(span["match_hash_alg"], `source_spans[${index}].match_hash_alg`) !== "hmac-sha256"
  ) {
    throw new Error(`source_spans[${index}].match_hash_alg is invalid`);
  }
  requireString(span["match_class"], `source_spans[${index}].match_class`);
  const hasOffset = Object.prototype.hasOwnProperty.call(span, "char_offset");
  const hasLength = Object.prototype.hasOwnProperty.call(span, "char_length");
  if (hasOffset !== hasLength)
    throw new Error(`source_spans[${index}] must pair char_offset and char_length`);
  if (hasOffset) {
    requireNumber(span["char_offset"], `source_spans[${index}].char_offset`);
    const length = requireNumber(span["char_length"], `source_spans[${index}].char_length`);
    if (length <= 0) throw new Error(`source_spans[${index}].char_length must be positive`);
    if (!offsetsAllowedForView(normalizedView)) {
      throw new Error(`source_spans[${index}].char_offset not allowed for normalized_view`);
    }
  }
}

function validateProxyDecisionWithSpansPayload(payload: JSONObject): void {
  rejectUnknownFields(payload, proxyDecisionWithSpansFields, "payload");
  validateProxyDecisionBase(payload);
  const spans = payload["source_spans"];
  if (!Array.isArray(spans) || spans.length === 0) throw new Error("source_spans is required");
  spans.forEach(validateSourceSpan);
}

export function normalizeEvidenceReceipt(receipt: Receipt): Receipt {
  rejectUnknownFields(receipt as Record<string, unknown>, envelopeFields, "receipt");
  if (receipt.record_type !== v2RecordType)
    throw new Error(`unsupported record_type ${String(receipt.record_type)}`);
  if (receipt.receipt_version !== v2ReceiptVersion) {
    throw new Error(`unsupported receipt_version ${String(receipt.receipt_version)} (expected 2)`);
  }
  const payloadKind = requireString(receipt.payload_kind, "payload_kind");
  if (reservedV2PayloadKinds.has(payloadKind)) {
    throw new Error(`payload_kind ${payloadKind} is known but not implemented`);
  }
  if (!v2PayloadKinds.has(payloadKind)) throw new Error(`unknown payload_kind ${payloadKind}`);
  validateCanonicalization(receipt.canonicalization);
  validateCrit(receipt.crit, payloadKind);
  requireString(receipt.event_id, "event_id");
  requireString(receipt.timestamp, "timestamp");
  requireNumber(receipt.chain_seq, "chain_seq");
  requireString(receipt.chain_prev_hash, "chain_prev_hash");
  requireSHA256Digest(receipt.policy_hash, "policy_hash");
  const signature = requireObject(receipt.signature, "signature");
  rejectUnknownFields(signature, signatureFields, "signature");
  requireString(signature["signer_key_id"], "signature.signer_key_id");
  const purpose = requireString(signature["key_purpose"], "signature.key_purpose");
  if (purpose !== v2RequiredSignaturePurpose) {
    throw new Error(`signature.key_purpose ${purpose} is not authorized for ${payloadKind}`);
  }
  if (requireString(signature["algorithm"], "signature.algorithm") !== v2SignatureAlgorithm) {
    throw new Error("signature.algorithm is invalid");
  }
  const sig = requireString(signature["signature"], "signature.signature");
  if (!/^ed25519:[0-9a-f]{128}$/u.test(sig)) {
    throw new Error("signature.signature must be ed25519:<128 hex>");
  }
  const payload = requireObject(receipt.payload, "payload");
  if (payloadKind === "proxy_decision") validateProxyDecisionPayload(payload);
  if (payloadKind === "proxy_decision_with_spans") validateProxyDecisionWithSpansPayload(payload);
  return receipt;
}

function evidencePreimage(receipt: Receipt): Buffer {
  const clone = {
    ...(receipt as JSONObject),
    signature: {
      signer_key_id: "",
      key_purpose: "",
      algorithm: "",
      signature: "",
    },
  };
  return canonicalizeBytes(clone);
}

export function validateActionRecord(actionRecord: ActionRecord | undefined): ActionRecord {
  if (!actionRecord || typeof actionRecord !== "object")
    throw new Error("action_record is required");
  if (actionRecord.version !== 1) {
    throw new Error(
      `unsupported action record version ${String(actionRecord.version)} (expected 1)`,
    );
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

export interface VerifyReceiptOptions {
  allowUnpinned?: boolean;
}

export async function verifyReceipt(
  receipt: Receipt,
  expectedKeyHex = "",
  options: VerifyReceiptOptions = {},
): Promise<void> {
  if (receipt.record_type === v2RecordType) {
    return verifyEvidenceReceipt(receipt, expectedKeyHex);
  }
  normalizeReceipt(receipt);
  const signerKey = (receipt.signer_key ?? "").toLowerCase();
  const expected = expectedKeyHex.toLowerCase();
  if (expected === "" && options.allowUnpinned !== true) {
    throw new Error(unpinnedReceiptBanner);
  }
  const keyHex = expected === "" ? signerKey : expected;
  if (expected !== "" && signerKey !== expected) {
    throw new Error(`signer_key ${signerKey} does not match expected key ${expected}`);
  }

  const pubKey = decodeHex(keyHex, 32, "signer_key");
  const signature = String(receipt.signature ?? "");
  if (!signature.startsWith(signaturePrefix)) {
    throw new Error(`invalid signature format: missing ${signaturePrefix} prefix`);
  }
  const sig = decodeHex(signature.slice(signaturePrefix.length), 64, "signature");
  const digest = createHash("sha256")
    .update(canonicalizeActionRecord(receipt.action_record as ActionRecord))
    .digest();
  const ok = await ed25519.verifyAsync(sig, digest, pubKey, { zip215: false });
  if (!ok) throw new Error("signature verification failed");
}

export async function verifyEvidenceReceipt(receipt: Receipt, expectedKeyHex = ""): Promise<void> {
  normalizeEvidenceReceipt(receipt);
  const signature = receipt.signature as JSONObject;
  const keyHex = expectedKeyHex.toLowerCase();
  if (keyHex === "") throw new Error("EvidenceReceipt v2 verification requires --key");
  const pubKey = decodeHex(keyHex, 32, "signer_key_id");
  const sig = decodeHex(
    String(signature["signature"]).slice(signaturePrefix.length),
    64,
    "signature",
  );
  const ok = await ed25519.verifyAsync(sig, evidencePreimage(receipt), pubKey, { zip215: false });
  if (!ok) throw new Error("signature verification failed");
}

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import * as path from "node:path";
import * as ed25519 from "@noble/ed25519";
import { parseJSONStrict, RawNumber } from "./aarp/strictjson.js";
import { receiptHash, verifyChain } from "./chain.js";
import type { ChainResult, Receipt } from "./types.js";
import { decodeHex, InvalidError, RuntimeError } from "./util.js";

const endorsementVersion = 1;
const endorsementDomain = "pipelock-rotation-endorsement-v1\u0000";
const signaturePrefix = "ed25519:";
const endorsementFields = new Set([
  "version",
  "session_id",
  "prior_signer_key",
  "prior_final_seq",
  "prior_tail_hash",
  "new_signer_key",
  "rotated_at",
  "endorsement",
]);

export interface RotationEndorsement {
  version: number;
  session_id: string;
  prior_signer_key: string;
  prior_final_seq: number;
  prior_tail_hash: string;
  new_signer_key: string;
  rotated_at: string;
  endorsement: string;
}

export interface EndorsedChainOptions {
  sessionID: string;
  endorsements: RotationEndorsement[];
}

function broken(base: ChainResult, message: string): ChainResult {
  return { ...base, valid: false, error: message };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function materializeStrictJSON(value: unknown): unknown {
  if (value instanceof RawNumber) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(value.literal)) {
      throw new InvalidError("rotation endorsement numbers must be non-negative integers");
    }
    const parsed = Number(value.literal);
    if (!Number.isSafeInteger(parsed)) {
      throw new InvalidError("rotation endorsement integer exceeds the safe range");
    }
    return parsed;
  }
  if (Array.isArray(value)) return value.map(materializeStrictJSON);
  if (isObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, materializeStrictJSON(child)]),
    );
  }
  return value;
}

function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function requireCanonicalString(value: unknown, field: string): string {
  if (typeof value !== "string" || value === "" || hasLoneSurrogate(value)) {
    throw new InvalidError(`rotation endorsement ${field} is invalid`);
  }
  return value;
}

function requireHex(value: unknown, bytes: number, field: string): string {
  const text = requireCanonicalString(value, field);
  if (text !== text.toLowerCase() || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "u").test(text)) {
    throw new InvalidError(`rotation endorsement ${field} is invalid`);
  }
  return text;
}

function requireCanonicalTimestamp(value: unknown): string {
  const text = requireCanonicalString(value, "rotated_at");
  const match =
    /^(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?<time>[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.(?<fraction>[0-9]{0,8}[1-9]))?Z$/u.exec(
      text,
    );
  if (
    match === null ||
    !validDateTime(match.groups?.["date"] ?? "", match.groups?.["time"] ?? "")
  ) {
    throw new InvalidError("rotation endorsement rotated_at must be canonical UTC RFC3339Nano");
  }
  return text;
}

function validDateTime(date: string, time: string): boolean {
  const [year, month, day] = date.split("-").map(Number);
  const [hour, minute, second] = time.split(":").map(Number);
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined ||
    month < 1 ||
    month > 12 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false;
  }
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= (days[month - 1] ?? 0);
}

function normalizeEndorsement(value: unknown): RotationEndorsement {
  if (!isObject(value)) throw new InvalidError("rotation endorsement must be a JSON object");
  for (const key of Object.keys(value)) {
    if (!endorsementFields.has(key)) {
      throw new InvalidError(`rotation endorsement contains unknown field ${key}`);
    }
  }
  if (Object.keys(value).length !== endorsementFields.size) {
    throw new InvalidError("rotation endorsement is missing a required field");
  }
  if (value["version"] !== endorsementVersion) {
    throw new InvalidError(`unsupported rotation endorsement version ${String(value["version"])}`);
  }
  const sessionID = requireCanonicalString(value["session_id"], "session_id");
  if (sessionID.trim() === "") throw new InvalidError("rotation endorsement session_id is empty");
  const priorSignerKey = requireHex(value["prior_signer_key"], 32, "prior_signer_key");
  const newSignerKey = requireHex(value["new_signer_key"], 32, "new_signer_key");
  if (priorSignerKey === newSignerKey) {
    throw new InvalidError("rotation endorsement successor key must differ from prior key");
  }
  if (!Number.isSafeInteger(value["prior_final_seq"]) || (value["prior_final_seq"] as number) < 0) {
    throw new InvalidError("rotation endorsement prior_final_seq is invalid");
  }
  return {
    version: endorsementVersion,
    session_id: sessionID,
    prior_signer_key: priorSignerKey,
    prior_final_seq: value["prior_final_seq"] as number,
    prior_tail_hash: requireHex(value["prior_tail_hash"], 32, "prior_tail_hash"),
    new_signer_key: newSignerKey,
    rotated_at: requireCanonicalTimestamp(value["rotated_at"]),
    endorsement: requireCanonicalString(value["endorsement"], "signature"),
  };
}

function goHTMLEscape(serialized: string): string {
  return serialized
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function endorsementDigest(endorsement: RotationEndorsement): Buffer {
  const canonical = {
    version: endorsement.version,
    session_id: endorsement.session_id,
    prior_signer_key: endorsement.prior_signer_key,
    prior_final_seq: endorsement.prior_final_seq,
    prior_tail_hash: endorsement.prior_tail_hash,
    new_signer_key: endorsement.new_signer_key,
    rotated_at: endorsement.rotated_at,
  };
  return createHash("sha256")
    .update(Buffer.from(endorsementDomain, "utf8"))
    .update(Buffer.from(goHTMLEscape(JSON.stringify(canonical)), "utf8"))
    .digest();
}

export async function verifyRotationEndorsement(
  value: RotationEndorsement,
): Promise<RotationEndorsement> {
  const endorsement = normalizeEndorsement(value);
  if (!endorsement.endorsement.startsWith(signaturePrefix)) {
    throw new InvalidError(
      `invalid endorsement signature format: missing ${signaturePrefix} prefix`,
    );
  }
  const signature = decodeHex(
    endorsement.endorsement.slice(signaturePrefix.length),
    64,
    "endorsement",
  );
  const publicKey = decodeHex(endorsement.prior_signer_key, 32, "prior_signer_key");
  const valid = await ed25519.verifyAsync(signature, endorsementDigest(endorsement), publicKey, {
    zip215: false,
  });
  if (!valid) throw new InvalidError("rotation endorsement signature verification failed");
  return endorsement;
}

export async function loadRotationEndorsementFile(file: string): Promise<RotationEndorsement> {
  const normalized = path.normalize(file);
  let descriptor: number;
  try {
    descriptor = openSync(normalized, constants.O_RDONLY | constants.O_NONBLOCK);
  } catch (err) {
    throw new RuntimeError(`read ${file}: ${(err as Error).message}`);
  }
  let text: string;
  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new InvalidError("rotation endorsement must be a regular file");
    }
    const data = Buffer.allocUnsafe(64 * 1024 + 1);
    let total = 0;
    while (total < data.length) {
      const count = readSync(descriptor, data, total, data.length - total, null);
      if (count === 0) break;
      total += count;
    }
    if (total > 64 * 1024) {
      throw new InvalidError("rotation endorsement exceeds 65536 bytes");
    }
    const bytes = data.subarray(0, total);
    text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes)) {
      throw new InvalidError("rotation endorsement is not valid UTF-8");
    }
  } catch (err) {
    if (err instanceof InvalidError) throw err;
    throw new RuntimeError(`read ${file}: ${(err as Error).message}`);
  } finally {
    closeSync(descriptor);
  }
  try {
    const parsed = materializeStrictJSON(parseJSONStrict(text));
    return await verifyRotationEndorsement(parsed as RotationEndorsement);
  } catch (err) {
    if (err instanceof InvalidError) throw err;
    throw new InvalidError((err as Error).message);
  }
}

function sessionOpen(receipt: Receipt): Record<string, unknown> | undefined {
  const control = receipt.action_record?.["session_control"];
  if (!isObject(control) || control["kind"] !== "session_open" || !isObject(control["open"])) {
    return undefined;
  }
  return control["open"];
}

function verifySignedRecorderSession(sessionID: string, receipts: Receipt[]): string | undefined {
  const firstBoundary = receipts.findIndex(
    (receipt, index) => index > 0 && receipt.action_record?.key_transition !== undefined,
  );
  const boundaryIndex = firstBoundary < 0 ? receipts.length : firstBoundary;
  let rootOpenFound = false;
  for (let index = 0; index < receipts.length; index++) {
    const open = sessionOpen(receipts[index] as Receipt);
    if (open === undefined) continue;
    if (open["recorder_session"] !== sessionID) {
      return `signed recorder session ${String(open["recorder_session"])} does not match endorsement session ${sessionID}`;
    }
    if (index < boundaryIndex) rootOpenFound = true;
  }
  return rootOpenFound
    ? undefined
    : "root receipt segment has no signed session_open recorder binding";
}

export async function verifyChainWithEndorsements(
  receipts: Receipt[],
  rootKeyHex: string,
  options: EndorsedChainOptions,
): Promise<ChainResult> {
  if (options.sessionID.trim() === "") {
    return broken(
      { valid: false, receipt_count: receipts.length, final_seq: 0, root_hash: "" },
      "rotation endorsement verification requires a recorder session ID",
    );
  }
  if (receipts.length === 0) {
    return broken(
      { valid: false, receipt_count: 0, final_seq: 0, root_hash: "" },
      options.endorsements.length === 0
        ? "empty chain"
        : "rotation endorsements supplied for an empty receipt chain",
    );
  }
  let authorizedSigner = receipts[0]?.signer_key?.toLowerCase() ?? "";
  for (let index = 1; index < receipts.length; index++) {
    const receipt = receipts[index] as Receipt;
    const signer = receipt.signer_key?.toLowerCase() ?? "";
    const transition = receipt.action_record?.key_transition !== undefined;
    if (!transition && signer !== authorizedSigner) {
      return broken(
        { valid: false, receipt_count: receipts.length, final_seq: 0, root_hash: "" },
        "signer key changed without a key_transition boundary",
      );
    }
    if (transition) authorizedSigner = signer;
  }
  const allKeys = [
    ...new Set(
      receipts
        .map((receipt) => receipt.signer_key?.toLowerCase() ?? "")
        .filter((key) => key !== ""),
    ),
  ];
  const base = await verifyChain(receipts, allKeys.join(","));
  if (!base.valid) return base;
  const roots = new Set(
    rootKeyHex
      .split(",")
      .map((key) => key.trim().toLowerCase())
      .filter((key) => key !== ""),
  );
  if (roots.size === 0) {
    return broken(base, "rotation endorsement verification requires at least one trusted root key");
  }
  const firstKey = receipts[0]?.signer_key?.toLowerCase() ?? "";
  if (!roots.has(firstKey))
    return broken(base, "genesis signer key is not in the trusted root set");
  const sessionError = verifySignedRecorderSession(options.sessionID, receipts);
  if (sessionError !== undefined) return broken(base, sessionError);

  const endorsements: RotationEndorsement[] = [];
  for (const candidate of options.endorsements) {
    try {
      endorsements.push(await verifyRotationEndorsement(candidate));
    } catch (err) {
      return broken(base, (err as Error).message);
    }
  }
  const used = new Set<number>();
  for (let index = 1; index < receipts.length; index++) {
    const boundary = receipts[index] as Receipt;
    if (boundary.action_record?.key_transition === undefined) continue;
    const prior = receipts[index - 1] as Receipt;
    const successor = boundary.signer_key?.toLowerCase() ?? "";
    const matches = endorsements
      .map((endorsement, endorsementIndex) => ({ endorsement, endorsementIndex }))
      .filter(
        ({ endorsement, endorsementIndex }) =>
          !used.has(endorsementIndex) &&
          endorsement.session_id === options.sessionID &&
          endorsement.prior_signer_key === (prior.signer_key?.toLowerCase() ?? "") &&
          endorsement.prior_final_seq === prior.action_record?.chain_seq &&
          endorsement.prior_tail_hash === receiptHash(prior) &&
          endorsement.new_signer_key === successor,
      );
    if (matches.length > 1) {
      return broken(base, "multiple rotation endorsements match one receipt boundary");
    }
    if (matches.length === 0) {
      return broken(base, "rotation endorsement does not match receipt boundary");
    }
    used.add((matches[0] as { endorsementIndex: number }).endorsementIndex);
  }
  if (used.size !== endorsements.length) {
    return broken(base, "unused rotation endorsement does not match a required boundary");
  }
  return base;
}

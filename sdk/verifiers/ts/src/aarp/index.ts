// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// AARP verifier entry points: the unmarshal pipeline (strict parse → safe-number
// guard → typed decode) and trust-file loading, ported from
// internal/aarp/envelope.go (Unmarshal) and cmd/pipelock-verifier/aarp.go
// (loadTrustFile). The CLI subcommand composes these.

import { readFileSync } from "node:fs";
import { Appraisal, TrustEntry, VerifyOptions, comparableAppraisal, verify } from "./appraise.js";
import { comparableChain, verifyChain } from "./chain.js";
import { Envelope, decodeEnvelope } from "./envelope.js";
import { enforceSafeNumbers } from "./numbers.js";
import { parseJSONStrict } from "./strictjson.js";

// unmarshal parses an AARP envelope from JSON bytes, rejecting duplicate keys,
// trailing tokens, unsafe numbers, and unknown fields. Any failure is
// envelope-fatal (the thrown error carries code 1).
export function unmarshal(text: string): Envelope {
  const tree = parseJSONStrict(text);
  // Reject any raw JSON number outside the I-JSON safe range anywhere in the
  // envelope before decoding into typed structures.
  enforceSafeNumbers(tree);
  return decodeEnvelope(tree);
}

export { verify, comparableAppraisal, comparableChain, verifyChain };
export type { Envelope, Appraisal, VerifyOptions };

// emptyTrust returns a VerifyOptions with no trusted keys: every signature is
// reported unknown_key. Used when --trust is absent.
export function emptyTrust(): VerifyOptions {
  return { trustedKeys: new Map(), trust: new Map() };
}

interface TrustFileShape {
  trusted_keys?: Record<string, string>;
  trust_entries?: Record<string, { mediator_id?: string; role?: string; trust_domain?: string }>;
}

// TrustFileError marks an I/O or trust-file parse error (CLI exit code 2).
export class TrustFileError extends Error {
  readonly code = 2;
}

// loadTrustFile reads the pinned trust JSON into VerifyOptions. A missing path
// yields empty trust so the verifier still runs the no-trust path.
export function loadTrustFile(path: string): VerifyOptions {
  if (path === "") return emptyTrust();
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new TrustFileError(`read trust file: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new TrustFileError(`parse trust file: ${(err as Error).message}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new TrustFileError("trust file must be a JSON object");
  }
  const tf = parsed as TrustFileShape;
  const allowed = new Set(["trusted_keys", "trust_entries"]);
  for (const key of Object.keys(tf)) {
    if (!allowed.has(key)) throw new TrustFileError(`unknown field in trust file: ${key}`);
  }

  const trustedKeys = new Map<string, Uint8Array>();
  for (const [keyID, keyHex] of Object.entries(tf.trusted_keys ?? {})) {
    if (typeof keyHex !== "string" || !/^[0-9a-fA-F]+$/u.test(keyHex)) {
      throw new TrustFileError(`trusted_keys[${keyID}]: not hex`);
    }
    const buf = Buffer.from(keyHex, "hex");
    if (buf.length !== 32) {
      throw new TrustFileError(`trusted_keys[${keyID}]: ${buf.length} bytes, want 32`);
    }
    trustedKeys.set(keyID, Uint8Array.from(buf));
  }

  const trust = new Map<string, TrustEntry>();
  for (const [keyID, entry] of Object.entries(tf.trust_entries ?? {})) {
    const te: TrustEntry = { mediator_id: entry.mediator_id ?? "" };
    if (entry.role !== undefined) te.role = entry.role;
    if (entry.trust_domain !== undefined) te.trust_domain = entry.trust_domain;
    trust.set(keyID, te);
  }

  return { trustedKeys, trust };
}

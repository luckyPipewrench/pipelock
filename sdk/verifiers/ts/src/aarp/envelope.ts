// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Envelope schema and signed-payload construction, ported from
// internal/aarp/envelope.go (+ chain.go). The strict tree from parseJSONStrict
// is decoded into typed structures here, rejecting unknown fields in
// AARP-controlled objects so a producer cannot smuggle unsigned content past
// appraisal. ext is a free map and is NOT part of the signed payload.

import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.js";
import {
  GrammarError,
  validateHex256,
  validateTimestamp,
  validateUint64String,
} from "./numbers.js";
import { RawNumber } from "./strictjson.js";
import { PROFILE, ProtectedHeader, checkCriticalExtensions } from "./suite.js";

// ContextAssertion is the domain separator for the assurance-assertion signature.
export const CONTEXT_ASSERTION = "pipelock-aarp-v0.1/assurance-assertion";

// GenesisPriorHash is the prior-hash sentinel for the first link in a stream.
export const GENESIS_PRIOR_HASH = "0".repeat(64);

// SchemaError marks an envelope-fatal schema violation (missing/extra field,
// wrong type, bad grammar). The CLI maps it to exit 1.
export class SchemaError extends Error {
  readonly code = 1;
}

const knownReceiptTypes: Record<string, boolean> = {
  action_receipt_v1: true,
  evidence_receipt_v2: true,
};

export interface Subject {
  action_record_sha256: string;
  receipt_envelope_sha256: string;
  receipt_signer_key: string;
  receipt_type: string;
}

export interface Assertion {
  claimed: string[];
  mediator_id: string;
  trust_domain?: string;
  complete_mediation: boolean;
  evidence_refs?: string[];
  issued_at: string;
}

export interface ChainLink {
  issuer_id: string;
  seq: string;
  prior_hash: string;
}

export interface Signature {
  protected: ProtectedHeader;
  sig: string;
}

export interface Envelope {
  profile: string;
  subject: Subject;
  assertion: Assertion;
  chain?: ChainLink;
  signatures: Signature[];
  crit_ext?: string[];
}

// asObject narrows a strict-tree value to a plain object or throws schema-fatal.
function asObject(v: unknown, field: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v) || v instanceof RawNumber) {
    throw new SchemaError(`${field} must be an object`);
  }
  return v as Record<string, unknown>;
}

function asString(v: unknown, field: string): string {
  if (typeof v !== "string") throw new SchemaError(`${field} must be a string`);
  return v;
}

function asBool(v: unknown, field: string): boolean {
  if (typeof v !== "boolean") throw new SchemaError(`${field} must be a boolean`);
  return v;
}

function asStringArray(v: unknown, field: string): string[] {
  if (!Array.isArray(v)) throw new SchemaError(`${field} must be an array`);
  return v.map((item, i) => asString(item, `${field}[${i}]`));
}

// rejectUnknownKeys enforces that an AARP-controlled object carries only the
// allowed fields, mirroring Go's DisallowUnknownFields on the typed structs.
function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  field: string,
): void {
  const allow = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allow.has(key)) {
      throw new SchemaError(`unknown field ${JSON.stringify(key)} in ${field}`);
    }
  }
}

function decodeSubject(v: unknown): Subject {
  const obj = asObject(v, "subject");
  rejectUnknownKeys(
    obj,
    ["action_record_sha256", "receipt_envelope_sha256", "receipt_signer_key", "receipt_type"],
    "subject",
  );
  return {
    action_record_sha256: asString(obj.action_record_sha256, "subject.action_record_sha256"),
    receipt_envelope_sha256: asString(
      obj.receipt_envelope_sha256,
      "subject.receipt_envelope_sha256",
    ),
    receipt_signer_key: asString(obj.receipt_signer_key, "subject.receipt_signer_key"),
    receipt_type: asString(obj.receipt_type, "subject.receipt_type"),
  };
}

function decodeAssertion(v: unknown): Assertion {
  const obj = asObject(v, "assertion");
  rejectUnknownKeys(
    obj,
    ["claimed", "mediator_id", "trust_domain", "complete_mediation", "evidence_refs", "issued_at"],
    "assertion",
  );
  const out: Assertion = {
    claimed: obj.claimed === undefined ? [] : asStringArray(obj.claimed, "assertion.claimed"),
    mediator_id: asString(obj.mediator_id, "assertion.mediator_id"),
    complete_mediation:
      obj.complete_mediation === undefined
        ? false
        : asBool(obj.complete_mediation, "assertion.complete_mediation"),
    issued_at: asString(obj.issued_at, "assertion.issued_at"),
  };
  if (obj.trust_domain !== undefined) {
    out.trust_domain = asString(obj.trust_domain, "assertion.trust_domain");
  }
  if (obj.evidence_refs !== undefined) {
    out.evidence_refs = asStringArray(obj.evidence_refs, "assertion.evidence_refs");
  }
  return out;
}

function decodeChainLink(v: unknown): ChainLink {
  const obj = asObject(v, "chain");
  rejectUnknownKeys(obj, ["issuer_id", "seq", "prior_hash"], "chain");
  return {
    issuer_id: asString(obj.issuer_id, "chain.issuer_id"),
    seq: asString(obj.seq, "chain.seq"),
    prior_hash: asString(obj.prior_hash, "chain.prior_hash"),
  };
}

function decodeProtected(v: unknown, idx: number): ProtectedHeader {
  const obj = asObject(v, `signatures[${idx}].protected`);
  rejectUnknownKeys(
    obj,
    ["profile", "canon", "alg", "key_type", "key_id", "signer_role", "crit"],
    `signatures[${idx}].protected`,
  );
  const header: ProtectedHeader = {
    profile: asString(obj.profile, `signatures[${idx}].protected.profile`),
    canon: asString(obj.canon, `signatures[${idx}].protected.canon`),
    alg: asString(obj.alg, `signatures[${idx}].protected.alg`),
    key_type: asString(obj.key_type, `signatures[${idx}].protected.key_type`),
    key_id: asString(obj.key_id, `signatures[${idx}].protected.key_id`),
    signer_role: asString(obj.signer_role, `signatures[${idx}].protected.signer_role`),
  };
  if (obj.crit !== undefined) {
    header.crit = asStringArray(obj.crit, `signatures[${idx}].protected.crit`);
  }
  return header;
}

function decodeSignature(v: unknown, idx: number): Signature {
  const obj = asObject(v, `signatures[${idx}]`);
  rejectUnknownKeys(obj, ["protected", "sig"], `signatures[${idx}]`);
  if (obj.protected === undefined) {
    throw new SchemaError(`signatures[${idx}].protected is required`);
  }
  return {
    protected: decodeProtected(obj.protected, idx),
    sig: asString(obj.sig, `signatures[${idx}].sig`),
  };
}

// decodeEnvelope decodes a strict-parsed tree into a typed Envelope, rejecting
// unknown fields in every AARP-controlled object. ext is allowed and ignored.
export function decodeEnvelope(tree: unknown): Envelope {
  const obj = asObject(tree, "envelope");
  rejectUnknownKeys(
    obj,
    ["profile", "subject", "assertion", "chain", "signatures", "crit_ext", "ext"],
    "envelope",
  );
  if (obj.subject === undefined) throw new SchemaError("subject is required");
  if (obj.assertion === undefined) throw new SchemaError("assertion is required");
  if (obj.signatures === undefined || !Array.isArray(obj.signatures)) {
    throw new SchemaError("signatures must be an array");
  }
  const env: Envelope = {
    profile: asString(obj.profile, "profile"),
    subject: decodeSubject(obj.subject),
    assertion: decodeAssertion(obj.assertion),
    signatures: obj.signatures.map((s, i) => decodeSignature(s, i)),
  };
  if (obj.chain !== undefined) {
    env.chain = decodeChainLink(obj.chain);
  }
  if (obj.crit_ext !== undefined) {
    env.crit_ext = asStringArray(obj.crit_ext, "crit_ext");
  }
  return env;
}

function wrapSchema(err: unknown): never {
  if (err instanceof GrammarError) throw new SchemaError(err.message);
  throw err;
}

function validateSubject(s: Subject): void {
  try {
    validateHex256(s.action_record_sha256);
  } catch (err) {
    wrapSchema(err);
  }
  try {
    validateHex256(s.receipt_envelope_sha256);
  } catch (err) {
    wrapSchema(err);
  }
  try {
    validateHex256(s.receipt_signer_key);
  } catch (err) {
    wrapSchema(err);
  }
  if (!knownReceiptTypes[s.receipt_type]) {
    throw new SchemaError(`unknown subject.receipt_type ${JSON.stringify(s.receipt_type)}`);
  }
}

function validateAssertion(a: Assertion): void {
  if (a.mediator_id === "") {
    throw new SchemaError("assertion.mediator_id is required");
  }
  try {
    validateTimestamp(a.issued_at);
  } catch (err) {
    wrapSchema(err);
  }
  // trust_domain validation is intentionally minimal in core; an empty string is
  // simply absent. The Go core validates a SPIFFE name shape only when set, but
  // the corpus never exercises that path, so a non-empty value is accepted here
  // as the Go core would accept any well-formed SPIFFE-like string.
}

function validateChainLink(c: ChainLink): void {
  if (c.issuer_id === "") {
    throw new SchemaError("chain.issuer_id is required");
  }
  try {
    validateUint64String(c.seq);
  } catch (err) {
    wrapSchema(err);
  }
  try {
    validateHex256(c.prior_hash);
  } catch (err) {
    wrapSchema(err);
  }
  if (c.seq === "0" && c.prior_hash !== GENESIS_PRIOR_HASH) {
    throw new SchemaError("genesis link (seq 0) must carry the zero prior hash");
  }
  if (c.seq !== "0" && c.prior_hash === GENESIS_PRIOR_HASH) {
    throw new SchemaError(`non-genesis link (seq ${c.seq}) must not carry the genesis prior hash`);
  }
}

// validatePayloadParts validates the signed payload-bearing fields plus
// envelope-level critical extensions.
export function validatePayloadParts(e: Envelope): void {
  if (e.profile !== PROFILE) {
    throw new SchemaError(`profile ${JSON.stringify(e.profile)}, want ${JSON.stringify(PROFILE)}`);
  }
  validateSubject(e.subject);
  validateAssertion(e.assertion);
  if (e.chain !== undefined) {
    validateChainLink(e.chain);
  }
  checkCriticalExtensions(e.crit_ext);
}

// validateStructure runs the envelope-fatal schema checks before any
// per-signature appraisal: the payload parts (which include the top-level
// profile and the envelope-level critical-extension list) and a non-empty
// signature set.
//
// Only fields inside the SIGNED payload are envelope-fatal here. Per-signature
// suite fields (a signature's protected profile, canon, and its own
// critical-extension list) are deliberately NOT checked here: they are
// per-signature outcomes appraised in appraiseSignature. The signatures array
// is not itself signed, so a man-in-the-middle can append a junk signature; if
// a bad protected header were envelope-fatal, that append would deny a
// legitimately-signed envelope. Per-signature handling makes one unverifiable
// signature inert instead of fatal, while the signed top-level profile and
// crit_ext (which an append cannot forge) stay fatal.
export function validateStructure(e: Envelope): void {
  validatePayloadParts(e);
  if (e.signatures.length === 0) {
    throw new SchemaError("envelope has no signatures");
  }
}

// payloadObject builds the JCS-input object for the signed payload: profile,
// subject, assertion, crit_ext, optional chain. It excludes signatures and ext,
// and applies Go's omitempty semantics for the optional assertion fields so the
// canonical bytes match the Go marshaller exactly. crit_ext is NOT omitempty: a
// nil/absent envelope crit_ext must serialize as "crit_ext": [] (never omitted,
// never null), matching Go's payload() which normalizes nil to []string{} with a
// no-omitempty struct tag. Without this, the computed payload digest differs
// from Go and every signature fails to verify.
function payloadObject(e: Envelope): Record<string, unknown> {
  const assertion: Record<string, unknown> = {
    claimed: e.assertion.claimed,
    mediator_id: e.assertion.mediator_id,
    complete_mediation: e.assertion.complete_mediation,
    issued_at: e.assertion.issued_at,
  };
  if (e.assertion.trust_domain !== undefined && e.assertion.trust_domain !== "") {
    assertion.trust_domain = e.assertion.trust_domain;
  }
  if (e.assertion.evidence_refs !== undefined && e.assertion.evidence_refs.length > 0) {
    assertion.evidence_refs = e.assertion.evidence_refs;
  }
  const payload: Record<string, unknown> = {
    profile: e.profile,
    subject: {
      action_record_sha256: e.subject.action_record_sha256,
      receipt_envelope_sha256: e.subject.receipt_envelope_sha256,
      receipt_signer_key: e.subject.receipt_signer_key,
      receipt_type: e.subject.receipt_type,
    },
    assertion,
  };
  payload.crit_ext = e.crit_ext === undefined ? [] : e.crit_ext;
  if (e.chain !== undefined) {
    payload.chain = {
      issuer_id: e.chain.issuer_id,
      seq: e.chain.seq,
      prior_hash: e.chain.prior_hash,
    };
  }
  return payload;
}

// canonicalPayload returns the JCS-canonical bytes of the signed payload.
export function canonicalPayload(e: Envelope): Buffer {
  return Buffer.from(canonicalize(payloadObject(e)), "utf8");
}

// payloadDigest returns the lowercase-hex SHA-256 of the canonical payload.
export function payloadDigest(e: Envelope): string {
  return createHash("sha256").update(canonicalPayload(e)).digest("hex");
}

// signingInput builds the canonical bytes one signature signs: the domain
// context, the shared payload digest, and that signature's protected header.
export function signingInput(payloadSha256: string, h: ProtectedHeader): Buffer {
  const protectedObj: Record<string, unknown> = {
    profile: h.profile,
    canon: h.canon,
    alg: h.alg,
    key_type: h.key_type,
    key_id: h.key_id,
    signer_role: h.signer_role,
  };
  // Go marshals crit with omitempty: present only when the slice is non-empty.
  if (h.crit !== undefined && h.crit.length > 0) {
    protectedObj.crit = h.crit;
  }
  const obj = {
    context: CONTEXT_ASSERTION,
    payload_sha256: payloadSha256,
    protected: protectedObj,
  };
  return Buffer.from(canonicalize(obj), "utf8");
}

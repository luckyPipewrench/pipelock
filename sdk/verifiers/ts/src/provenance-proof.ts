// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Fixture-only evidence-provenance proof verifier. This deliberately verifies
// the experimental PR3 proof shape without registering a production receipt
// payload or changing the ordinary receipt verifier.

import { createHash, createHmac } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import { closeSync, openSync, readSync } from "node:fs";
import { RawNumber, parseJSONStrict } from "./aarp/strictjson.js";
import {
  EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
  applyEvidenceProvenanceRecipe,
  validateEvidenceProvenanceRecipe,
} from "./provenance.js";

export const provenanceFixtureFormat = "pipelock-evidence-provenance-verification-fixture/v1";
const proofVersion = "pipelock-evidence-provenance-proof/v1";
const profileDigest = EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST;
const knownFeature = "evidence_provenance";
const trustRoots = "fixture supplied; self-attested; not authenticated";
// These are fixture-wide limits, rather than per-entry limits. A chain can
// otherwise repeat a valid source or match list enough times to turn this
// fixture-only verifier into an unbounded work amplifier.
const maxFixtureSourceReferences = 128;
const maxFixtureMatchChecks = 4096;
const maxFixtureRecipeProcessingBytes = 64 << 20;
const maxFixtureBytes = 16 << 20;
const maxFixtureJSONDepth = 64;
const maxFixtureEntries = 32;
const maxVerificationSources = 32;
const maxProofSources = 32;
const maxMatchesPerSource = 1024;
const maxSignedBytes = 1 << 20;
const maxSourceBytes = 2 << 20;
const maxTotalSourceBytes = 16 << 20;
const maxArtifactBytes = 2 << 20;

type SignatureStage = "verified" | "invalid" | "not_checked";
type ChainStage = "verified" | "invalid" | "not_checked";
type ArtifactStage = "matched" | "mismatch" | "attested_unchecked" | "not_attested";
type OpenStage = "opened" | "mismatch" | "not_checked";
type ReproductionStage = "reproduced" | "mismatch" | "not_checked";
type LocationStage = "exact_coordinates" | "mismatch" | "not_checked";
type OverallStage = "verified" | "invalid" | "incomplete";
export type FailureStage =
  | "signature"
  | "chain"
  | "critical_features"
  | "proof_structure"
  | "artifacts"
  | "view_reproduction"
  | "location"
  | "view_commitment"
  | "match_commitment";

export interface ProvenanceReport {
  trust_roots: typeof trustRoots;
  authenticated_provenance: false;
  signature: SignatureStage;
  chain: ChainStage;
  artifacts: ArtifactStage;
  source_commitment: OpenStage;
  view_reproduction: ReproductionStage;
  location: LocationStage;
  match_commitment: OpenStage;
  overall: OverallStage;
  failure_stage?: FailureStage;
}

interface Operation {
  raw: Record<string, unknown>;
  kind: string;
  component: string;
  selector: string;
  occurrence: number;
  passes: number;
  profile: string;
  decode_padding: boolean;
  alphabet: string;
  indices: number[];
  minimum_length: number;
}

interface Match {
  match_ordinal: bigint;
  byte_start: bigint;
  byte_end: bigint;
  match_class: string;
  match_commitment: string;
}

interface Source {
  source_ordinal: bigint;
  source_id: string;
  recipe: { transform_profile_digest: string; operations: Operation[] };
  view_commitment: string;
  matches: Match[];
}

interface Proof {
  version: string;
  transform_profile_digest: string;
  sources: Source[];
  producer: { binary_digest?: string; ruleset_digest?: string };
}

interface SignedEntry {
  bytes: Buffer;
  signature: Buffer;
  chain_seq: bigint;
  chain_prev_hash: string;
  critical_features: string[];
  proof: Proof;
}

interface Fixture {
  entries: SignedEntry[];
  signer: Buffer;
  commitmentKey?: Buffer;
  sources: Map<string, string>;
  binaryB64?: string;
  rulesetB64?: string;
}

interface FixtureWork {
  sourceReferences: number;
  matchChecks: number;
}

class FixtureError extends Error {}

class FixtureWorkLimit extends Error {
  override name = "FixtureWorkLimit";
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof RawNumber
  ) {
    throw new FixtureError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new FixtureError(`${label}: unknown field ${key}`);
  }
  for (const key of keys) {
    if (!(key in value)) throw new FixtureError(`${label}: missing required field ${key}`);
  }
}

function knownKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new FixtureError(`${label}: unknown field ${key}`);
  }
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new FixtureError(`${label} must be a string`);
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return string(value, label);
}

function bool(value: unknown, label: string, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new FixtureError(`${label} must be a boolean`);
  return value;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new FixtureError(`${label} must be an array`);
  return value;
}

function uint(value: unknown, label: string, max = BigInt(Number.MAX_SAFE_INTEGER)): bigint {
  if (!(value instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(value.literal)) {
    throw new FixtureError(`${label} must be an unsigned integer`);
  }
  const parsed = BigInt(value.literal);
  if (parsed > max) throw new FixtureError(`${label} is out of range`);
  return parsed;
}

function numberValue(value: unknown, label: string, max: number): number {
  return Number(uint(value, label, BigInt(max)));
}

function utf8(bytes: Buffer, label: string): string {
  const decoded = new TextDecoder("utf-8", { fatal: true });
  try {
    return decoded.decode(bytes);
  } catch {
    throw new FixtureError(`${label}: invalid UTF-8`);
  }
}

function b64(value: unknown, label: string, maxBytes?: number): Buffer {
  const encoded = string(value, label);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) {
    throw new FixtureError(`${label} must be canonical base64`);
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded)
    throw new FixtureError(`${label} must be canonical base64`);
  if (maxBytes !== undefined && decoded.length > maxBytes)
    throw new FixtureError(`${label} exceeds byte limit`);
  return decoded;
}

function hex(value: unknown, label: string, length: number): Buffer {
  const encoded = string(value, label);
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`, "u").test(encoded)) {
    throw new FixtureError(`${label} must be ${length}-byte lowercase hex`);
  }
  return Buffer.from(encoded, "hex");
}

function digest(value: string, prefix: string, label: string): void {
  if (!new RegExp(`^${prefix}[0-9a-f]{64}$`, "u").test(value)) {
    throw new FixtureError(`${label} must be ${prefix}<64 lowercase hex>`);
  }
}

function parseOperation(value: unknown, index: number): Operation {
  const op = object(value, `recipe.operations[${index}]`);
  const allowed = new Set([
    "kind",
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
    "alphabet",
    "indices",
    "minimum_length",
  ]);
  for (const key of Object.keys(op))
    if (!allowed.has(key)) throw new FixtureError(`recipe operation: unknown field ${key}`);
  const operation: Operation = {
    raw: {},
    kind: string(op.kind, "recipe operation.kind"),
    component: optionalString(op.component, "recipe operation.component") ?? "",
    selector: optionalString(op.selector, "recipe operation.selector") ?? "",
    occurrence:
      op.occurrence === undefined
        ? 0
        : numberValue(op.occurrence, "recipe operation.occurrence", 0xffffffff),
    passes: op.passes === undefined ? 0 : numberValue(op.passes, "recipe operation.passes", 255),
    profile: optionalString(op.profile, "recipe operation.profile") ?? "",
    decode_padding: bool(op.decode_padding, "recipe operation.decode_padding"),
    alphabet: optionalString(op.alphabet, "recipe operation.alphabet") ?? "",
    indices:
      op.indices === undefined
        ? []
        : array(op.indices, "recipe operation.indices").map((value) =>
            numberValue(value, "recipe operation.index", 0xff),
          ),
    minimum_length:
      op.minimum_length === undefined
        ? 0
        : numberValue(op.minimum_length, "recipe operation.minimum_length", 0xffffffff),
  };
  operation.raw = { kind: operation.kind };
  for (const field of [
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
    "alphabet",
    "indices",
    "minimum_length",
  ] as const) {
    if (field in op) operation.raw[field] = operation[field];
  }
  return operation;
}

function parseProof(value: unknown, work: FixtureWork): Proof {
  const raw = object(value, "proof");
  exactKeys(raw, ["version", "transform_profile_digest", "sources", "producer"], "proof");
  const sourceValues = array(raw.sources, "proof.sources");
  if (sourceValues.length > maxProofSources) throw new FixtureError("proof exceeds source limit");
  const sources: Source[] = [];
  for (const [sourceIndex, item] of sourceValues.entries()) {
    work.sourceReferences += 1;
    if (work.sourceReferences > maxFixtureSourceReferences)
      throw new FixtureError("fixture exceeds source-reference limit");
    const source = object(item, `proof.sources[${sourceIndex}]`);
    exactKeys(
      source,
      ["source_ordinal", "source_id", "recipe", "view_commitment", "matches"],
      "proof source",
    );
    const recipe = object(source.recipe, "source recipe");
    exactKeys(recipe, ["transform_profile_digest", "operations"], "source recipe");
    const matchValues = array(source.matches, "source matches");
    if (matchValues.length > maxMatchesPerSource)
      throw new FixtureError("proof source exceeds match limit");
    work.matchChecks += matchValues.length;
    if (work.matchChecks > maxFixtureMatchChecks)
      throw new FixtureError("fixture exceeds match-check limit");
    const matches = matchValues.map((matchValue, matchIndex) => {
      const match = object(matchValue, `source match ${matchIndex}`);
      exactKeys(
        match,
        ["match_ordinal", "byte_start", "byte_end", "match_class", "match_commitment"],
        "source match",
      );
      return {
        match_ordinal: uint(match.match_ordinal, "match ordinal", (1n << 64n) - 1n),
        byte_start: uint(match.byte_start, "byte start", (1n << 64n) - 1n),
        byte_end: uint(match.byte_end, "byte end", (1n << 64n) - 1n),
        match_class: string(match.match_class, "match class"),
        match_commitment: string(match.match_commitment, "match commitment"),
      };
    });
    sources.push({
      source_ordinal: uint(source.source_ordinal, "source ordinal", (1n << 64n) - 1n),
      source_id: string(source.source_id, "source ID"),
      recipe: {
        transform_profile_digest: string(
          recipe.transform_profile_digest,
          "recipe transform profile digest",
        ),
        operations: array(recipe.operations, "recipe.operations").map(parseOperation),
      },
      view_commitment: string(source.view_commitment, "view commitment"),
      matches,
    });
  }
  const producerRaw = object(raw.producer, "proof.producer");
  const allowedProducer = new Set(["binary_digest", "ruleset_digest"]);
  for (const key of Object.keys(producerRaw))
    if (!allowedProducer.has(key)) throw new FixtureError(`proof.producer: unknown field ${key}`);
  return {
    version: string(raw.version, "proof.version"),
    transform_profile_digest: string(
      raw.transform_profile_digest,
      "proof.transform_profile_digest",
    ),
    sources,
    producer: {
      binary_digest: optionalString(producerRaw.binary_digest, "proof.producer.binary_digest"),
      ruleset_digest: optionalString(producerRaw.ruleset_digest, "proof.producer.ruleset_digest"),
    },
  };
}

function parseFixture(data: string): Fixture {
  if (Buffer.byteLength(data, "utf8") > maxFixtureBytes)
    throw new FixtureError("fixture exceeds byte limit");
  const root = object(parseJSONStrict(data, maxFixtureJSONDepth), "fixture");
  exactKeys(root, ["format", "entries", "verification"], "fixture");
  if (string(root.format, "format") !== provenanceFixtureFormat)
    throw new FixtureError("unsupported fixture format");
  const verification = object(root.verification, "verification");
  const verificationAllowed = new Set([
    "signer_public_key_hex",
    "commitment_key_hex",
    "sources",
    "binary_b64",
    "ruleset_b64",
  ]);
  for (const key of Object.keys(verification))
    if (!verificationAllowed.has(key)) throw new FixtureError(`verification: unknown field ${key}`);
  const signer = hex(verification.signer_public_key_hex, "verification.signer_public_key_hex", 32);
  const commitmentHex = optionalString(
    verification.commitment_key_hex,
    "verification.commitment_key_hex",
  );
  const commitmentKey =
    commitmentHex === undefined
      ? undefined
      : hex(commitmentHex, "verification.commitment_key_hex", 32);
  const sources = new Map<string, string>();
  let totalSourceBytes = 0;
  const sourceValues = array(verification.sources ?? [], "verification.sources");
  if (sourceValues.length > maxVerificationSources)
    throw new FixtureError("verification exceeds source limit");
  for (const value of sourceValues) {
    const source = object(value, "verification source");
    exactKeys(source, ["source_id", "bytes_b64"], "verification source");
    const id = string(source.source_id, "verification source_id");
    if (sources.has(id)) throw new FixtureError(`duplicate verification source ${id}`);
    const bytes = b64(source.bytes_b64, "verification source bytes_b64", maxSourceBytes);
    totalSourceBytes += bytes.length;
    if (totalSourceBytes > maxTotalSourceBytes)
      throw new FixtureError("verification sources exceed byte limit");
    sources.set(id, utf8(bytes, "verification source bytes"));
  }
  const work: FixtureWork = { sourceReferences: 0, matchChecks: 0 };
  const entryValues = array(root.entries, "entries");
  if (entryValues.length > maxFixtureEntries) throw new FixtureError("fixture exceeds entry limit");
  const entries = entryValues.map((value, index) => {
    const entry = object(value, `entries[${index}]`);
    exactKeys(entry, ["signed_b64", "signature"], "entry");
    const bytes = b64(entry.signed_b64, "entry.signed_b64", maxSignedBytes);
    const signed = object(
      parseJSONStrict(utf8(bytes, "signed_b64"), maxFixtureJSONDepth),
      "signed",
    );
    knownKeys(signed, ["chain_seq", "chain_prev_hash", "critical_features", "proof"], "signed");
    for (const key of ["chain_seq", "chain_prev_hash", "proof"]) {
      if (!(key in signed)) throw new FixtureError(`signed: missing required field ${key}`);
    }
    const signature = string(entry.signature, "entry.signature");
    if (!signature.startsWith("ed25519:"))
      throw new FixtureError("entry.signature must use ed25519 prefix");
    return {
      bytes,
      signature: hex(signature.slice("ed25519:".length), "entry.signature", 64),
      chain_seq: uint(signed.chain_seq, "signed.chain_seq", (1n << 64n) - 1n),
      chain_prev_hash: string(signed.chain_prev_hash, "signed.chain_prev_hash"),
      critical_features: array(signed.critical_features ?? [], "signed.critical_features").map(
        (feature, i) => string(feature, `signed.critical_features[${i}]`),
      ),
      proof: parseProof(signed.proof, work),
    };
  });
  if (entries.length === 0) throw new FixtureError("entries must not be empty");
  return {
    entries,
    signer,
    commitmentKey,
    sources,
    binaryB64: optionalString(verification.binary_b64, "verification.binary_b64"),
    rulesetB64: optionalString(verification.ruleset_b64, "verification.ruleset_b64"),
  };
}

function stage(failure?: FailureStage): ProvenanceReport {
  return {
    trust_roots: trustRoots,
    authenticated_provenance: false,
    signature: failure === "signature" ? "invalid" : "not_checked",
    chain: "not_checked",
    artifacts: "attested_unchecked",
    source_commitment: "not_checked",
    view_reproduction: "not_checked",
    location: "not_checked",
    match_commitment: "not_checked",
    overall: "invalid",
    ...(failure === undefined ? {} : { failure_stage: failure }),
  };
}

function invalid(failure: FailureStage, report: ProvenanceReport): ProvenanceReport {
  report.overall = "invalid";
  report.failure_stage = failure;
  return report;
}

function validateProofStructure(proof: Proof): void {
  if (proof.version !== proofVersion || proof.transform_profile_digest !== profileDigest) {
    throw new FixtureError("unsupported evidence provenance proof");
  }
  for (const value of [proof.producer.binary_digest, proof.producer.ruleset_digest]) {
    if (value !== undefined) digest(value, "sha256:", "producer digest");
  }
  let previousSource = -1n;
  const sourceIDs = new Set<string>();
  const sourceOrdinals = new Set<bigint>();
  for (const source of proof.sources) {
    if (
      source.source_id === "" ||
      sourceIDs.has(source.source_id) ||
      sourceOrdinals.has(source.source_ordinal)
    ) {
      throw new FixtureError("duplicate or missing source identity");
    }
    if (source.source_ordinal <= previousSource)
      throw new FixtureError("source ordinals must be strictly increasing");
    sourceIDs.add(source.source_id);
    sourceOrdinals.add(source.source_ordinal);
    previousSource = source.source_ordinal;
    validateRecipe(source.recipe);
    digest(source.view_commitment, "hmac-sha256:", "view commitment");
    let previousOrdinal = -1n;
    for (const match of source.matches) {
      if (match.match_ordinal <= previousOrdinal) throw new FixtureError("invalid match ordinal");
      if (match.match_class === "") throw new FixtureError("match class is required");
      digest(match.match_commitment, "hmac-sha256:", "match commitment");
      previousOrdinal = match.match_ordinal;
    }
    validateProvenanceIntervals(
      undefined,
      source.matches.map((match) => [match.byte_start, match.byte_end] as const),
    );
  }
}

function validateRecipe(recipe: Source["recipe"]): void {
  try {
    validateEvidenceProvenanceRecipe({
      transform_profile_digest: recipe.transform_profile_digest,
      operations: recipe.operations.map((operation) => operation.raw),
    });
  } catch (error) {
    throw new FixtureError(error instanceof Error ? error.message : String(error));
  }
}

function frame(value: Buffer): Buffer {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value.length));
  return Buffer.concat([length, value]);
}

function u64(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value);
  return out;
}

function u32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function operationBytes(op: Operation): Buffer {
  const kind: Record<string, number> = {
    identity: 1,
    url_component: 2,
    percent_decode: 3,
    dlp_normalize: 4,
    lowercase: 5,
    invisible_strip: 6,
    hex_decode: 7,
    base32_decode: 8,
    base64_decode: 9,
    leetspeak: 10,
    vowel_fold: 11,
    query_unescape: 12,
    invisible_space: 13,
    matching_normalize: 14,
    hex_decode_liberal: 15,
    base32_decode_liberal: 16,
    base64_decode_liberal: 17,
    encoded_token_normalize: 18,
    text_segment: 19,
    html_entity_decode: 20,
    whitespace_compact: 21,
    url_noise_strip: 22,
    ordered_query_concat: 23,
    query_subsequence: 24,
    hostname_dot_remove: 25,
    encoded_run: 26,
    canary_canonicalize: 27,
  };
  const component: Record<string, number> = {
    "": 0,
    url: 1,
    hostname: 2,
    path: 3,
    query_key: 4,
    query_value: 5,
    raw_query: 6,
  };
  const fields = [
    frame(Buffer.from([kind[op.kind] ?? 0])),
    frame(Buffer.from([component[op.component] ?? 0])),
    frame(Buffer.from(op.selector, "utf8")),
    frame(u32(op.occurrence)),
    frame(Buffer.from([op.passes])),
    frame(Buffer.from(op.profile, "utf8")),
    frame(Buffer.from([op.decode_padding ? 1 : 0])),
  ];
  if ((kind[op.kind] ?? 0) >= 12) {
    fields.push(
      frame(Buffer.from(op.alphabet, "utf8")),
      frame(Buffer.from(op.indices)),
      frame(u32(op.minimum_length)),
    );
  }
  return Buffer.concat(fields);
}

function recipeBytes(recipe: Source["recipe"]): Buffer {
  return Buffer.concat([
    frame(Buffer.from("pipelock/evidence-provenance/recipe/v1", "ascii")),
    frame(Buffer.from(recipe.transform_profile_digest, "ascii")),
    frame(u64(BigInt(recipe.operations.length))),
    ...recipe.operations.map((op) => frame(operationBytes(op))),
  ]);
}

function commitment(key: Buffer, domain: string, values: Buffer[]): string {
  const mac = createHmac("sha256", key);
  mac.update(frame(Buffer.from(domain, "ascii")));
  for (const value of values) mac.update(frame(value));
  return `hmac-sha256:${mac.digest("hex")}`;
}

function commitView(key: Buffer, source: Source, view: string): string {
  return commitment(key, "pipelock/evidence-provenance/view/v1", [
    u64(source.source_ordinal),
    Buffer.from(source.source_id, "utf8"),
    Buffer.from(source.recipe.transform_profile_digest, "ascii"),
    recipeBytes(source.recipe),
    Buffer.from(view, "utf8"),
  ]);
}

function commitMatch(key: Buffer, source: Source, match: Match): string {
  return commitment(key, "pipelock/evidence-provenance/match/v1", [
    Buffer.from(source.source_id, "utf8"),
    Buffer.from(source.recipe.transform_profile_digest, "ascii"),
    recipeBytes(source.recipe),
    Buffer.from(source.view_commitment, "ascii"),
    u64(match.match_ordinal),
    u64(match.byte_start),
    u64(match.byte_end),
    Buffer.from(match.match_class, "utf8"),
  ]);
}

function applyRecipe(
  recipe: Source["recipe"],
  input: string,
  chargeFixtureWork: (bytes: number) => void,
): string {
  try {
    return Buffer.from(
      applyEvidenceProvenanceRecipe(
        Buffer.from(input, "utf8"),
        {
          transform_profile_digest: recipe.transform_profile_digest,
          operations: recipe.operations.map((operation) => operation.raw),
        },
        chargeFixtureWork,
      ),
    ).toString("utf8");
  } catch (error) {
    if (error instanceof FixtureWorkLimit) throw error;
    throw new FixtureError(error instanceof Error ? error.message : String(error));
  }
}

// executeProvenanceRecipe is the narrow fixture-only test seam used by the
// shared transform corpus. It accepts raw bytes so invalid UTF-8 is rejected
// before JavaScript can substitute replacement characters.
export function executeProvenanceRecipe(recipeValue: unknown, input: Buffer): Buffer {
  const raw = utf8(input, "recipe input");
  const recipeObject = object(recipeValue, "recipe");
  exactKeys(recipeObject, ["transform_profile_digest", "operations"], "recipe");
  const recipe: Source["recipe"] = {
    transform_profile_digest: string(
      recipeObject.transform_profile_digest,
      "recipe transform profile digest",
    ),
    operations: array(recipeObject.operations, "recipe.operations").map(parseOperation),
  };
  validateRecipe(recipe);
  return Buffer.from(
    applyRecipe(recipe, raw, () => {}),
    "utf8",
  );
}

function decodeRawBase64(value: string): Buffer {
  if (!/^[A-Za-z0-9+/]*$/u.test(value) || value.length % 4 === 1)
    throw new FixtureError("base64 decode failed");
  const padded = value.padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64");
  if (decoded.toString("base64").replace(/=+$/u, "") !== value)
    throw new FixtureError("base64 decode: non-canonical encoding");
  return decoded;
}

function boundary(bytes: Buffer, offset: bigint): boolean {
  if (offset === 0n || offset === BigInt(bytes.length)) return true;
  return offset < BigInt(bytes.length) && (bytes[Number(offset)]! & 0xc0) !== 0x80;
}

export function validateProvenanceIntervals(
  view: Buffer | undefined,
  intervals: Array<readonly [bigint, bigint]>,
): void {
  if (view !== undefined) utf8(view, "view");
  let previousStart = -1n;
  let previousEnd = -1n;
  for (const [start, end] of intervals) {
    if (end <= start) throw new FixtureError("byte end must be greater than byte start");
    if (start < previousStart) throw new FixtureError("intervals are unsorted");
    if (start === previousStart) throw new FixtureError("duplicate interval start");
    if (start < previousEnd) throw new FixtureError("intervals overlap");
    if (view !== undefined) {
      if (end > BigInt(view.length)) throw new FixtureError("interval out of bounds");
      if (!boundary(view, start) || !boundary(view, end))
        throw new FixtureError("interval splits UTF-8 code point");
    }
    previousStart = start;
    previousEnd = end;
  }
}

function artifacts(proof: Proof, fixture: Fixture): ArtifactStage {
  const pairs: Array<[string | undefined, string | undefined, string]> = [
    [proof.producer.binary_digest, fixture.binaryB64, "verification.binary_b64"],
    [proof.producer.ruleset_digest, fixture.rulesetB64, "verification.ruleset_b64"],
  ];
  let hasAttestation = false;
  let unchecked = false;
  let mismatch = false;
  for (const [attestedDigest, encoded, label] of pairs) {
    if (attestedDigest === undefined) continue;
    hasAttestation = true;
    if (encoded === undefined) unchecked = true;
    else {
      let supplied: Buffer;
      try {
        supplied = b64(encoded, label, maxArtifactBytes);
      } catch {
        return "mismatch";
      }
      if (`sha256:${createHash("sha256").update(supplied).digest("hex")}` !== attestedDigest)
        mismatch = true;
    }
  }
  if (mismatch) return "mismatch";
  if (unchecked) return "attested_unchecked";
  return hasAttestation ? "matched" : "not_attested";
}

// verifyProvenanceFixture returns compact stages only. It never exposes source
// bytes, keys, or implementation errors; the stage is the comparable contract.
export async function verifyProvenanceFixture(data: string): Promise<ProvenanceReport> {
  let fixture: Fixture;
  try {
    fixture = parseFixture(data);
  } catch {
    return invalid("proof_structure", stage("proof_structure"));
  }
  const report = stage();
  for (const entry of fixture.entries) {
    if (
      !(await ed25519.verifyAsync(entry.signature, entry.bytes, fixture.signer, { zip215: false }))
    )
      return invalid("signature", stage("signature"));
  }
  report.signature = "verified";
  for (let index = 0; index < fixture.entries.length; index++) {
    const entry = fixture.entries[index]!;
    const expectedPrev =
      index === 0
        ? "genesis"
        : `sha256:${createHash("sha256")
            .update(fixture.entries[index - 1]!.bytes)
            .digest("hex")}`;
    if (entry.chain_seq !== BigInt(index) || entry.chain_prev_hash !== expectedPrev) {
      report.chain = "invalid";
      return invalid("chain", report);
    }
  }
  report.chain = "verified";
  for (const entry of fixture.entries) {
    if (entry.critical_features.length !== 1 || entry.critical_features[0] !== knownFeature)
      return invalid("critical_features", report);
  }
  try {
    for (const entry of fixture.entries) validateProofStructure(entry.proof);
  } catch {
    return invalid("proof_structure", report);
  }
  let artifactsMatched = false;
  let artifactsUnchecked = false;
  for (const entry of fixture.entries) {
    const artifactStage = artifacts(entry.proof, fixture);
    if (artifactStage === "mismatch") {
      report.artifacts = "mismatch";
      return invalid("artifacts", report);
    }
    artifactsMatched ||= artifactStage === "matched";
    artifactsUnchecked ||= artifactStage === "attested_unchecked";
  }
  report.artifacts = artifactsUnchecked
    ? "attested_unchecked"
    : artifactsMatched
      ? "matched"
      : "not_attested";
  const allSources: Array<{ source: Source; raw?: string; view?: string }> = [];
  for (const entry of fixture.entries) {
    for (const source of entry.proof.sources)
      allSources.push({ source, raw: fixture.sources.get(source.source_id) });
  }
  const missingSource = allSources.some((item) => item.raw === undefined);
  const availableSources = allSources.filter(
    (item): item is { source: Source; raw: string; view?: string } => item.raw !== undefined,
  );
  let recipeProcessingBytes = 0;
  const reconstructedViews = new Map<string, string>();
  const chargeFixtureWork = (bytes: number): void => {
    if (bytes > maxFixtureRecipeProcessingBytes - recipeProcessingBytes)
      throw new FixtureWorkLimit("fixture exceeds recipe-processing byte limit");
    recipeProcessingBytes += bytes;
  };
  try {
    for (const item of availableSources) {
      const key = `${item.source.source_id}\u0000${recipeBytes(item.source.recipe).toString("base64")}`;
      item.view = reconstructedViews.get(key);
      if (item.view === undefined) {
        item.view = applyRecipe(item.source.recipe, item.raw, chargeFixtureWork);
        reconstructedViews.set(key, item.view);
      }
    }
  } catch (error) {
    if (error instanceof FixtureWorkLimit) return invalid("proof_structure", report);
    report.view_reproduction = "mismatch";
    return invalid("view_reproduction", report);
  }
  if (availableSources.length > 0) report.view_reproduction = "reproduced";
  for (const item of availableSources) {
    const bytes = Buffer.from(item.view!, "utf8");
    try {
      validateProvenanceIntervals(
        bytes,
        item.source.matches.map((match) => [match.byte_start, match.byte_end] as const),
      );
    } catch {
      if (missingSource) {
        report.view_reproduction = "not_checked";
        report.location = "not_checked";
        report.match_commitment = "not_checked";
      } else {
        report.location = "mismatch";
      }
      return invalid("location", report);
    }
  }
  if (availableSources.length > 0) report.location = "exact_coordinates";
  if (fixture.commitmentKey === undefined) {
    report.match_commitment = "not_checked";
    if (missingSource) {
      report.view_reproduction = "not_checked";
      report.location = "not_checked";
    }
    report.overall = "incomplete";
    return report;
  }
  for (const item of availableSources) {
    if (
      commitView(fixture.commitmentKey, item.source, item.view!) !== item.source.view_commitment
    ) {
      if (missingSource) {
        report.view_reproduction = "not_checked";
        report.location = "not_checked";
      }
      report.match_commitment = "mismatch";
      return invalid("view_commitment", report);
    }
    for (const match of item.source.matches) {
      if (commitMatch(fixture.commitmentKey, item.source, match) !== match.match_commitment) {
        if (missingSource) {
          report.view_reproduction = "not_checked";
          report.location = "not_checked";
        }
        report.match_commitment = "mismatch";
        return invalid("match_commitment", report);
      }
    }
  }
  report.match_commitment = availableSources.length > 0 ? "opened" : "not_checked";
  if (missingSource) {
    report.view_reproduction = "not_checked";
    report.location = "not_checked";
    report.match_commitment = "not_checked";
  }
  // PR3 contains no source-commitment field. Its explicit unavailable state is
  // load-bearing: it prevents fixture support from being misreported as a fully
  // opened provenance proof.
  report.source_commitment = "not_checked";
  report.overall = "incomplete";
  return report;
}

export async function runProvenanceFixture(path: string): Promise<ProvenanceReport> {
  try {
    const fd = openSync(path, "r");
    try {
      const chunks: Buffer[] = [];
      let total = 0;
      while (total <= maxFixtureBytes) {
        const chunk = Buffer.allocUnsafe(Math.min(64 << 10, maxFixtureBytes + 1 - total));
        const read = readSync(fd, chunk, 0, chunk.length, null);
        if (read === 0) break;
        chunks.push(chunk.subarray(0, read));
        total += read;
      }
      return await verifyProvenanceFixture(utf8(Buffer.concat(chunks), "fixture"));
    } finally {
      closeSync(fd);
    }
  } catch {
    return invalid("proof_structure", stage("proof_structure"));
  }
}

export function comparableProvenance(report: ProvenanceReport): string {
  const ordered: ProvenanceReport = {
    trust_roots: report.trust_roots,
    authenticated_provenance: report.authenticated_provenance,
    signature: report.signature,
    chain: report.chain,
    artifacts: report.artifacts,
    source_commitment: report.source_commitment,
    view_reproduction: report.view_reproduction,
    location: report.location,
    match_commitment: report.match_commitment,
    overall: report.overall,
    ...(report.failure_stage === undefined ? {} : { failure_stage: report.failure_stage }),
  };
  return JSON.stringify(ordered);
}

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// X.509-SVID attestation layer, ported from internal/svid/svid.go,
// internal/aarp/attest.go, and cmd/pipelock-verifier/aarp_svid.go. It appraises
// an X.509-SVID workload-identity proof-of-possession binding on top of the
// envelope appraisal. It is ADDITIVE: it never changes the envelope contract,
// never makes an envelope fatal, and never removes a core claim. On a signed
// assertion whose binding fully verifies it adds exactly three claims.
//
// Two distinct error surfaces, matching the Go reference:
//
//   - A malformed PINNED bundle (bad DER, inverted/empty window, empty domain)
//     is an operator-configuration error -> SVIDFileError (CLI exit 2). The
//     bundle is trusted input, so a structural problem there is misconfiguration,
//     not a fixture verdict.
//   - Everything in `evidence` is attacker-controlled, so a failure there
//     appraises fail-closed: verifySVIDBinding throws an SVIDBindingError that
//     addSVIDClaims catches inline (withholds claims, adds a warning) and NEVER
//     propagates as a non-zero exit.

import { createHash, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  AXIS_FRESHNESS,
  AXIS_IDENTITY,
  Appraisal,
  CLAIM_SVID_VALID_AT_ACTION_TIME,
  CLAIM_WORKLOAD_IDENTITY_VERIFIED,
  CLAIM_X509_SVID_BOUND,
  VerifyOptions,
  addVerified,
  appraiseCore,
  classifyClaims,
} from "./appraise.js";
import { canonicalize } from "./canonical.js";
import { Envelope, payloadDigest } from "./envelope.js";
import { validateTimestamp } from "./numbers.js";

// ContextSVIDBinding is the domain separator for the SVID proof-of-possession
// binding. It is a signed field of the binding payload.
export const CONTEXT_SVID_BINDING = "pipelock-aarp-v0.1/svid-receipt-binding";

// minNonceBytes is the minimum SVID-binding nonce size: 128 bits.
const MIN_NONCE_BYTES = 16;

// SVID binding algorithm identifiers. The binding signature is made by the SVID
// leaf's private key, so the algorithm follows the leaf key type.
export const BINDING_ALG_ECDSA_P256_SHA256 = "ecdsa-p256-sha256";
export const BINDING_ALG_ED25519 = "ed25519";

// SVIDFileError marks an I/O, parse, or operator-pinned-bundle error in the
// --svid sidecar (CLI exit code 2). A structurally broken pinned bundle is
// operator misconfiguration, never a fixture verdict.
export class SVIDFileError extends Error {
  readonly code = 2;
}

// SVIDBindingError marks a fail-closed attestation failure on attacker-supplied
// evidence. It is NOT a coded error: addSVIDClaims catches it inline so a failed
// binding withholds the SVID claims (with a warning) and never errors the
// envelope or exits non-zero.
class SVIDBindingError extends Error {}

// SVIDBinding is the proof-of-possession signature tying an SVID to a receipt.
export interface SVIDBinding {
  alg: string;
  context: string;
  payload_sha256: string;
  signature_b64: string;
}

// SVIDEvidence is the producer-supplied X.509-SVID proof-of-possession.
export interface SVIDEvidence {
  type: string;
  spiffe_id: string;
  leaf_der_b64: string;
  chain_der_b64?: string[];
  nonce: string;
  issued_at: string;
  binding: SVIDBinding;
}

// PinnedGeneration is one pinned trust-bundle generation: a window and the CA
// authorities authoritative during it. Windows are JS Dates (UTC instants).
interface PinnedGeneration {
  notBefore: Date;
  notAfter: Date | null; // null = open-ended / current
  authorities: X509Certificate[];
}

// SVIDVerifyOptions carries the verifier's pinned SVID trust context.
export interface SVIDVerifyOptions {
  trustDomain: string;
  generations: PinnedGeneration[];
  actionTime: Date;
  allowedSpiffeIDs: string[];
}

// ---- Sidecar wire shapes (decoded strictly, unknown fields rejected) ----

// rejectUnknownKeys mirrors Go's DisallowUnknownFields on the typed sidecar
// structs: any key outside the allowed set in an SVID-controlled object is an
// operator/format error (exit 2).
function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  field: string,
): void {
  const allow = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allow.has(key)) {
      throw new SVIDFileError(`unknown field ${JSON.stringify(key)} in ${field}`);
    }
  }
}

function asFileObject(v: unknown, field: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new SVIDFileError(`${field} must be an object`);
  }
  return v as Record<string, unknown>;
}

function asFileString(v: unknown, field: string): string {
  if (typeof v !== "string") throw new SVIDFileError(`${field} must be a string`);
  return v;
}

function asFileStringArray(v: unknown, field: string): string[] {
  if (!Array.isArray(v)) throw new SVIDFileError(`${field} must be an array`);
  return v.map((item, i) => asFileString(item, `${field}[${i}]`));
}

// decodeEvidence decodes the producer evidence block strictly. The evidence is
// attacker-controlled CONTENT, but a structurally broken sidecar (wrong types,
// unknown fields) is still a format error (exit 2): the appraisal only fails
// closed on well-formed-but-invalid evidence, not on malformed JSON.
function decodeEvidence(v: unknown): SVIDEvidence {
  const obj = asFileObject(v, "evidence");
  rejectUnknownKeys(
    obj,
    ["type", "spiffe_id", "leaf_der_b64", "chain_der_b64", "nonce", "issued_at", "binding"],
    "evidence",
  );
  const bindingObj = asFileObject(obj.binding, "evidence.binding");
  rejectUnknownKeys(
    bindingObj,
    ["alg", "context", "payload_sha256", "signature_b64"],
    "evidence.binding",
  );
  const ev: SVIDEvidence = {
    type: asFileString(obj.type, "evidence.type"),
    spiffe_id: asFileString(obj.spiffe_id, "evidence.spiffe_id"),
    leaf_der_b64: asFileString(obj.leaf_der_b64, "evidence.leaf_der_b64"),
    nonce: asFileString(obj.nonce, "evidence.nonce"),
    issued_at: asFileString(obj.issued_at, "evidence.issued_at"),
    binding: {
      alg: asFileString(bindingObj.alg, "evidence.binding.alg"),
      context: asFileString(bindingObj.context, "evidence.binding.context"),
      payload_sha256: asFileString(bindingObj.payload_sha256, "evidence.binding.payload_sha256"),
      signature_b64: asFileString(bindingObj.signature_b64, "evidence.binding.signature_b64"),
    },
  };
  if (obj.chain_der_b64 !== undefined) {
    ev.chain_der_b64 = asFileStringArray(obj.chain_der_b64, "evidence.chain_der_b64");
  }
  return ev;
}

// decodeVerify decodes the verifier-pinned trust block and builds the pinned
// bundle history, enforcing the append-only, non-overlapping invariant from
// internal/svid (NewGeneration / NewTrustBundleHistory). Any structural problem
// is an operator-config error (exit 2).
function decodeVerify(v: unknown): SVIDVerifyOptions {
  const obj = asFileObject(v, "verify");
  rejectUnknownKeys(obj, ["trust_domain", "action_time", "allowed_spiffe_ids", "bundle"], "verify");
  const trustDomain = asFileString(obj.trust_domain, "verify.trust_domain");
  validateTrustDomain(trustDomain);
  const actionTime = parseFileTimestamp(obj.action_time, "verify.action_time");

  let allowedSpiffeIDs: string[] = [];
  if (obj.allowed_spiffe_ids !== undefined) {
    allowedSpiffeIDs = asFileStringArray(obj.allowed_spiffe_ids, "verify.allowed_spiffe_ids");
  }

  if (!Array.isArray(obj.bundle)) {
    throw new SVIDFileError("verify.bundle must be an array");
  }
  if (obj.bundle.length === 0) {
    throw new SVIDFileError("trust bundle history needs at least one generation");
  }
  const generations: PinnedGeneration[] = [];
  for (let i = 0; i < obj.bundle.length; i++) {
    generations.push(decodeGeneration(obj.bundle[i], i, generations));
  }

  return { trustDomain, generations, actionTime, allowedSpiffeIDs };
}

// decodeGeneration parses one pinned generation and enforces the append-only
// timeline invariant against the generations already pinned (matches Go's
// appendGen): a new generation must start strictly after the previous one began;
// an open-ended previous generation is closed at the new one's start; a previous
// closed generation must not overlap.
function decodeGeneration(v: unknown, idx: number, prior: PinnedGeneration[]): PinnedGeneration {
  const field = `bundle[${idx}]`;
  const obj = asFileObject(v, field);
  rejectUnknownKeys(obj, ["not_before", "not_after", "authorities_der_b64"], field);

  const notBefore = parseFileTimestamp(obj.not_before, `${field}.not_before`);
  let notAfter: Date | null = null;
  if (obj.not_after !== undefined && obj.not_after !== "") {
    notAfter = parseFileTimestamp(obj.not_after, `${field}.not_after`);
  }
  // Window validity (validateGenerationWindow): notAfter must be strictly after
  // notBefore when set.
  if (notAfter !== null && notAfter.getTime() <= notBefore.getTime()) {
    throw new SVIDFileError(`${field}: generation notAfter must be after notBefore`);
  }

  const derList = asFileStringArray(obj.authorities_der_b64, `${field}.authorities_der_b64`);
  if (derList.length === 0) {
    throw new SVIDFileError(`${field}: generation has no trust authorities`);
  }
  const authorities: X509Certificate[] = [];
  for (let j = 0; j < derList.length; j++) {
    const der = decodeStdBase64(derList[j] as string, `${field}.authorities_der_b64[${j}]`);
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(der);
    } catch (err) {
      throw new SVIDFileError(
        `${field}.authorities_der_b64[${j}]: parse certificate: ${(err as Error).message}`,
      );
    }
    validateAuthority(cert, `${field}.authorities_der_b64[${j}]`);
    authorities.push(cert);
  }

  // Append-only / non-overlap invariant against the previous generation.
  if (prior.length > 0) {
    const last = prior[prior.length - 1] as PinnedGeneration;
    if (notBefore.getTime() <= last.notBefore.getTime()) {
      throw new SVIDFileError(`${field}: generation starts at or before the previous generation`);
    }
    if (last.notAfter === null) {
      // Open-ended previous generation: legitimate rotation closes it here.
      last.notAfter = notBefore;
    } else if (notBefore.getTime() < last.notAfter.getTime()) {
      throw new SVIDFileError(`${field}: generation overlaps a closed generation`);
    }
  }

  return { notBefore, notAfter, authorities };
}

// validateAuthority mirrors internal/svid.validateAuthority: the cert must be a
// CA, and (when key usage is asserted) must carry cert-sign usage. A missing
// keyUsage extension (Node reports undefined) is allowed, matching Go's
// KeyUsage == 0 case.
function validateAuthority(cert: X509Certificate, field: string): void {
  if (!cert.ca) {
    throw new SVIDFileError(`${field}: trust authority certificate is not a CA`);
  }
  const usage = cert.keyUsage;
  if (usage !== undefined && usage.length > 0 && !usage.includes("Certificate Sign")) {
    throw new SVIDFileError(`${field}: trust authority certificate lacks cert-sign key usage`);
  }
}

// validateTrustDomain rejects an empty domain and an IP-literal domain, matching
// internal/svid.parseTrustDomain (SPIFFE-ID requires a DNS-name trust domain).
function validateTrustDomain(td: string): void {
  if (td === "") {
    throw new SVIDFileError("trust domain must not be empty");
  }
  // A SPIFFE trust domain is a host-like authority; reject scheme/path/userinfo.
  if (/[/@:]/u.test(td) || td.includes("spiffe://")) {
    throw new SVIDFileError(`invalid trust domain ${JSON.stringify(td)}`);
  }
  if (isIPLiteral(td)) {
    throw new SVIDFileError(`trust domain must be a DNS name, not an IP address: ${td}`);
  }
}

function isIPLiteral(s: string): boolean {
  // IPv4 dotted quad or an IPv6 literal in brackets / containing a colon.
  if (/^\d{1,3}(\.\d{1,3}){3}$/u.test(s)) return true;
  if (s.includes(":")) return true;
  return false;
}

function parseFileTimestamp(v: unknown, field: string): Date {
  const s = asFileString(v, field);
  try {
    validateTimestamp(s);
  } catch (err) {
    throw new SVIDFileError(`${field}: ${(err as Error).message}`);
  }
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) {
    throw new SVIDFileError(`${field}: unparseable timestamp ${JSON.stringify(s)}`);
  }
  return d;
}

// decodeStdBase64 strictly decodes standard base64 (round-trip check) for an
// operator-pinned field.
function decodeStdBase64(b64: string, field: string): Buffer {
  const buf = Buffer.from(b64, "base64");
  if (buf.toString("base64") !== b64) {
    throw new SVIDFileError(`${field}: not standard base64`);
  }
  return buf;
}

// loadSVIDFile reads a --svid sidecar into producer evidence and verifier-pinned
// SVID options. Strict decode: unknown fields and trailing tokens are rejected
// (mirrors Go's DisallowUnknownFields + trailing-token check). Any error here is
// SVIDFileError (exit 2).
export function loadSVIDFile(path: string): { evidence: SVIDEvidence; opts: SVIDVerifyOptions } {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new SVIDFileError(`read svid file: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new SVIDFileError(`parse svid file: ${(err as Error).message}`);
  }
  const obj = asFileObject(parsed, "svid file");
  rejectUnknownKeys(obj, ["evidence", "verify"], "svid file");
  if (obj.evidence === undefined) throw new SVIDFileError("evidence is required");
  if (obj.verify === undefined) throw new SVIDFileError("verify is required");
  const evidence = decodeEvidence(obj.evidence);
  const opts = decodeVerify(obj.verify);
  return { evidence, opts };
}

// ---- SVID validation (offline, point-in-time) ----

// generationAt returns the bundle generation authoritative at t, or null if no
// pinned generation covers t (stale/forked bundle).
function generationAt(gens: PinnedGeneration[], t: Date): PinnedGeneration | null {
  const ms = t.getTime();
  for (const g of gens) {
    if (ms < g.notBefore.getTime()) continue;
    if (g.notAfter === null || ms < g.notAfter.getTime()) return g;
  }
  return null;
}

// parseSpiffeURISAN extracts the single SPIFFE URI SAN from a leaf cert and
// returns its trust domain. It mirrors x509svid.IDFromCert: the leaf must carry
// exactly one well-formed SPIFFE URI SAN (a spiffe:// URI with a host and no
// query/fragment/userinfo/port). Anything else is not an X.509-SVID.
function parseSpiffeURISAN(leaf: X509Certificate): { id: string; trustDomain: string } {
  const san = leaf.subjectAltName;
  if (san === undefined || san === "") {
    throw new SVIDBindingError("leaf is not an X.509-SVID: no subjectAltName");
  }
  // Node renders SANs as a comma-space-joined list of "<type>:<value>" entries.
  // Split carefully: a URI value can itself contain no commas in this corpus,
  // but a value containing a quoted comma would be rendered with quotes; reject
  // those rather than mis-parse.
  const uris: string[] = [];
  for (const part of splitSANList(san)) {
    const idx = part.indexOf(":");
    if (idx < 0) continue;
    const kind = part.slice(0, idx);
    const value = part.slice(idx + 1);
    if (kind === "URI") uris.push(value);
  }
  if (uris.length !== 1) {
    throw new SVIDBindingError(
      `leaf is not an X.509-SVID: ${uris.length} URI SANs, want exactly 1`,
    );
  }
  const uri = uris[0] as string;
  return parseSpiffeID(uri);
}

// splitSANList splits Node's subjectAltName rendering into entries. Node joins
// entries with ", "; a value containing characters that would need quoting is
// rendered with surrounding quotes (and embedded commas escaped), which this
// corpus never produces. Reject a quoted entry to avoid mis-parsing.
function splitSANList(san: string): string[] {
  if (san.includes('"')) {
    throw new SVIDBindingError("leaf SAN contains a quoted entry; refusing to parse ambiguously");
  }
  return san.split(", ");
}

// SPIFFE_SCHEME is the only scheme a SPIFFE ID may carry.
const SPIFFE_SCHEME = "spiffe://";

// isTrustDomainChar reports whether c is allowed in a SPIFFE trust domain
// (authority): lowercase letters, digits, and '.', '-', '_'. Mirrors go-spiffe
// v2.6.0 spiffeid's trust-domain charset. Uppercase is rejected (no normalize).
function isTrustDomainChar(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c === "." || c === "-" || c === "_";
}

// isPathSegmentChar reports whether c is allowed in a SPIFFE path segment:
// letters (either case), digits, and '.', '-', '_'. Mirrors go-spiffe v2.6.0
// ValidatePath's segment charset.
function isPathSegmentChar(c: string): boolean {
  return (
    (c >= "A" && c <= "Z") ||
    (c >= "a" && c <= "z") ||
    (c >= "0" && c <= "9") ||
    c === "." ||
    c === "-" ||
    c === "_"
  );
}

// parseSpiffeID validates a SPIFFE ID against an EXPLICIT grammar (mirroring
// go-spiffe v2.6.0 spiffeid.FromString + ValidatePath, which the Go reference
// uses) and returns its trust domain. It deliberately does NOT route the value
// through `new URL(...)`: WHATWG URL parsing silently normalizes dot-segment
// paths (`/workload/../imposter` -> `/imposter`), lowercases the host, and
// resolves percent-escapes, any of which would turn a malformed SPIFFE ID into
// an accepted one (display-vs-reality divergence). Validation runs against the
// RAW SAN string so what we validate is exactly what was presented.
//
//   - scheme exactly `spiffe://`;
//   - trust domain (authority, up to the first `/`): non-empty, only
//     [a-z0-9._-] (lowercase: uppercase is rejected, not folded), no userinfo
//     (`@`), no port (`:`);
//   - path (from the first `/`): may be empty; if present each `/`-separated
//     segment must be non-empty (reject `//`), must not be `.` or `..` (reject
//     dot-segments), only [A-Za-z0-9._-]; no trailing slash;
//   - no query (`?`) and no fragment (`#`).
function parseSpiffeID(uri: string): { id: string; trustDomain: string } {
  if (!uri.startsWith(SPIFFE_SCHEME)) {
    throw new SVIDBindingError(`leaf URI SAN ${JSON.stringify(uri)} is not a SPIFFE ID`);
  }
  // A query or fragment is never part of a SPIFFE ID. Reject before splitting so
  // a `?`/`#` cannot hide later structure from the path checks.
  if (uri.includes("?")) {
    throw new SVIDBindingError("leaf SPIFFE ID must not carry a query");
  }
  if (uri.includes("#")) {
    throw new SVIDBindingError("leaf SPIFFE ID must not carry a fragment");
  }

  const rest = uri.slice(SPIFFE_SCHEME.length);
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash); // includes the leading '/'

  if (authority === "") {
    throw new SVIDBindingError("leaf SPIFFE ID has an empty trust domain");
  }
  if (authority.includes("@")) {
    throw new SVIDBindingError("leaf SPIFFE ID must not carry userinfo");
  }
  if (authority.includes(":")) {
    throw new SVIDBindingError("leaf SPIFFE ID must not carry a port");
  }
  for (const c of authority) {
    if (!isTrustDomainChar(c)) {
      throw new SVIDBindingError(
        `leaf SPIFFE ID trust domain ${JSON.stringify(authority)} has invalid character ${JSON.stringify(c)}`,
      );
    }
  }

  validateSpiffePath(path);
  return { id: uri, trustDomain: authority };
}

// validateSpiffePath validates the path component of a SPIFFE ID (the substring
// from the first `/`, or empty). Mirrors go-spiffe v2.6.0 ValidatePath: an empty
// path is valid; otherwise it must start with `/`, must not end with `/` (no
// trailing slash), and each `/`-separated segment must be non-empty (no `//`),
// must not be a dot-segment (`.` or `..`), and may contain only [A-Za-z0-9._-].
function validateSpiffePath(path: string): void {
  if (path === "") {
    return;
  }
  // path begins with '/' (it is the substring from the first slash).
  if (path.endsWith("/")) {
    throw new SVIDBindingError("leaf SPIFFE ID path has a trailing slash");
  }
  // Drop the leading '/', then split on '/'. Every resulting segment must be a
  // valid, non-empty, non-dot segment.
  const segments = path.slice(1).split("/");
  for (const seg of segments) {
    if (seg === "") {
      throw new SVIDBindingError("leaf SPIFFE ID path has an empty segment");
    }
    if (seg === "." || seg === "..") {
      throw new SVIDBindingError(`leaf SPIFFE ID path has a dot-segment ${JSON.stringify(seg)}`);
    }
    for (const c of seg) {
      if (!isPathSegmentChar(c)) {
        throw new SVIDBindingError(
          `leaf SPIFFE ID path segment ${JSON.stringify(seg)} has invalid character ${JSON.stringify(c)}`,
        );
      }
    }
  }
}

// RFC3339_NANO_RE captures the fractional-seconds digits and the zone of an
// already-validated RFC3339Nano timestamp so the value can be reduced to exact
// epoch nanoseconds. (Grammar validity is enforced earlier by validateTimestamp;
// this only needs to split out the parts.)
const RFC3339_NANO_RE =
  /^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/u;

// rfc3339ToUnixNanos converts an already-validated RFC3339Nano timestamp to
// epoch nanoseconds as a bigint, preserving full sub-second precision (JS Date
// is millisecond-only and would silently truncate the nanosecond tail). The
// whole-second instant is computed via Date.parse on the second-truncated string
// (always an integer number of milliseconds, i.e. a whole number of seconds
// here), then the fractional-seconds digits are added back as nanoseconds.
function rfc3339ToUnixNanos(s: string): bigint {
  const m = RFC3339_NANO_RE.exec(s);
  if (m === null) {
    // Should never happen: callers validate the grammar first. Fail closed.
    throw new SVIDBindingError(`issued_at ${JSON.stringify(s)} is not RFC3339Nano`);
  }
  const secondsPart = m[1] as string;
  const frac = m[2] ?? "";
  const zone = m[3] as string;
  const wholeMs = Date.parse(`${secondsPart}${zone}`);
  if (Number.isNaN(wholeMs)) {
    throw new SVIDBindingError(`issued_at ${JSON.stringify(s)} is not a parseable instant`);
  }
  // wholeMs is a whole number of seconds (no sub-second in secondsPart), so
  // converting ms -> ns is exact.
  let nanos = BigInt(wholeMs) * 1_000_000n;
  if (frac !== "") {
    // Right-pad/truncate the fractional digits to exactly 9 (nanoseconds).
    const nineDigits = (frac + "000000000").slice(0, 9);
    nanos += BigInt(nineDigits);
  }
  return nanos;
}

// certNotBeforeMs / certNotAfterMs read an X509Certificate's validity window as
// epoch milliseconds. They parse the always-present `validFrom` / `validTo`
// string properties rather than the `validFromDate` / `validToDate` Date
// accessors: those Date accessors only exist on Node >= 22, so on Node 20 they
// are `undefined` and `.getTime()` throws -- a cross-version differential that
// withheld the claims on the valid baselines. X.509 validity windows are
// whole-second, so millisecond precision is exact here; the sub-second issued_at
// boundary is handled separately in nanoseconds (rfc3339ToUnixNanos).
function certNotBeforeMs(cert: X509Certificate): number {
  return new Date(cert.validFrom).getTime();
}

function certNotAfterMs(cert: X509Certificate): number {
  return new Date(cert.validTo).getTime();
}

// validateSVID validates the leaf (single-CA, leaf-directly-under-root corpus)
// offline at the action time against the pinned bundle authoritative then. It
// mirrors internal/svid.ValidateSVID for the no-intermediate case: the leaf must
// chain to the authoritative CA, fall inside its own validity window at the
// action time, carry exactly one SPIFFE URI SAN, and belong to the expected
// trust domain. Returns the validated leaf and its SPIFFE ID. Throws
// SVIDBindingError (fail-closed) on any failure.
function validateSVID(
  evidence: SVIDEvidence,
  opts: SVIDVerifyOptions,
): { leaf: X509Certificate; spiffeID: string } {
  const leafDER = decodeEvidenceBase64(evidence.leaf_der_b64, "leaf_der_b64");
  if (leafDER.length === 0) {
    throw new SVIDBindingError("empty leaf certificate DER");
  }
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(leafDER);
  } catch (err) {
    throw new SVIDBindingError(`leaf certificate DER is invalid: ${(err as Error).message}`);
  }

  // The corpus is single-CA, leaf-directly-under-root: any chain_der_b64
  // intermediates are out of scope, but reject a leaf that ships them so the TS
  // verifier does not silently accept an unvalidated extra hop.
  if (evidence.chain_der_b64 !== undefined && evidence.chain_der_b64.length > 0) {
    throw new SVIDBindingError("intermediate certificates are out of scope for the SVID corpus");
  }

  // Extract the SPIFFE ID and trust domain before chain work, so a trust-domain
  // mismatch is reported precisely (matches Go's ordering).
  const { id, trustDomain } = parseSpiffeURISAN(leaf);
  if (trustDomain !== opts.trustDomain) {
    throw new SVIDBindingError(
      `SVID trust domain ${JSON.stringify(trustDomain)}, expected ${JSON.stringify(opts.trustDomain)}`,
    );
  }

  // Find the pinned generation authoritative at the action time.
  const gen = generationAt(opts.generations, opts.actionTime);
  if (gen === null) {
    throw new SVIDBindingError(
      `no pinned bundle authoritative at ${opts.actionTime.toISOString()}`,
    );
  }

  // The leaf must chain to one of the authorities pinned for that generation
  // (signature + issuer linkage). Single CA, no intermediates. The signing CA
  // must ALSO be inside its own validity window at the action time: Go's
  // x509svid.Verify(..., WithTime(actionTime)) validates the FULL chain at the
  // action time, including the root. Node's leaf.verify(ca.publicKey) only
  // checks the issuer signature, so we add the CA-window check explicitly here
  // (mirroring the Rust/Python ports). A CA expired-at-action inside an
  // otherwise-covering pinned generation is rejected, not accepted.
  const at = opts.actionTime.getTime();
  let chained = false;
  for (const ca of gen.authorities) {
    if (at < certNotBeforeMs(ca) || at > certNotAfterMs(ca)) {
      // CA outside its own window at the action time: skip it (do not chain to
      // an expired/not-yet-valid signing CA).
      continue;
    }
    if (!leaf.checkIssued(ca)) {
      // Node's leaf.verify(ca.publicKey) checks only the signature bytes. Go's
      // x509 path builder also requires issuer/subject linkage, so a leaf signed
      // by the same key but naming a different issuer must not chain to the
      // pinned CA identity. Use the structural checkIssued() rather than comparing
      // the formatted issuer/subject DN strings: Node's X509Certificate DN string
      // rendering differs across Node versions (20 vs 22), so a string compare is
      // a cross-version differential; checkIssued() compares at the certificate
      // level and is stable.
      continue;
    }
    let sigOK = false;
    try {
      sigOK = leaf.verify(ca.publicKey);
    } catch {
      sigOK = false;
    }
    if (sigOK) {
      chained = true;
      break;
    }
  }
  if (!chained) {
    throw new SVIDBindingError("chain does not validate to a pinned bundle");
  }

  // Point-in-time validity window of the leaf: action time must be within
  // [NotBefore, NotAfter]. Node has no point-in-time chain builder, so we check
  // the window manually against the action time (not "now"). `at` is the
  // action-time epoch ms already computed above for the CA-window check.
  if (at < certNotBeforeMs(leaf) || at > certNotAfterMs(leaf)) {
    throw new SVIDBindingError("not valid at the requested time");
  }

  return { leaf, spiffeID: id };
}

// ---- Binding canonical payload + proof-of-possession verification ----

// bindingCanonical returns the JCS-canonical bytes of the binding payload built
// from the envelope and evidence. It is the message the SVID leaf key signs. The
// keys are JCS-sorted by the shared canonicalizer, so listing order here is
// immaterial; every value is a typed string.
function bindingCanonical(e: Envelope, ev: SVIDEvidence): string {
  const bp = {
    action_record_sha256: e.subject.action_record_sha256,
    assurance_assertion_sha256: payloadDigest(e),
    context: CONTEXT_SVID_BINDING,
    issued_at: ev.issued_at,
    mediator_id: e.assertion.mediator_id,
    nonce: ev.nonce,
    profile: e.profile,
    receipt_envelope_sha256: e.subject.receipt_envelope_sha256,
    receipt_signer_key: e.subject.receipt_signer_key,
    spiffe_id: ev.spiffe_id,
  };
  return canonicalize(bp);
}

function hexSHA256(s: string): string {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}

// verifyLeafSignature verifies a proof-of-possession signature under the SVID
// leaf public key, dispatching on the declared algorithm and the actual key
// type. A declared algorithm that does not match the key type fails closed. For
// ECDSA the alg id names P-256, so an explicit curve check rejects a P-384/P-521
// leaf even though ASN.1 ECDSA verification is curve-agnostic.
function verifyLeafSignature(
  leaf: X509Certificate,
  alg: string,
  message: string,
  sig: Buffer,
): void {
  const pub = leaf.publicKey;
  const keyType = pub.asymmetricKeyType;
  const msg = Buffer.from(message, "utf8");

  if (keyType === "ec") {
    if (alg !== BINDING_ALG_ECDSA_P256_SHA256) {
      throw new SVIDBindingError(
        `binding alg ${JSON.stringify(alg)} does not match ECDSA leaf key`,
      );
    }
    const curve = pub.asymmetricKeyDetails?.namedCurve;
    if (curve !== "prime256v1") {
      throw new SVIDBindingError(`ECDSA leaf curve ${String(curve)}, binding alg requires P-256`);
    }
    let ok = false;
    try {
      ok = cryptoVerify("sha256", msg, { key: pub, dsaEncoding: "der" }, sig);
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new SVIDBindingError("ECDSA proof-of-possession does not verify");
    }
    return;
  }

  if (keyType === "ed25519") {
    if (alg !== BINDING_ALG_ED25519) {
      throw new SVIDBindingError(
        `binding alg ${JSON.stringify(alg)} does not match Ed25519 leaf key`,
      );
    }
    let ok = false;
    try {
      ok = cryptoVerify(null, msg, pub, sig);
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new SVIDBindingError("Ed25519 proof-of-possession does not verify");
    }
    return;
  }

  throw new SVIDBindingError(`unsupported SVID leaf key type ${String(keyType)}`);
}

// decodeEvidenceBase64 strictly decodes a standard-base64 producer field. A bad
// encoding fails closed (SVIDBindingError) -- the evidence is attacker input, so
// it withholds claims rather than erroring the envelope.
function decodeEvidenceBase64(b64: string, field: string): Buffer {
  const buf = Buffer.from(b64, "base64");
  if (buf.toString("base64") !== b64) {
    throw new SVIDBindingError(`${field}: not standard base64`);
  }
  return buf;
}

// decodeNonceBase64Url strictly decodes a base64url (no padding) producer nonce.
function decodeNonceBase64Url(b64url: string): Buffer {
  const buf = Buffer.from(b64url, "base64url");
  // Re-encode and compare to reject padding / non-base64url input the way Go's
  // base64.RawURLEncoding does (strict, no padding).
  if (buf.toString("base64url") !== b64url) {
    throw new SVIDBindingError("nonce not base64url (no padding)");
  }
  return buf;
}

// verifySVIDBinding verifies that the SVID evidence is a genuine, receipt-bound
// X.509-SVID workload-identity proof. It fails closed: any structural problem,
// chain-validation failure, digest/signer/spiffe mismatch, or bad PoP signature
// throws SVIDBindingError. On success it returns the validated SPIFFE ID. Mirrors
// internal/aarp.VerifySVIDBinding step for step.
export function verifySVIDBinding(e: Envelope, ev: SVIDEvidence, opts: SVIDVerifyOptions): string {
  // 1. Only an X.509-SVID counts as verified attestation; JWT is bearer-only.
  if (ev.type !== "x509") {
    throw new SVIDBindingError(
      `evidence type ${JSON.stringify(ev.type)} (only x509 counts as verified attestation)`,
    );
  }
  // 2. issued_at must be a valid RFC3339Nano timestamp.
  try {
    validateTimestamp(ev.issued_at);
  } catch (err) {
    throw new SVIDBindingError(`issued_at: ${(err as Error).message}`);
  }
  // 3. nonce must be base64url (no padding) decoding to >= 16 bytes.
  const nonceBytes = decodeNonceBase64Url(ev.nonce);
  if (nonceBytes.length < MIN_NONCE_BYTES) {
    throw new SVIDBindingError(`nonce ${nonceBytes.length} bytes, want >= ${MIN_NONCE_BYTES}`);
  }
  // 4. binding.context must equal the SVID binding domain separator.
  if (ev.binding.context !== CONTEXT_SVID_BINDING) {
    throw new SVIDBindingError(`binding context ${JSON.stringify(ev.binding.context)}`);
  }

  // 5. Offline point-in-time chain validation at action_time.
  const { leaf, spiffeID } = validateSVID(ev, opts);

  // 6. The claimed spiffe_id must equal the validated URI SAN (no substitution),
  //    and be permitted by allowed_spiffe_ids when that set is non-empty.
  if (ev.spiffe_id !== spiffeID) {
    throw new SVIDBindingError(
      `evidence spiffe_id ${JSON.stringify(ev.spiffe_id)} != validated ${JSON.stringify(spiffeID)}`,
    );
  }
  if (!spiffeIDPermitted(spiffeID, opts.allowedSpiffeIDs)) {
    throw new SVIDBindingError(
      `spiffe_id not permitted by trust policy: ${JSON.stringify(spiffeID)}`,
    );
  }

  // 7. The signed assertion must declare the same trust domain the SVID validated
  //    against (trust-domain confusion). trust_domain is required with a binding.
  if (e.assertion.trust_domain === undefined || e.assertion.trust_domain === "") {
    throw new SVIDBindingError("assertion.trust_domain is required with an SVID binding");
  }
  if (e.assertion.trust_domain !== opts.trustDomain) {
    throw new SVIDBindingError(
      `assertion trust_domain ${JSON.stringify(e.assertion.trust_domain)} != validated SVID trust domain ${JSON.stringify(opts.trustDomain)}`,
    );
  }

  // 8. issued_at must fall within the leaf [NotBefore, NotAfter] window (post-
  //    expiry key use rejected even when the chain validates at action time).
  //    Compare in NANOSECONDS, not `new Date(...).getTime()` (millisecond): Go
  //    parses issued_at with time.RFC3339Nano (nanosecond precision) and the
  //    boundary is exact, so an issued_at one nanosecond past a whole-second
  //    leaf NotAfter must be rejected. Truncating to ms would equalize them and
  //    spuriously accept. Leaf window bounds are whole seconds in the corpus, so
  //    ms*1e6 is their exact nanosecond value.
  const issuedAtNanos = rfc3339ToUnixNanos(ev.issued_at);
  const leafNotBeforeNanos = BigInt(certNotBeforeMs(leaf)) * 1_000_000n;
  const leafNotAfterNanos = BigInt(certNotAfterMs(leaf)) * 1_000_000n;
  if (issuedAtNanos < leafNotBeforeNanos || issuedAtNanos > leafNotAfterNanos) {
    throw new SVIDBindingError(
      `binding issued_at ${ev.issued_at} outside the SVID leaf validity window`,
    );
  }

  // 9. The PoP signature must verify under the leaf public key over the canonical
  //    binding payload (curve-enforced for ECDSA).
  const canonical = bindingCanonical(e, ev);
  if (ev.binding.payload_sha256 !== "") {
    const want = hexSHA256(canonical);
    if (ev.binding.payload_sha256 !== want) {
      throw new SVIDBindingError("binding payload_sha256 mismatch");
    }
  }
  const sig = decodeEvidenceBase64(ev.binding.signature_b64, "binding.signature_b64");
  verifyLeafSignature(leaf, ev.binding.alg, canonical, sig);

  return spiffeID;
}

// spiffeIDPermitted reports whether id is in the allowed set. An empty allowed
// set permits any validated SPIFFE ID in the (already verified) trust domain.
function spiffeIDPermitted(id: string, allowed: string[]): boolean {
  if (allowed.length === 0) return true;
  return allowed.includes(id);
}

// addSVIDClaims attaches the workload-identity claims when the assertion is
// signed AND the binding verifies. An unsigned assertion (the binding ties to the
// signed assertion digest) or a failed binding withholds all three claims with a
// warning -- never removes a core claim, never errors the envelope. Mirrors
// internal/aarp.addSVIDClaims.
export function addSVIDClaims(
  ap: Appraisal,
  e: Envelope,
  ev: SVIDEvidence,
  opts: SVIDVerifyOptions,
): void {
  if (!ap.assertion_signed) {
    ap.warnings.push(
      "SVID evidence present but assertion not signed; workload identity reported claim-only",
    );
    return;
  }
  try {
    verifySVIDBinding(e, ev, opts);
  } catch (err) {
    // Fail-closed: ANY error from binding verification on attacker-supplied
    // evidence withholds the three claims with a warning and NEVER errors the
    // envelope or exits non-zero. The Go reference (addSVIDClaims) absorbs every
    // error returned by VerifySVIDBinding the same way. Catching only
    // SVIDBindingError would let an unexpected error class (e.g. a
    // CanonicalizeError on attacker content, or a number/grammar error surfacing
    // from a helper) become envelope-fatal -- a withholdable failure must never
    // crash the appraisal. There is no genuinely-impossible-programmer-state
    // throw to preserve here, so all errors are absorbed.
    const message = err instanceof Error ? err.message : String(err);
    ap.warnings.push(`SVID attestation did not verify: ${message}`);
    return;
  }
  addVerified(ap, CLAIM_WORKLOAD_IDENTITY_VERIFIED, AXIS_IDENTITY);
  addVerified(ap, CLAIM_X509_SVID_BOUND, AXIS_IDENTITY);
  addVerified(ap, CLAIM_SVID_VALID_AT_ACTION_TIME, AXIS_FRESHNESS);
}

// appraiseWithSVID runs the core appraisal and, when SVID evidence verifies on a
// signed assertion, adds the workload-identity claims, then classifies. Mirrors
// internal/aarp.AppraiseWithSVID. Throws only envelope-fatal errors (from
// appraiseCore); SVID failures are absorbed fail-closed inside addSVIDClaims.
export function appraiseWithSVID(
  e: Envelope,
  ev: SVIDEvidence,
  opts: VerifyOptions,
  svidOpts: SVIDVerifyOptions,
): Appraisal {
  const ap = appraiseCore(e, opts);
  addSVIDClaims(ap, e, ev, svidOpts);
  classifyClaims(ap);
  return ap;
}

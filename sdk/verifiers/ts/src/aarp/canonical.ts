// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// RFC 8785 JCS canonicalization, ported to match Go's
// internal/contract.Canonicalize byte-for-byte:
//
//   - strings are NFC-normalized (String.prototype.normalize("NFC")),
//   - object keys are sorted ascending by Unicode code point,
//   - output is compact (no insignificant whitespace),
//   - the bytes < > & and U+2028/U+2029 are escaped the way Go's
//     encoding/json does by default,
//   - floats are rejected; only integer numbers are emitted.
//
// This is the single canonicalizer used both to recompute the signed payload
// digest and to emit the comparable appraisal output, exactly as the Go
// reference uses one Canonicalize for both surfaces.

// compareCodePointStrings orders two strings ascending by Unicode code point,
// matching Go's lexicographic comparison of the NFC-normalized UTF-8 key bytes.
// Iterating by code point (Array.from) rather than UTF-16 code unit keeps
// supplementary-plane keys ordered the way Go orders their UTF-8 bytes.
export function compareCodePointStrings(a: string, b: string): number {
  const left = Array.from(a);
  const right = Array.from(b);
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i++) {
    const leftCodePoint = left[i]?.codePointAt(0) ?? 0;
    const rightCodePoint = right[i]?.codePointAt(0) ?? 0;
    if (leftCodePoint !== rightCodePoint) return leftCodePoint - rightCodePoint;
  }
  return left.length - right.length;
}

// goHTMLEscape applies the same default escaping Go's encoding/json does to a
// JSON-serialized string or document: < > & become their \u00xx forms and the
// JSON-unsafe line/paragraph separators U+2028/U+2029 become \u2028/\u2029.
// JSON.stringify and Go's encoding/json already agree on quote, backslash, and
// C0 control escaping, so only these five bytes need fixing up.
function goHTMLEscape(serialized: string): string {
  return serialized
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/gu, "\\u2028")
    .replace(/\u2029/gu, "\\u2029");
}

// replaceSurrogates matches Go encoding/json's handling of UNPAIRED UTF-16
// surrogate code units: a lone high or low surrogate becomes U+FFFD before
// normalization and JSON string escaping. A VALID surrogate pair (high followed
// by low) is a legitimate astral code point (e.g. an emoji) and MUST be
// preserved intact -- naively replacing every surrogate code unit would mangle
// astral characters to two U+FFFD, computing different canonical bytes than Go,
// Rust, and Python, which is exactly the cross-language divergence this corpus
// exists to prevent. The strict parser already substitutes lone surrogates at
// decode time, so this is a defense-in-depth pass that must not corrupt pairs.
function replaceSurrogates(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += s[i]! + s[i + 1]!; // valid astral pair: keep both code units
        i++;
        continue;
      }
      out += "\uFFFD"; // lone high surrogate
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      out += "\uFFFD"; // lone low surrogate
      continue;
    }
    out += s[i] ?? "";
  }
  return out;
}

// CanonicalizeError mirrors the Go canonicalizer's fatal conditions: a float (or
// non-integer number), an unsupported value type, or an NFC key collision.
export class CanonicalizeError extends Error {
  readonly code = 1;
}

// encodeString NFC-normalizes a string and emits its Go-encoding/json escaping.
function encodeString(s: string): string {
  return goHTMLEscape(JSON.stringify(replaceSurrogates(s).normalize("NFC")));
}

// isPlainObject narrows to a non-array, non-null object.
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// canonicalizeValue serializes a single JSON value into the buffer of pieces.
// Numbers are validated as safe integers earlier (enforceSafeNumbers) for parsed
// envelopes; here we still reject any float we are handed so the comparable-output
// path (which builds objects directly) can never emit a non-integer number.
function canonicalizeValue(v: unknown, out: string[]): void {
  if (v === null || v === undefined) {
    out.push("null");
    return;
  }
  if (typeof v === "boolean") {
    out.push(v ? "true" : "false");
    return;
  }
  if (typeof v === "string") {
    out.push(encodeString(v));
    return;
  }
  if (typeof v === "bigint") {
    out.push(v.toString());
    return;
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      throw new CanonicalizeError(`float not allowed in canonicalization: ${v}`);
    }
    out.push(String(v));
    return;
  }
  if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out.push(",");
      canonicalizeValue(v[i], out);
    }
    out.push("]");
    return;
  }
  if (isPlainObject(v)) {
    canonicalizeObject(v, out);
    return;
  }
  throw new CanonicalizeError(`unsupported type in canonicalization: ${typeof v}`);
}

// canonicalizeObject sorts keys by NFC code point and rejects NFC collisions,
// mirroring the Go canonicalizer's duplicate-after-normalization guard.
function canonicalizeObject(obj: Record<string, unknown>, out: string[]): void {
  const pairs = Object.keys(obj).map((orig) => ({
    nfc: replaceSurrogates(orig).normalize("NFC"),
    orig,
  }));
  pairs.sort((a, b) => compareCodePointStrings(a.nfc, b.nfc));
  for (let i = 1; i < pairs.length; i++) {
    const cur = pairs[i];
    const prev = pairs[i - 1];
    if (cur && prev && cur.nfc === prev.nfc && cur.orig !== prev.orig) {
      throw new CanonicalizeError(`NFC collision between ${prev.orig} and ${cur.orig}`);
    }
  }
  out.push("{");
  for (let i = 0; i < pairs.length; i++) {
    const p = pairs[i];
    if (!p) continue;
    if (i > 0) out.push(",");
    out.push(goHTMLEscape(JSON.stringify(p.nfc)));
    out.push(":");
    canonicalizeValue(obj[p.orig], out);
  }
  out.push("}");
}

// canonicalize returns the JCS-canonical UTF-8 string for the given value.
export function canonicalize(v: unknown): string {
  const out: string[] = [];
  canonicalizeValue(v, out);
  return out.join("");
}

// canonicalizeBytes returns the JCS-canonical bytes for the given value.
export function canonicalizeBytes(v: unknown): Buffer {
  return Buffer.from(canonicalize(v), "utf8");
}

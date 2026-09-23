// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// The Go reference verifier hashes a v1 receipt as json.Marshal(Receipt). The
// top-level ext bag is a json.RawMessage, so its bytes in that preimage are the
// SOURCE bytes of the ext value, compacted and HTML-escaped by encoding/json,
// with key order, number spelling, and string escape spelling kept verbatim.
// Re-serializing a parsed value cannot reproduce that: JavaScript reorders
// integer-like object keys and respells numbers and escapes. This module
// recovers the ext value's source span from the recorder line and re-encodes
// it the way Go does, so the chain link hash matches the Go producer byte for
// byte. The ext VALUE stays unsigned and advisory; only its bytes join the
// link hash.

interface ExtSource {
  bytes: string;
  snapshot: string;
}

const extSources = new WeakMap<object, ExtSource>();

const whitespace = new Set([" ", "\t", "\n", "\r"]);

function skipWhitespace(text: string, i: number): number {
  while (i < text.length && whitespace.has(text[i] as string)) i++;
  return i;
}

// skipString returns the index just past the closing quote of the JSON string
// that opens at text[i].
function skipString(text: string, i: number): number {
  i++; // opening quote
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\\") {
      i += 2;
      continue;
    }
    i++;
    if (ch === '"') return i;
  }
  throw new Error("unterminated JSON string");
}

// skipValue returns the index just past the JSON value that starts at text[i].
function skipValue(text: string, i: number): number {
  const first = text[i];
  if (first === '"') return skipString(text, i);
  if (first === "{" || first === "[") {
    let depth = 0;
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"') {
        i = skipString(text, i);
        continue;
      }
      if (ch === "{" || ch === "[") depth++;
      if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    throw new Error("unterminated JSON container");
  }
  // Scalar: number, true, false, null. Runs until a structural character or
  // whitespace.
  while (i < text.length && !/[\s,}\]]/u.test(text[i] as string)) i++;
  return i;
}

// objectMemberSpan returns the source span of the value stored under key in
// the JSON object that opens at text[objectStart], or undefined when absent.
// The text must already have passed a strict JSON parse and the duplicate-key
// check, so each key appears at most once.
export function objectMemberSpan(
  text: string,
  objectStart: number,
  key: string,
): { start: number; end: number } | undefined {
  let i = skipWhitespace(text, objectStart);
  if (text[i] !== "{") return undefined;
  i = skipWhitespace(text, i + 1);
  if (text[i] === "}") return undefined;
  while (i < text.length) {
    if (text[i] !== '"') throw new Error("expected JSON object key");
    const keyEnd = skipString(text, i);
    const name = JSON.parse(text.slice(i, keyEnd)) as string;
    i = skipWhitespace(text, keyEnd);
    if (text[i] !== ":") throw new Error("expected ':' after JSON object key");
    const start = skipWhitespace(text, i + 1);
    const end = skipValue(text, start);
    if (name === key) return { start, end };
    i = skipWhitespace(text, end);
    if (text[i] === ",") {
      i = skipWhitespace(text, i + 1);
      continue;
    }
    if (text[i] === "}") return undefined;
    throw new Error("expected ',' or '}' in JSON object");
  }
  throw new Error("unterminated JSON object");
}

// goRawMessageBytes reproduces encoding/json's output for a json.RawMessage:
// insignificant whitespace removed, and <, >, &, U+2028, U+2029 escaped as
// \u003c, \u003e, \u0026, \u2028, \u2029. Every other byte, including existing
// escape sequences and number text, is copied verbatim.
export function goRawMessageBytes(raw: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i] as string;
    if (inString) {
      if (ch === "\\") {
        out += ch + (raw[i + 1] ?? "");
        i++;
        continue;
      }
      if (ch === '"') inString = false;
      out += goEscapeChar(ch);
      continue;
    }
    if (whitespace.has(ch)) continue;
    if (ch === '"') inString = true;
    out += goEscapeChar(ch);
  }
  return out;
}

function goEscapeChar(ch: string): string {
  switch (ch) {
    case "<":
      return "\\u003c";
    case ">":
      return "\\u003e";
    case "&":
      return "\\u0026";
    case "\u2028":
      return "\\u2028";
    case "\u2029":
      return "\\u2029";
    default:
      return ch;
  }
}

// bindRecorderLineExtSource records the Go-encoded ext bytes of the receipt
// carried in a recorder line's detail member, keyed by the parsed detail
// object. No-op when the detail has no ext member.
export function bindRecorderLineExtSource(detail: unknown, line: string): void {
  if (typeof detail !== "object" || detail === null || Array.isArray(detail)) return;
  if ((detail as Record<string, unknown>)["ext"] === undefined) return;
  const detailSpan = objectMemberSpan(line, 0, "detail");
  if (detailSpan === undefined) return;
  const extSpan = objectMemberSpan(line, detailSpan.start, "ext");
  if (extSpan === undefined) return;
  bindExtSource(detail, line.slice(extSpan.start, extSpan.end));
}

// bindExtSource records raw ext source text for a parsed receipt object.
export function bindExtSource(receipt: object, rawExt: string): void {
  const ext = (receipt as Record<string, unknown>)["ext"];
  extSources.set(receipt, {
    bytes: goRawMessageBytes(rawExt),
    snapshot: JSON.stringify(ext) ?? "",
  });
}

// extSourceBytes returns the Go-encoded ext bytes recorded for a receipt, or
// undefined when none were recorded or the parsed ext was changed after it was
// read, in which case the recorded bytes no longer describe it.
export function extSourceBytes(receipt: object): string | undefined {
  const source = extSources.get(receipt);
  if (source === undefined) return undefined;
  const current = JSON.stringify((receipt as Record<string, unknown>)["ext"]) ?? "";
  return current === source.snapshot ? source.bytes : undefined;
}

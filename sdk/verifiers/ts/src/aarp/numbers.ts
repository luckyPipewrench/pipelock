// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Number-safety and typed-string grammars, ported from internal/aarp/numbers.go.
// These guard the cross-language canonicalization: a raw JSON number is allowed
// only inside the I-JSON safe-integer range, and identity/digest/counter/
// timestamp/amount values are typed strings with strict grammars.

import { RawNumber } from "./strictjson.js";

// The I-JSON safe-integer range. Outside it a JavaScript verifier rounds to the
// nearest float64, changing the canonical bytes and breaking the signature.
const MAX_SAFE = (1n << 53n) - 1n;
const MIN_SAFE = -((1n << 53n) - 1n);

// FatalNumberError marks an envelope-fatal number-safety violation. Exit 1.
export class FatalNumberError extends Error {
  readonly code = 1;
}

// GrammarError marks a typed-string grammar violation. Callers wrap it as a
// schema fatal.
export class GrammarError extends Error {
  readonly code = 1;
}

// enforceSafeNumbers walks a parsed strict-JSON tree and rejects any raw number
// that is not a safe integer. It is the structural guard that makes an AARP
// envelope canonicalize identically across languages.
export function enforceSafeNumbers(tree: unknown): void {
  walk(tree, "$");
}

function walk(v: unknown, path: string): void {
  if (v instanceof RawNumber) {
    checkSafeNumber(v.literal, path);
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((item, idx) => walk(item, `${path}[${idx}]`));
    return;
  }
  if (typeof v === "object" && v !== null) {
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      walk(val, `${path}.${k}`);
    }
  }
  // Strings, bools, and null carry no numeric interoperability hazard.
}

// checkSafeNumber validates a single raw JSON number literal: integer only, no
// fractional part, no exponent, not negative zero, within the safe range.
function checkSafeNumber(lit: string, path: string): void {
  if (lit === "") {
    throw new FatalNumberError(`empty number at ${path}`);
  }
  if (/[.eE]/u.test(lit)) {
    throw new FatalNumberError(`float or exponent form ${JSON.stringify(lit)} at ${path}`);
  }
  if (lit === "-0") {
    throw new FatalNumberError(`negative zero at ${path}`);
  }
  let n: bigint;
  try {
    n = BigInt(lit);
  } catch {
    throw new FatalNumberError(`non-integer literal ${JSON.stringify(lit)} at ${path}`);
  }
  if (n > MAX_SAFE || n < MIN_SAFE) {
    throw new FatalNumberError(`${JSON.stringify(lit)} outside I-JSON safe range at ${path}`);
  }
}

// hexDigestLen is the lowercase-hex length of a SHA-256 digest.
const HEX_DIGEST_LEN = 64;

// validateHex256 checks a 64-char lowercase-hex SHA-256 digest grammar.
export function validateHex256(s: string): void {
  if (s.length !== HEX_DIGEST_LEN) {
    throw new GrammarError(`digest length ${s.length}, want ${HEX_DIGEST_LEN}`);
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isDigit = c >= 0x30 && c <= 0x39;
    const isLowerHex = c >= 0x61 && c <= 0x66;
    if (!isDigit && !isLowerHex) {
      throw new GrammarError(`digest contains non-lowercase-hex byte ${JSON.stringify(s[i])}`);
    }
  }
}

// validateUint64String checks an unsigned decimal counter grammar: digits, no
// sign, no leading zero (except the single "0"), within uint64.
const MAX_UINT64 = (1n << 64n) - 1n;

export function validateUint64String(s: string): void {
  if (s === "") {
    throw new GrammarError("empty unsigned counter");
  }
  if (s === "0") {
    return;
  }
  if (s[0] === "0") {
    throw new GrammarError(`leading zero in counter ${JSON.stringify(s)}`);
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) {
      throw new GrammarError(`non-digit in counter ${JSON.stringify(s)}`);
    }
  }
  if (BigInt(s) > MAX_UINT64) {
    throw new GrammarError(`counter ${JSON.stringify(s)} exceeds uint64`);
  }
}

// validateTimestamp checks an RFC 3339 timestamp with nanosecond precision and a
// mandatory zone, matching Go's time.RFC3339Nano accepting parser.
//
// Go's time.Parse(RFC3339Nano) accepts: a date, "T", a time with optional
// fractional seconds (any number of digits), and a zone that is "Z" or
// (+|-)HH:MM. It validates calendar ranges (month 1-12, day in month, etc.).
const RFC3339_RE =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/u;

export function validateTimestamp(s: string): void {
  if (s === "") {
    throw new GrammarError("empty timestamp");
  }
  const m = RFC3339_RE.exec(s);
  if (m === null) {
    throw new GrammarError(`timestamp ${JSON.stringify(s)} is not RFC3339Nano`);
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (month < 1 || month > 12) {
    throw new GrammarError(`timestamp ${JSON.stringify(s)} has invalid month`);
  }
  if (day < 1 || day > daysInMonth(year, month)) {
    throw new GrammarError(`timestamp ${JSON.stringify(s)} has invalid day`);
  }
  // Go allows second up to 60 (leap second) only at 23:59:60; keep it simple and
  // accept 0-59 plus the leap-second value, matching time.Parse leniency band.
  if (hour > 23 || minute > 59 || second > 60) {
    throw new GrammarError(`timestamp ${JSON.stringify(s)} has invalid time`);
  }
  const zone = m[8] as string;
  if (zone !== "Z" && zone !== "z") {
    const zoneHour = Number(zone.slice(1, 3));
    const zoneMinute = Number(zone.slice(4, 6));
    if (zoneHour > 23 || zoneMinute > 59) {
      throw new GrammarError(`timestamp ${JSON.stringify(s)} has invalid zone`);
    }
  }
}

function daysInMonth(year: number, month: number): number {
  const lengths = [31, isLeap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return lengths[month - 1] as number;
}

function isLeap(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

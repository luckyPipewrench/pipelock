// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// The recorder entry hash chain, ported from the Go reference
// internal/recorder (ComputeHash, ValidateEntrySchema, VerifyChain). Every
// recorder entry carries hash = sha256 over a NUL-separated projection of its
// fields, and prev_hash naming the entry before it ("genesis" for the first).
// The chain is unkeyed: it detects an edit that was not followed by
// recomputing the hashes, and anything that recomputes them passes. Receipt
// and checkpoint signatures remain the authenticity boundary. The Go finding
// for a break is outer_chain_broken.
//
// The projection hashes the parsed field values the way Go's encoding/json
// decodes them, so this reads the raw line again rather than trusting a
// generic parse: seq keeps its decimal literal, ts is re-rendered in UTC as
// RFC3339Nano, and detail is the exact source bytes of the value.

import { parseJSONStrict, RawNumber } from "./aarp/strictjson.js";
import { objectMemberSpan } from "./rawjson.js";
import { sha256Hex } from "./util.js";

export const FindingOuterChainBroken = "outer_chain_broken";

const genesisHash = "genesis";
const maxUint64 = 18446744073709551615n;

// RecorderLine is one parsed recorder entry with the line it was read from.
export interface RecorderLine {
  line: string;
}

// The fields Go decodes from a recorder line. Go's encoding/json matches keys
// case-insensitively, so "Summary" would fill summary; such a key is refused
// here instead of hashed as a different field.
const entryFields = [
  "v",
  "seq",
  "ts",
  "session_id",
  "chain_kind",
  "writer_instance_id",
  "trace_id",
  "type",
  "event_kind",
  "transport",
  "summary",
  "detail",
  "raw_ref",
  "prev_hash",
  "hash",
];

function foldKey(key: string): string {
  return [...key].map((ch) => (ch === "ſ" ? "s" : ch === "K" ? "k" : ch.toLowerCase())).join("");
}

// ProjectedEntry is the Go Entry as the hash sees it.
interface ProjectedEntry {
  version: number;
  seq: string;
  ts: string;
  sessionID: string;
  chainKind: string;
  writerInstanceID: string;
  traceID: string;
  type: string;
  eventKind: string;
  transport: string;
  summary: string;
  detail: string;
  rawRef: string;
  prevHash: string;
  hash: string;
}

function projectEntry(line: string): ProjectedEntry {
  const raw = parseJSONStrict(line);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || raw instanceof RawNumber) {
    throw new Error("recorder entry is not a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (entryFields.includes(key)) continue;
    const folded = foldKey(key);
    const alias = entryFields.find((f) => f === folded);
    if (alias !== undefined) {
      throw new Error(`case-folded key "${key}" aliases "${alias}"`);
    }
  }
  const str = (field: string): string => {
    const value = obj[field];
    if (value === undefined || value === null) return "";
    if (typeof value !== "string") throw new Error(`${field} must be a string`);
    return value;
  };
  const v = obj["v"];
  if (!(v instanceof RawNumber) || !["1", "2", "3"].includes(v.literal)) {
    throw new Error("unsupported entry version");
  }
  const version = Number(v.literal);
  let seq = "0";
  const seqValue = obj["seq"];
  if (seqValue !== undefined && seqValue !== null) {
    if (
      !(seqValue instanceof RawNumber) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(seqValue.literal) ||
      BigInt(seqValue.literal) > maxUint64
    ) {
      throw new Error("seq must be an unsigned 64-bit integer");
    }
    seq = seqValue.literal;
  }
  const tsValue = obj["ts"];
  let ts = "0001-01-01T00:00:00Z";
  if (tsValue !== undefined && tsValue !== null) {
    if (typeof tsValue !== "string") throw new Error("ts is not a JSON string");
    ts = goUTCRFC3339Nano(tsValue);
  }
  const span = objectMemberSpan(line, line.indexOf("{"), "detail");
  const e: ProjectedEntry = {
    version,
    seq,
    ts,
    sessionID: str("session_id"),
    chainKind: str("chain_kind"),
    writerInstanceID: str("writer_instance_id"),
    traceID: str("trace_id"),
    type: str("type"),
    eventKind: str("event_kind"),
    transport: str("transport"),
    summary: str("summary"),
    detail: span === undefined ? "null" : line.slice(span.start, span.end),
    rawRef: str("raw_ref"),
    prevHash: str("prev_hash"),
    hash: str("hash"),
  };
  validateEntrySchema(e);
  return e;
}

// validateEntrySchema mirrors Go ValidateEntrySchema: the namespace fields fit
// the version, and no projected string contains the NUL separator.
function validateEntrySchema(e: ProjectedEntry): void {
  if (e.version === 3) {
    if (e.chainKind === "") throw new Error("v3 chain_kind required");
    if (e.writerInstanceID === "") throw new Error("v3 writer_instance_id required");
  } else if (e.chainKind !== "" || e.writerInstanceID !== "") {
    throw new Error("legacy entry cannot carry v3 recorder namespace fields");
  }
  const fields: [string, string][] = [
    ["session_id", e.sessionID],
    ["trace_id", e.traceID],
    ["type", e.type],
    ["transport", e.transport],
    ["summary", e.summary],
    ["raw_ref", e.rawRef],
    ["prev_hash", e.prevHash],
    ["event_kind", e.eventKind],
    ["chain_kind", e.chainKind],
    ["writer_instance_id", e.writerInstanceID],
  ];
  for (const [name, value] of fields) {
    if (value.includes("\u0000")) throw new Error(`v${e.version} ${name} cannot contain NUL`);
  }
}

function hashProjection(e: ProjectedEntry): string {
  const fields = [String(e.version), e.seq, e.ts, e.sessionID];
  if (e.version === 3) fields.push(e.chainKind, e.writerInstanceID);
  fields.push(e.traceID, e.type);
  if (e.version >= 2) fields.push(e.eventKind);
  fields.push(e.transport, e.summary, e.detail, e.rawRef, e.prevHash);
  return sha256Hex(fields.join("\u0000"));
}

// recorderEntryHash returns Go's recorder.ComputeHash for one recorder line.
// It throws when Go would refuse to read the line.
export function recorderEntryHash(line: string): string {
  return hashProjection(projectEntry(line));
}

// verifyRecorderChain mirrors Go recorder.VerifyChain (without checkpoint
// signatures): it returns the first break, with Go's wording, or undefined
// when the chain holds.
export function verifyRecorderChain(lines: readonly RecorderLine[]): string | undefined {
  let namespace: { session: string; kind: string; writer: string } | undefined;
  let prev: ProjectedEntry | undefined;
  for (const { line } of lines) {
    let e: ProjectedEntry;
    try {
      e = projectEntry(line);
    } catch (err) {
      return `entry: ${(err as Error).message}`;
    }
    if (e.version === 3) {
      if (prev !== undefined && prev.version !== 3) {
        return `entry seq ${e.seq}: v3 chain cannot continue a legacy recorder namespace`;
      }
      if (namespace === undefined) {
        namespace = { session: e.sessionID, kind: e.chainKind, writer: e.writerInstanceID };
      } else if (
        e.sessionID !== namespace.session ||
        e.chainKind !== namespace.kind ||
        e.writerInstanceID !== namespace.writer
      ) {
        return `entry seq ${e.seq}: v3 chain namespace changed`;
      }
    } else if (namespace !== undefined) {
      return `entry seq ${e.seq}: legacy entry cannot continue a v3 recorder namespace`;
    }
    const computed = hashProjection(e);
    if (computed !== e.hash) {
      return `entry seq ${e.seq}: hash mismatch: computed ${computed}, stored ${e.hash}`;
    }
    if (prev === undefined) {
      if (e.prevHash !== genesisHash) {
        return `entry seq ${e.seq}: first entry PrevHash should be "${genesisHash}", got "${e.prevHash}"`;
      }
    } else if (e.prevHash !== prev.hash) {
      return `entry seq ${e.seq}: chain break: PrevHash ${e.prevHash} != previous Hash ${prev.hash}`;
    }
    prev = e;
  }
  return undefined;
}

// goUTCRFC3339Nano parses ts the way Go's time.Time.UnmarshalJSON does
// (strict RFC 3339: upper-case T and Z, two-digit fields in range, a real
// calendar day, a numeric offset of at most 23:59, a fraction truncated to
// nanoseconds) and formats the instant as Go's UTC().Format(RFC3339Nano):
// trailing fractional zeros dropped, "Z" for the zone.
export function goUTCRFC3339Nano(ts: string): string {
  const fail = (): never => {
    throw new Error(`parsing time "${ts}": not RFC 3339`);
  };
  const num = (s: string, min: number, max: number): number => {
    if (!/^[0-9]+$/u.test(s)) fail();
    const n = Number(s);
    if (n < min || n > max) fail();
    return n;
  };
  if (ts.length < 19) fail();
  if (ts[4] !== "-" || ts[7] !== "-" || ts[10] !== "T" || ts[13] !== ":" || ts[16] !== ":") fail();
  const year = num(ts.slice(0, 4), 0, 9999);
  const month = num(ts.slice(5, 7), 1, 12);
  const day = num(ts.slice(8, 10), 1, daysIn(year, month));
  const hour = num(ts.slice(11, 13), 0, 23);
  const minute = num(ts.slice(14, 16), 0, 59);
  const second = num(ts.slice(17, 19), 0, 59);
  let rest = ts.slice(19);
  let frac = "";
  if (rest.length >= 2 && rest[0] === "." && /[0-9]/u.test(rest[1] as string)) {
    let n = 1;
    while (n < rest.length && /[0-9]/u.test(rest[n] as string)) n++;
    frac = rest.slice(1, Math.min(n, 10));
    rest = rest.slice(n);
  }
  let offsetMinutes = 0;
  if (rest !== "Z") {
    if (rest.length !== 6 || (rest[0] !== "+" && rest[0] !== "-") || rest[3] !== ":") fail();
    const oh = num(rest.slice(1, 3), 0, 23);
    const om = num(rest.slice(4, 6), 0, 59);
    offsetMinutes = (oh * 60 + om) * (rest[0] === "-" ? -1 : 1);
  }
  const days = daysFromCivil(year, month, day);
  const total = days * 86400 + hour * 3600 + minute * 60 + second - offsetMinutes * 60;
  const utcDays = Math.floor(total / 86400);
  const secOfDay = total - utcDays * 86400;
  const civil = civilFromDays(utcDays);
  if (civil.year < 0 || civil.year > 9999) {
    throw new Error(`time "${ts}" is outside the four-digit year range`);
  }
  const nanos = frac.padEnd(9, "0").replace(/0+$/u, "");
  const pad = (n: number, w: number): string => String(n).padStart(w, "0");
  return (
    `${pad(civil.year, 4)}-${pad(civil.month, 2)}-${pad(civil.day, 2)}` +
    `T${pad(Math.floor(secOfDay / 3600), 2)}:${pad(Math.floor((secOfDay % 3600) / 60), 2)}:${pad(secOfDay % 60, 2)}` +
    `${nanos === "" ? "" : `.${nanos}`}Z`
  );
}

function isLeap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysIn(year: number, month: number): number {
  if (month === 2) return isLeap(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

// daysFromCivil and civilFromDays are Howard Hinnant's proleptic Gregorian
// day-count conversions, days relative to 1970-01-01.
function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function civilFromDays(z: number): { year: number; month: number; day: number } {
  z += 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor(
    (doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365,
  );
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const month = mp + (mp < 10 ? 3 : -9);
  return { year: yoe + era * 400 + (month <= 2 ? 1 : 0), month, day };
}

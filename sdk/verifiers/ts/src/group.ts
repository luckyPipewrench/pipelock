// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  statSync,
} from "node:fs";
import * as path from "node:path";
import * as ed25519 from "@noble/ed25519";
import { parseJSONStrict, RawNumber } from "./aarp/strictjson.js";
import { evidenceChainKey, receiptHash, verifyChain } from "./chain.js";
import {
  parseEvidenceFilename,
  readSessionEvidence,
  sessionEvidenceFiles,
  withPinnedEvidenceDirectory,
} from "./chain-set.js";
import { extractTypedFromEntries, parseEntryLinesText } from "./recorder.js";
import { verifyRecorderChain } from "./recorder-chain.js";
import type { Receipt, RecorderEntry } from "./types.js";
import { goJSONMarshal, isCanonicalUTCTimestamp } from "./rotation.js";
import { decodeUTF8, sha256Hex } from "./util.js";
import { trimGoSpace } from "./line-space.js";

export type ReceiptGroupVerdict = "GROUP_VALID" | "GROUP_INCOMPLETE" | "GROUP_INVALID";
export interface ReceiptGroupResult {
  group_id: string;
  base_session?: string;
  verdict: ReceiptGroupVerdict;
  open_manifest_sha256?: string;
  close_manifest_sha256?: string;
  shard_count: number;
  error?: string;
}

interface GroupShard {
  shard_index: number;
  session_id: string;
}
interface GroupOpen {
  version: number;
  kind: string;
  group_id: string;
  base_session: string;
  shard_count: number;
  process_shard_index: number;
  signer_key: string;
  shards: GroupShard[];
  previous_group_id: string;
  previous_open_manifest_sha256: string;
  created_at: string;
  signature: string;
}
interface GroupHead {
  shard_index: number;
  session_id: string;
  final_chain_seq: number;
  final_chain_hash: string;
  receipt_count: number;
  session_close_hash: string;
  transcript_root_hash: string;
  checkpoint_hash: string;
  native_ael_final_seq: number;
  native_ael_final_hash: string;
  native_ael_record_count: number;
}
interface GroupClose {
  version: number;
  kind: string;
  group_id: string;
  open_manifest_sha256: string;
  status: string;
  shards: GroupHead[];
  closed_at: string;
  signer_key: string;
  signature: string;
}
interface GroupPredecessor {
  shard_index: number;
  session_id: string;
  final_chain_seq: number;
  final_chain_hash: string;
  recovery_seal_sha256: string;
}
interface GroupTransition {
  version: number;
  kind: string;
  new_group_id: string;
  new_open_manifest_sha256: string;
  previous_group_id: string;
  previous_open_manifest_sha256: string;
  previous_close_manifest_sha256: string;
  predecessors: GroupPredecessor[];
  created_at: string;
  signer_key: string;
  signature: string;
}

const openFields = [
  "version",
  "kind",
  "group_id",
  "base_session",
  "shard_count",
  "process_shard_index",
  "signer_key",
  "shards",
  "previous_group_id",
  "previous_open_manifest_sha256",
  "created_at",
  "signature",
];
const closeFields = [
  "version",
  "kind",
  "group_id",
  "open_manifest_sha256",
  "status",
  "shards",
  "closed_at",
  "signer_key",
  "signature",
];
const headFields = [
  "shard_index",
  "session_id",
  "final_chain_seq",
  "final_chain_hash",
  "receipt_count",
  "session_close_hash",
  "transcript_root_hash",
  "checkpoint_hash",
  "native_ael_final_seq",
  "native_ael_final_hash",
  "native_ael_record_count",
];
const transitionFields = [
  "version",
  "kind",
  "new_group_id",
  "new_open_manifest_sha256",
  "previous_group_id",
  "previous_open_manifest_sha256",
  "previous_close_manifest_sha256",
  "predecessors",
  "created_at",
  "signer_key",
  "signature",
];
const predecessorFields = [
  "shard_index",
  "session_id",
  "final_chain_seq",
  "final_chain_hash",
  "recovery_seal_sha256",
];
const openDomain = "pipelock/receipt-group-open/v1";
const closeDomain = "pipelock/receipt-group-close/v1";
const transitionDomain = "pipelock/receipt-group-transition/v1";
const recoveryDomain = "pipelock-recovery-seal-v1\u0000";

function object(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof RawNumber
  )
    throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function materialize(value: unknown): unknown {
  if (value instanceof RawNumber) return safeNumber(value, "number");
  if (Array.isArray(value)) return value.map(materialize);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, materialize(v)]));
  }
  return value;
}
function sortedJSONValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedJSONValue);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sortedJSONValue(v)]),
    );
  }
  return value;
}
function strictObject(
  raw: Buffer,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  if (raw.length === 0 || raw.length > 128 * 1024) throw new Error(`${label} size invalid`);
  const parsed = object(parseJSONStrict(decodeUTF8(raw, label)), label);
  for (const key of Object.keys(parsed))
    if (!fields.includes(key)) throw new Error(`${label} has unknown field ${key}`);
  if (
    Object.keys(parsed).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(parsed, key))
  )
    throw new Error(`${label} is missing a field`);
  // Canonical Go JSON has struct field order and no insignificant whitespace.
  if (decodeUTF8(raw, label) !== goJSONMarshal(materialize(parsed)))
    throw new Error(`${label} is not canonical JSON`);
  return parsed;
}
function safeNumber(v: unknown, label: string, max = Number.MAX_SAFE_INTEGER): number {
  if (!(v instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(v.literal))
    throw new Error(`${label} must be an unsigned integer`);
  const n = Number(v.literal);
  if (!Number.isSafeInteger(n) || n > max) throw new Error(`${label} exceeds safe integer range`);
  return n;
}
function str(v: unknown, label: string): string {
  if (typeof v !== "string") throw new Error(`${label} must be a string`);
  return v;
}
function isHex(v: string, length: number): boolean {
  return new RegExp(`^[0-9a-f]{${length}}$`, "u").test(v);
}
function canonicalOrdered(raw: Record<string, unknown>, fields: readonly string[]): string {
  const out: Record<string, unknown> = {};
  const normalized = materialize(raw) as Record<string, unknown>;
  for (const f of fields) if (f !== "signature") out[f] = normalized[f];
  return goJSONMarshal(out);
}
async function verifySignature(
  raw: Record<string, unknown>,
  fields: readonly string[],
  domain: string,
  trusted: Set<string>,
): Promise<void> {
  const signer = str(raw.signer_key, "signer_key");
  if (!isHex(signer, 64) || !trusted.has(signer))
    throw new Error("receipt group signer is not trusted");
  const sigText = str(raw.signature, "signature");
  if (!sigText.startsWith("ed25519:") || !isHex(sigText.slice(8), 128))
    throw new Error("invalid receipt group signature encoding");
  const sig = Buffer.from(sigText.slice(8), "hex");
  const key = Buffer.from(signer, "hex");
  const message = Buffer.from(domain + canonicalOrdered(raw, fields), "utf8");
  if (!(await ed25519.verifyAsync(sig, message, key, { zip215: false })))
    throw new Error("receipt group signature verification failed");
}
function sha(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function canonicalTime(s: string): boolean {
  return isCanonicalUTCTimestamp(s);
}
function parseOpen(raw: Buffer): GroupOpen {
  const o = strictObject(raw, openFields, "receipt group opening");
  const version = safeNumber(o.version, "version");
  const shardCount = safeNumber(o.shard_count, "shard_count", 32);
  const index = safeNumber(o.process_shard_index, "process_shard_index", 31);
  if (
    version !== 1 ||
    o.kind !== "receipt_group_open" ||
    shardCount < 2 ||
    shardCount > 32 ||
    !Array.isArray(o.shards) ||
    o.shards.length !== shardCount ||
    index >= shardCount
  )
    throw new Error("invalid receipt group opening identity");
  const groupID = str(o.group_id, "group_id"),
    signer = str(o.signer_key, "signer_key"),
    base = str(o.base_session, "base_session");
  if (
    !isHex(groupID, 32) ||
    !isHex(signer, 64) ||
    base.length === 0 ||
    base.includes("/") ||
    base.includes("\\") ||
    base.includes(".run.") ||
    !canonicalTime(str(o.created_at, "created_at"))
  )
    throw new Error("invalid receipt group opening fields");
  const prevID = str(o.previous_group_id, "previous_group_id"),
    prevHash = str(o.previous_open_manifest_sha256, "previous_open_manifest_sha256");
  if (
    (prevID === "") !== (prevHash === "") ||
    (prevID !== "" && (!isHex(prevID, 32) || !isHex(prevHash, 64) || prevID === groupID))
  )
    throw new Error("invalid receipt group predecessor binding");
  const shards = o.shards.map((rawShard, i) => {
    const s = object(rawShard, `shard ${i}`);
    if (
      Object.keys(s).length !== 2 ||
      Object.keys(s).some((k) => !["shard_index", "session_id"].includes(k))
    )
      throw new Error(`invalid shard ${i} schema`);
    const shardIndex = safeNumber(s.shard_index, "shard_index", 31),
      session = str(s.session_id, "session_id");
    if (
      shardIndex !== i ||
      !session.startsWith(`${base}.run.`) ||
      !isHex(session.slice(`${base}.run.`.length), 32)
    )
      throw new Error(`invalid group shard ${i}`);
    return { shard_index: shardIndex, session_id: session };
  });
  if (new Set(shards.map((s) => s.session_id)).size !== shards.length)
    throw new Error("duplicate receipt group session");
  return {
    ...o,
    version,
    kind: String(o.kind),
    shard_count: shardCount,
    process_shard_index: index,
    group_id: groupID,
    signer_key: signer,
    base_session: base,
    shards: shards as GroupShard[],
    previous_group_id: prevID,
    previous_open_manifest_sha256: prevHash,
    created_at: o.created_at as string,
    signature: o.signature as string,
  } as GroupOpen;
}
function normalizeNumbers(
  raw: Record<string, unknown>,
  fields: readonly string[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const f of fields) {
    const v = raw[f];
    if (v instanceof RawNumber) result[f] = safeNumber(v, f);
    else if (Array.isArray(v))
      result[f] = v.map((x) =>
        normalizeNumbers(object(x, f), f === "shards" ? headFields : predecessorFields),
      );
    else result[f] = v;
  }
  return result;
}
export function readBoundedArtifactBytes(
  name: string,
  initialSize: number,
  max: number,
  readAt: (buffer: Buffer, offset: number, length: number, position: number) => number,
): Buffer {
  if (initialSize > max) throw new Error(`artifact ${name} exceeds size limit`);
  const data = Buffer.alloc(initialSize);
  let off = 0;
  while (off < data.length) {
    const n = readAt(data, off, data.length - off, off);
    if (n <= 0) throw new Error(`artifact ${name} truncated during read`);
    off += n;
  }
  const growth = Buffer.alloc(1);
  if (readAt(growth, 0, 1, off) !== 0)
    throw new Error(`artifact ${name} exceeds size limit during read`);
  return data;
}

function readChild(name: string, max = 128 * 1024): Buffer {
  const before = lstatSync(name, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink())
    throw new Error(`artifact ${name} is not a regular file`);
  const fd = openSync(name, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size > BigInt(max))
      throw new Error(`artifact ${name} changed or exceeds size limit`);
    const data = readBoundedArtifactBytes(
      name,
      Number(opened.size),
      max,
      (buffer, offset, length, position) => readSync(fd, buffer, offset, length, position),
    );
    const after = fstatSync(fd, { bigint: true });
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs
    )
      throw new Error(`artifact ${name} changed during read`);
    return data;
  } finally {
    closeSync(fd);
  }
}

function existsNoFollow(name: string): boolean {
  try {
    lstatSync(name);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
}

// A torn final write does not erase a complete first group gate. Inspect the
// first terminated entry before the legacy directory command selects a path.
export function receiptGroupEvidencePresent(dir: string): boolean {
  for (const name of readdirSync(dir)) {
    if (name.startsWith("receipt-group-")) return true;
    const parsed = parseEvidenceFilename(name);
    if (!parsed || parsed.seqStart !== 0n) continue;
    const child = path.join(dir, name);
    const kind = lstatSync(child);
    if (!kind.isFile() || kind.isSymbolicLink()) continue;
    let raw: Buffer;
    try {
      raw = readChild(child, 128 << 20);
    } catch {
      // Legacy verification reports malformed or changing shard files.
      continue;
    }
    const end = raw.indexOf(0x0a);
    if (end < 0) continue;
    try {
      const first = object(
        parseJSONStrict(decodeUTF8(raw.subarray(0, end), "first recorder entry")),
        "first recorder entry",
      );
      if (first.type === "receipt_group_v1") return true;
    } catch {
      // A malformed legacy first entry belongs to the legacy verifier.
    }
  }
  return false;
}

interface AELHead {
  finalSeq: number;
  finalHash: string;
  recordCount: number;
}
async function verifyAELRun(run: string, signer: string, requireClose = true): Promise<AELHead> {
  if (!isHex(run, 32) || !isHex(signer, 64)) throw new Error("invalid native AEL run binding");
  const pub = Buffer.from(signer, "hex"),
    keyID = sha(pub),
    dir = path.join("ael", run);
  for (const name of ["ael", dir, path.join(dir, "keys"), path.join(dir, "recorders")]) {
    const st = lstatSync(name);
    if (!st.isDirectory() || st.isSymbolicLink())
      throw new Error(`native AEL path ${name} is redirected`);
  }
  const manifest = readChild(path.join(dir, "manifest.json"), 4096).toString("utf8");
  const expectedManifest = JSON.stringify({
    ael_format: 1,
    coverage: "mediated-only",
    custody: "same-process",
    recorders: [{ file: "recorders/pipelock.jsonl", id: "pipelock", key: keyID, run }],
    runs: [run],
  });
  if (manifest !== expectedManifest)
    throw new Error("native AEL manifest differs from signed run layout");
  if (
    readChild(path.join(dir, "keys", `${keyID}.pub`), 128).toString("ascii") !==
    pub.toString("base64")
  )
    throw new Error("native AEL published key differs from trusted signer");
  const stream = readChild(path.join(dir, "recorders", "pipelock.jsonl"), 256 << 20);
  const lines = stream.toString("utf8").split("\n");
  const final = lines.pop();
  if (requireClose && final !== "") throw new Error("native AEL stream has torn line");
  let prev = "0".repeat(64),
    count = 0,
    closed = false;
  for (const rawLine of lines) {
    const line = trimGoSpace(rawLine);
    if (line === "") continue;
    if (closed) throw new Error("native AEL has empty line or records after close");
    const pieces = line.split(".");
    if (pieces.length !== 2) throw new Error("invalid native AEL compact record");
    const payload = Buffer.from(pieces[0] as string, "base64url"),
      sig = Buffer.from(pieces[1] as string, "base64url");
    if (
      payload.toString("base64url") !== pieces[0] ||
      sig.toString("base64url") !== pieces[1] ||
      sig.length !== 64 ||
      !(await ed25519.verifyAsync(sig, payload, pub, { zip215: false }))
    )
      throw new Error("invalid native AEL signature or encoding");
    const value = object(parseJSONStrict(decodeUTF8(payload, "native AEL")), "native AEL record");
    const canonical = goJSONMarshal(sortedJSONValue(materialize(value)));
    if (canonical !== payload.toString("utf8"))
      throw new Error("native AEL payload is not canonical JSON");
    const seq = safeNumber(value.seq, "native AEL seq");
    const kind = str(value.type, "native AEL type");
    if (
      safeNumber(value.v, "native AEL version") !== 1 ||
      value.run !== run ||
      value.recorder !== "pipelock" ||
      value.key !== keyID ||
      value.prev !== prev ||
      seq !== count
    )
      throw new Error(`native AEL record ${count} breaks run binding or chain`);
    if (!canonicalTime(str(value.ts, "native AEL timestamp")))
      throw new Error(`native AEL record ${count} has invalid timestamp`);
    const allowed = [
      "v",
      "type",
      "run",
      "recorder",
      "key",
      "prev",
      "seq",
      "ts",
      ...(kind === "open"
        ? ["hmax", "htol"]
        : kind === "activity"
          ? ["event"]
          : kind === "close"
            ? ["count", "head"]
            : []),
    ];
    if (
      Object.keys(value).length !== allowed.length ||
      Object.keys(value).some((k) => !allowed.includes(k))
    )
      throw new Error("native AEL record fields differ from type schema");
    if (
      (count === 0) !== (kind === "open") ||
      (kind !== "open" && !["activity", "heartbeat", "close"].includes(kind))
    )
      throw new Error("invalid native AEL lifecycle order");
    if (
      kind === "open" &&
      safeNumber(value.htol, "native AEL heartbeat tolerance") >
        safeNumber(value.hmax, "native AEL heartbeat maximum")
    )
      throw new Error("invalid native AEL heartbeat bounds");
    if (kind === "activity") {
      const event = object(value.event, "native AEL event");
      if (
        Object.keys(event).length !== 3 ||
        typeof event.class !== "string" ||
        event.class === "" ||
        typeof event.id !== "string" ||
        event.id === "" ||
        !["in", "out", "internal"].includes(String(event.dir))
      )
        throw new Error("invalid native AEL activity");
    }
    if (
      kind === "close" &&
      (safeNumber(value.count, "native AEL close count") !== count + 1 || value.head !== prev)
    )
      throw new Error("native AEL close head or count differs");
    prev = sha(payload);
    count++;
    closed = kind === "close";
  }
  if (requireClose && (!closed || count < 2)) throw new Error("native AEL run has no signed close");
  if (closed && final !== "") throw new Error("native AEL stream continues after close");
  return { finalSeq: Math.max(count - 1, 0), finalHash: prev, recordCount: count };
}

function fileInventory(): string {
  const digest = createHash("sha256");
  const walk = (dir: string, prefix: string): void => {
    for (const de of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    )) {
      const child = path.join(dir, de.name),
        rel = prefix ? `${prefix}/${de.name}` : de.name;
      const s = lstatSync(child, { bigint: true });
      digest.update(`${rel}\0${s.dev}:${s.ino}:${s.mode}:${s.size}:${s.mtimeNs}\n`);
      if (s.isDirectory() && !s.isSymbolicLink()) walk(child, rel);
    }
  };
  walk(".", "");
  return digest.digest("hex");
}

async function verifyGroupAt(
  groupID: string,
  trustedKeys: readonly string[],
): Promise<ReceiptGroupResult> {
  const result: ReceiptGroupResult = {
    group_id: groupID,
    verdict: "GROUP_INVALID",
    shard_count: 0,
  };
  try {
    if (!isHex(groupID, 32)) throw new Error("invalid receipt group ID");
    const trusted = new Set(trustedKeys.map((k) => k.trim().toLowerCase()).filter(Boolean));
    if (!trusted.size) throw new Error("receipt group verification requires a trusted signer key");
    const rootStart = statSync(".", { bigint: true }),
      aelStart = statSync("ael", { bigint: true });
    const before = fileInventory();
    for (const name of readdirSync(".")) {
      if (
        name.startsWith("receipt-group-") &&
        !/^receipt-group-[0-9a-f]{32}-(?:open|close|transition)\.json$/u.test(name)
      )
        throw new Error(`unknown receipt group artifact ${JSON.stringify(name)}`);
    }
    const openBytes = readChild(`receipt-group-${groupID}-open.json`);
    const openRaw = strictObject(openBytes, openFields, "receipt group opening");
    const open = parseOpen(openBytes);
    await verifySignature(openRaw, openFields, openDomain, trusted);
    if (open.group_id !== groupID) throw new Error("receipt group opening ID mismatch");
    result.base_session = open.base_session;
    result.shard_count = open.shards.length;
    result.open_manifest_sha256 = sha(openBytes);
    const closeName = `receipt-group-${groupID}-close.json`;
    let closeBytes: Buffer;
    try {
      closeBytes = readChild(closeName);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      // Do not promote absent close to success; still validate any successor claim and inventory.
      await verifySuccessorTransitionInventory(open, result.open_manifest_sha256, "", trusted);
      await verifyAELInventory(open, trusted, true);
      checkDirectoryIdentity(rootStart, aelStart, before);
      result.verdict = "GROUP_INCOMPLETE";
      result.error = "receipt group has no signed close manifest";
      return result;
    }
    const closeRaw = strictObject(closeBytes, closeFields, "receipt group close");
    const close = normalizeNumbers(closeRaw, closeFields) as unknown as GroupClose;
    await verifySignature(closeRaw, closeFields, closeDomain, trusted);
    if (
      close.version !== 1 ||
      close.kind !== "receipt_group_close" ||
      close.status !== "complete" ||
      close.group_id !== groupID ||
      close.open_manifest_sha256 !== result.open_manifest_sha256 ||
      close.signer_key !== open.signer_key ||
      !canonicalTime(close.closed_at) ||
      !Array.isArray(close.shards) ||
      close.shards.length !== open.shards.length
    )
      throw new Error("receipt group close does not bind opening manifest");
    for (let i = 0; i < close.shards.length; i++) {
      const claimed = close.shards[i] as GroupHead,
        actual = await verifyShard(open, result.open_manifest_sha256, i);
      if (goJSONMarshal(claimed) !== goJSONMarshal(actual))
        throw new Error(`receipt group shard ${i} head differs from signed close`);
    }
    if (open.previous_group_id)
      await verifyPredecessorTransition(open, result.open_manifest_sha256, trusted);
    await verifySuccessorTransitionInventory(
      open,
      result.open_manifest_sha256,
      sha(closeBytes),
      trusted,
    );
    const openAELTail = await verifyAELInventory(open, trusted, false);
    const predecessorIncomplete =
      open.previous_group_id &&
      !existsNoFollow(`receipt-group-${open.previous_group_id}-close.json`);
    checkDirectoryIdentity(rootStart, aelStart, before);
    result.close_manifest_sha256 = sha(closeBytes);
    result.verdict = openAELTail === "own" ? "GROUP_INCOMPLETE" : "GROUP_VALID";
    if (openAELTail)
      result.error =
        openAELTail === "own"
          ? "native AEL run has an open recorder tail"
          : "predecessor or neighboring group is GROUP_INCOMPLETE: native AEL run has an open recorder tail";
    if (result.verdict === "GROUP_VALID" && predecessorIncomplete)
      result.error = "predecessor group is GROUP_INCOMPLETE: no signed close manifest";
    return result;
  } catch (err) {
    result.error = (err as Error).message;
    return result;
  }
}

function checkDirectoryIdentity(
  root: { dev: bigint; ino: bigint },
  ael: { dev: bigint; ino: bigint },
  before: string,
): void {
  const re = statSync(".", { bigint: true }),
    ae = statSync("ael", { bigint: true });
  if (
    re.dev !== root.dev ||
    re.ino !== root.ino ||
    ae.dev !== ael.dev ||
    ae.ino !== ael.ino ||
    fileInventory() !== before
  )
    throw new Error("receipt group directory changed during verification");
}

async function verifyShard(open: GroupOpen, openHash: string, index: number): Promise<GroupHead> {
  const shard = open.shards[index] as GroupShard;
  const evidence = readSessionEvidence(".", shard.session_id, "prefix"),
    lines = evidence.lines,
    typed = evidence.typed;
  // A signed close covers the whole shard, so an unterminated final write is
  // invalid here, as in Go's session walker.
  if (evidence.torn)
    throw new Error(`reading ${shard.session_id}: torn JSONL tail after the last complete entry`);
  if (!lines.length) throw new Error(`receipt group shard ${index} is empty`);
  const binding = {
    group_id: open.group_id,
    shard_index: index,
    session_id: shard.session_id,
    open_manifest_sha256: openHash,
    signer_key: open.signer_key,
    previous_group_id: open.previous_group_id,
    previous_open_manifest_sha256: open.previous_open_manifest_sha256,
  };
  const first = lines[0]?.entry as (RecorderEntry & { hash: string }) | undefined;
  if (first?.type !== "receipt_group_v1" || goJSONMarshal(first.detail) !== goJSONMarshal(binding))
    throw new Error("receipt group first entry does not match signed gate");
  const cpFirst = lines[1]?.entry as (RecorderEntry & { hash: string }) | undefined;
  if (cpFirst?.type !== "checkpoint" || cpFirst.prev_hash !== first.hash)
    throw new Error("receipt group gate is not covered by next checkpoint");
  const pub = Buffer.from(open.signer_key, "hex");
  let count = 0,
    finalSeq = 0,
    finalHash = "",
    closeHash = "",
    rootHash = "",
    checkpointHash = "",
    rooted = false,
    closed = false,
    lastCheckpoint = false,
    run = "";
  for (let i = 0; i < lines.length; i++) {
    const entry = lines[i]?.entry as RecorderEntry & { hash: string };
    if (rooted && (entry.type !== "checkpoint" || entry.prev_hash !== rootHash || lastCheckpoint))
      throw new Error(
        "receipt group has evidence after transcript root instead of final checkpoint",
      );
    if (entry.type === "checkpoint") {
      const d = object(entry.detail, "checkpoint detail");
      const sig = Buffer.from(str(d.signature, "signature"), "hex");
      if (
        sig.length !== 64 ||
        !(await ed25519.verifyAsync(sig, Buffer.from(String(entry.prev_hash)), pub, {
          zip215: false,
        }))
      )
        throw new Error("receipt group checkpoint signature failed");
      checkpointHash = String(entry.hash);
    }
    if (entry.type === "transcript_root") {
      const d = object(entry.detail, "transcript root");
      if (
        rooted ||
        !closed ||
        d.session_id !== shard.session_id ||
        safeValue(d.final_seq) !== finalSeq ||
        d.root_hash !== finalHash ||
        safeValue(d.receipt_count) !== count
      )
        throw new Error("receipt group transcript root differs from signed closed chain");
      rooted = true;
      rootHash = String(entry.hash);
    }
    if (entry.type === "action_receipt" || entry.type === "evidence_receipt") {
      if (rooted || closed) throw new Error("receipt group has action after signed close");
      const r = (entry.detail ?? {}) as Receipt;
      if ((r.signer_key ?? "").toLowerCase() !== open.signer_key)
        throw new Error("group receipt signer differs from opening signer");
      if (entry.type === "action_receipt") {
        count++;
        finalSeq = Number(r.action_record?.chain_seq);
        finalHash = receiptHash(r);
      }
      if (count === 1) {
        const ctrl = r.action_record?.session_control as Record<string, unknown> | undefined;
        const op = ctrl?.open as Record<string, unknown> | undefined;
        if (
          ctrl?.kind !== "session_open" ||
          !op ||
          op.recorder_session !== shard.session_id ||
          goJSONMarshal(op.group_binding) !== goJSONMarshal(binding)
        )
          throw new Error("receipt group first signed receipt lacks matching session open");
        run = String(op.run_nonce ?? "");
      }
      const ctrl = r.action_record?.session_control as Record<string, unknown> | undefined;
      if (ctrl?.kind === "session_close") {
        closed = true;
        closeHash = receiptHash(r);
      }
    }
    lastCheckpoint = entry.type === "checkpoint";
  }
  const outer = verifyRecorderChain(lines);
  if (
    outer ||
    !closed ||
    !rooted ||
    !lastCheckpoint ||
    !checkpointHash ||
    count === 0 ||
    typed.action.length === 0
  )
    throw new Error(`receipt group shard incomplete or invalid${outer ? `: ${outer}` : ""}`);
  const action = await verifyChain(typed.action, open.signer_key);
  if (
    !action.valid ||
    action.root_hash !== finalHash ||
    action.final_seq !== finalSeq ||
    action.receipt_count !== count
  )
    throw new Error(`receipt group v1 chain failed: ${action.error ?? "head mismatch"}`);
  if (typed.evidence.length) {
    const ev = await verifyChain(typed.evidence, evidenceChainKey(open.signer_key, typed.evidence));
    if (!ev.valid) throw new Error(`receipt group v2 chain failed: ${ev.error ?? "invalid"}`);
  }
  const ael = await verifyAELRun(run, open.signer_key);
  return {
    shard_index: index,
    session_id: shard.session_id,
    final_chain_seq: finalSeq,
    final_chain_hash: finalHash,
    receipt_count: count,
    session_close_hash: closeHash,
    transcript_root_hash: rootHash,
    checkpoint_hash: checkpointHash,
    native_ael_final_seq: ael.finalSeq,
    native_ael_final_hash: ael.finalHash,
    native_ael_record_count: ael.recordCount,
  };
}
function safeValue(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (value instanceof RawNumber) return safeNumber(value, "integer");
  throw new Error("invalid integer");
}

async function verifyPredecessorTransition(
  open: GroupOpen,
  openHash: string,
  trusted: Set<string>,
): Promise<void> {
  const predecessorID = open.previous_group_id;
  const oldBytes = readChild(`receipt-group-${predecessorID}-open.json`),
    oldRaw = strictObject(oldBytes, openFields, "predecessor opening"),
    old = parseOpen(oldBytes);
  await verifySignature(oldRaw, openFields, openDomain, trusted);
  let closeHash = "";
  try {
    const closeBytes = readChild(`receipt-group-${predecessorID}-close.json`),
      closeRaw = strictObject(closeBytes, closeFields, "predecessor close");
    await verifySignature(closeRaw, closeFields, closeDomain, trusted);
    closeHash = sha(closeBytes);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const trBytes = readChild(`receipt-group-${open.group_id}-transition.json`),
    trRaw = strictObject(trBytes, transitionFields, "group transition");
  await verifyTransition(trRaw, open, old, openHash, sha(oldBytes), closeHash, trusted);
  await verifySuccessorTransitionInventory(old, sha(oldBytes), closeHash, trusted, false);
}

async function verifySuccessorTransitionInventory(
  open: GroupOpen,
  openHash: string,
  closeHash: string,
  trusted: Set<string>,
  verifyLinks = true,
): Promise<void> {
  let matched = 0;
  for (const name of readdirSync(".")) {
    if (!name.startsWith("receipt-group-") || !name.endsWith("-transition.json")) continue;
    const rawBytes = readChild(name),
      raw = strictObject(rawBytes, transitionFields, "group transition");
    const fileID = name.slice("receipt-group-".length, -"-transition.json".length);
    if (!isHex(fileID, 32) || raw.new_group_id !== fileID)
      throw new Error("receipt group transition file identity differs");
    const refersToOpen = raw.previous_open_manifest_sha256 === openHash;
    await verifySignature(
      raw,
      transitionFields,
      transitionDomain,
      refersToOpen ? trusted : new Set([str(raw.signer_key, "transition signer key")]),
    );
    if (!refersToOpen) continue;
    matched++;
    if (matched > 1) throw new Error("multiple successor transitions name one receipt group");
    if (raw.previous_close_manifest_sha256 !== closeHash)
      throw new Error("successor transition froze a different receipt group close state");
    const successorBytes = readChild(`receipt-group-${fileID}-open.json`),
      successorRaw = strictObject(successorBytes, openFields, "successor opening"),
      successor = parseOpen(successorBytes);
    await verifySignature(successorRaw, openFields, openDomain, trusted);
    if (verifyLinks)
      await verifyTransition(
        raw,
        successor,
        open,
        sha(successorBytes),
        openHash,
        closeHash,
        trusted,
      );
  }
}

async function verifyAELInventory(
  open: GroupOpen,
  trusted: Set<string>,
  incomplete: boolean,
): Promise<"own" | "neighbor" | undefined> {
  const sessions = new Set<string>();
  for (const name of readdirSync(".")) {
    const parsed = parseEvidenceFilename(name);
    if (parsed && parsed.seqStart === 0n) sessions.add(parsed.session);
  }
  const claims = new Map<
    string,
    { session: string; groupID: string; signer: string; completed: boolean }
  >();
  for (const session of sessions) {
    const evidence = readSessionEvidence(".", session, "prefix");
    const lines = evidence.lines;
    if (!lines.length)
      throw new Error(`inventory receipt session ${JSON.stringify(session)} is empty`);
    const first = lines[0]?.entry;
    let gate: Record<string, unknown> | undefined,
      claimedGroup = "",
      signer = "";
    if (first?.type === "receipt_group_v1") {
      gate = object(first.detail, "receipt group gate");
      claimedGroup = str(gate.group_id, "receipt group gate ID");
      if (!isHex(claimedGroup, 32) || gate.session_id !== session)
        throw new Error("receipt group gate has invalid identity");
      const openBytes = readChild(`receipt-group-${claimedGroup}-open.json`),
        openRaw = strictObject(openBytes, openFields, "receipt group opening"),
        owner = parseOpen(openBytes);
      await verifySignature(openRaw, openFields, openDomain, trusted);
      const idx = safeValue(gate.shard_index);
      const member = owner.shards[idx];
      const expected = {
        group_id: owner.group_id,
        shard_index: idx,
        session_id: session,
        open_manifest_sha256: sha(openBytes),
        signer_key: owner.signer_key,
        previous_group_id: owner.previous_group_id,
        previous_open_manifest_sha256: owner.previous_open_manifest_sha256,
      };
      if (
        !member ||
        member.session_id !== session ||
        goJSONMarshal(materialize(gate)) !== goJSONMarshal(expected)
      )
        throw new Error("receipt group gate is not owned by a signed opening");
      signer = owner.signer_key;
    }
    // Go tolerates an unterminated final write only for a legacy session, the
    // predecessor group, or (while the group is still open) this group; the
    // complete prefix is then what the inventory verifies.
    if (
      evidence.torn &&
      claimedGroup !== "" &&
      !(incomplete && claimedGroup === open.group_id) &&
      claimedGroup !== open.previous_group_id
    )
      throw new Error(
        `inventory receipt session ${JSON.stringify(session)}: torn JSONL tail in another receipt group`,
      );
    const outer = verifyRecorderChain(lines);
    if (outer) throw new Error(`inventory receipt session ${JSON.stringify(session)}: ${outer}`);
    const receipts = evidence.typed.action;
    const pin =
      signer || (receipts.length ? str(receipts[0]?.signer_key, "inventory signer key") : "");
    if (!trusted.has(pin))
      throw new Error(`inventory receipt session ${JSON.stringify(session)} signer is not trusted`);
    const verified = receipts.length ? await verifyChain(receipts, pin) : undefined;
    if (!verified?.valid)
      throw new Error(
        `inventory receipt session ${JSON.stringify(session)} chain invalid: ${verified?.error ?? "empty chain"}`,
      );
    let signedOpenSeen = false;
    for (const r of receipts) {
      const ctrl = r.action_record?.session_control as Record<string, unknown> | undefined;
      const sessionOpen =
        ctrl?.kind === "session_open"
          ? (ctrl.open as Record<string, unknown> | undefined)
          : undefined;
      if (!sessionOpen) continue;
      if (signedOpenSeen)
        throw new Error("receipt session has multiple signed native AEL openings");
      signedOpenSeen = true;
      const binding = sessionOpen.group_binding;
      if (
        gate === undefined
          ? binding !== undefined
          : goJSONMarshal(binding) !== goJSONMarshal(materialize(gate))
      )
        throw new Error("signed session open disagrees with recorder group gate");
      if (sessionOpen.run_nonce === undefined && claimedGroup === "") continue;
      const run = str(sessionOpen.run_nonce, "signed session open run_nonce");
      if (!isHex(run, 32)) throw new Error(`invalid signed native AEL run ${JSON.stringify(run)}`);
      if (claims.has(run)) throw duplicateSignedAELRunError(run);
      const completed =
        receipts.some(
          (receipt) =>
            (receipt.action_record?.session_control as Record<string, unknown> | undefined)
              ?.kind === "session_close",
        ) || lines.some((line) => line.entry.type === "transcript_root");
      claims.set(run, { session, groupID: claimedGroup, signer: pin, completed });
    }
  }
  const aelRuns = readdirSync("ael", { withFileTypes: true });
  let openTail = false;
  let neighborOpenTail = false;
  for (const ent of aelRuns) {
    if (!isHex(ent.name, 32))
      throw new Error(`invalid native AEL run directory ${JSON.stringify(ent.name)}`);
    const st = lstatSync(path.join("ael", ent.name));
    if (!ent.isDirectory() || ent.isSymbolicLink() || st.isSymbolicLink())
      throw new Error(`native AEL run ${JSON.stringify(ent.name)} is not a real directory`);
    const claim = claims.get(ent.name);
    if (!claim)
      throw new Error(`native AEL run ${JSON.stringify(ent.name)} has no signed session owner`);
    try {
      await verifyAELRun(ent.name, claim.signer, claim.completed);
    } catch (cause) {
      throw new Error(`native AEL run ${JSON.stringify(ent.name)} invalid: ${String(cause)}`);
    }
    if (!claim.completed) {
      if (claim.groupID === open.group_id) openTail = true;
      else neighborOpenTail = true;
    }
  }
  for (const run of claims.keys()) {
    let st;
    try {
      st = lstatSync(path.join("ael", run));
    } catch {
      throw new Error(
        `native AEL run ${JSON.stringify(run)} claimed by a signed session_open is missing`,
      );
    }
    if (!st.isDirectory() || st.isSymbolicLink())
      throw new Error(
        `native AEL run ${JSON.stringify(run)} claimed by a signed session_open is missing`,
      );
  }
  checkGroupAELMembership(
    open.shards.map((shard) => shard.session_id),
    [...claims.values()]
      .filter((claim) => claim.groupID === open.group_id)
      .map((claim) => claim.session),
    incomplete,
  );
  return openTail ? "own" : neighborOpenTail ? "neighbor" : undefined;
}

export function checkGroupAELMembership(
  signed: readonly string[],
  claimed: readonly string[],
  incomplete: boolean,
): void {
  const signedSessions = new Set(signed);
  const groupedSessions = new Set<string>();
  for (const session of claimed) {
    if (!signedSessions.has(session))
      throw new Error(
        `receipt group native AEL claim session ${JSON.stringify(session)} is outside signed shard membership`,
      );
    if (groupedSessions.has(session))
      throw new Error(
        `receipt group native AEL session ${JSON.stringify(session)} has duplicate claims`,
      );
    groupedSessions.add(session);
  }
  if (!incomplete && groupedSessions.size !== signedSessions.size)
    throw new Error(
      `receipt group native AEL claims = ${groupedSessions.size}, want ${signedSessions.size}`,
    );
}

export function duplicateSignedAELRunError(run: string): Error {
  return new Error(`duplicate signed native AEL run ${JSON.stringify(run)}`);
}

async function recoveredAELRun(
  predecessor: GroupOpen,
  index: number,
  seal: Record<string, unknown>,
  sealBytes: Buffer,
): Promise<{ run: string; completed: boolean }> {
  const shard = str(seal.shard, "recovery seal shard"),
    raw = readChild(shard, 8 << 20);
  const offset = safeNumber(seal.damage_offset, "recovery damage offset");
  if (
    raw.length !== safeNumber(seal.shard_size, "recovery shard size") ||
    sha(raw) !== seal.shard_sha256 ||
    offset <= 0 ||
    offset >= raw.length ||
    raw[offset - 1] !== 0x0a
  )
    throw new Error("recovery seal shard prefix is invalid");
  const shardInfo = predecessor.shards[index] as GroupShard;
  const files = sessionEvidenceFiles(".", shardInfo.session_id);
  if (files.length === 0 || path.basename(files[files.length - 1] as string) !== shard)
    throw new Error("recovery seal shard is not the last predecessor segment");
  const parts: Buffer[] = [];
  for (const file of files.slice(0, -1)) {
    const part = readChild(path.basename(file), 8 << 20);
    if (!part.length || part[part.length - 1] !== 0x0a)
      throw new Error("recovery seal predecessor has an earlier torn segment");
    parts.push(part);
  }
  parts.push(raw.subarray(0, offset));
  const prefix = parseEntryLinesText(
    decodeUTF8(Buffer.concat(parts), "recovery predecessor prefix"),
  );
  if (!prefix.length || verifyRecorderChain(prefix))
    throw new Error("recovery predecessor recorder prefix is invalid");
  const tailEntry = prefix[prefix.length - 1]?.entry as RecorderEntry & {
    seq?: number;
    hash: string;
  };
  if (
    safeValue(tailEntry.seq) !== safeNumber(seal.last_good_seq, "recovery last good seq") ||
    tailEntry.hash !== seal.last_good_hash
  )
    throw new Error("recovery seal last-good recorder head differs");
  const binding = {
    group_id: predecessor.group_id,
    shard_index: index,
    session_id: shardInfo.session_id,
    open_manifest_sha256: sha(readChild(`receipt-group-${predecessor.group_id}-open.json`)),
    signer_key: predecessor.signer_key,
    previous_group_id: predecessor.previous_group_id,
    previous_open_manifest_sha256: predecessor.previous_open_manifest_sha256,
  };
  if (
    prefix[0]?.entry.type !== "receipt_group_v1" ||
    goJSONMarshal(prefix[0]?.entry.detail) !== goJSONMarshal(binding)
  )
    throw new Error("recovery predecessor prefix does not match group gate");
  const typed = extractTypedFromEntries(
    prefix.map((line) => line.entry),
    true,
  );
  const v1 = await verifyChain(typed.action, predecessor.signer_key);
  const last = typed.action[typed.action.length - 1];
  if (
    !v1.valid ||
    !last ||
    v1.final_seq !== safeNumber(seal.predecessor_tail_seq, "predecessor tail seq") ||
    v1.root_hash !== seal.predecessor_tail_hash ||
    receiptHash(last) !== seal.predecessor_tail_hash
  )
    throw new Error("recovery predecessor signed receipt head differs");
  const openReceipt = typed.action.find(
    (r) =>
      (r.action_record?.session_control as Record<string, unknown> | undefined)?.kind ===
      "session_open",
  );
  const ctrl = openReceipt?.action_record?.session_control as Record<string, unknown> | undefined;
  const sessionOpen = ctrl?.open as Record<string, unknown> | undefined;
  if (!sessionOpen || goJSONMarshal(sessionOpen.group_binding) !== goJSONMarshal(binding))
    throw new Error("recovery predecessor signed session open lacks matching gate");
  const run = str(sessionOpen.run_nonce, "recovery predecessor run_nonce");
  if (!isHex(run, 32)) throw new Error("recovery predecessor run nonce is invalid");
  const completed =
    typed.action.some(
      (receipt) =>
        (receipt.action_record?.session_control as Record<string, unknown> | undefined)?.kind ===
        "session_close",
    ) || prefix.some((line) => line.entry.type === "transcript_root");
  return { run, completed };
}

async function verifyTransition(
  raw: Record<string, unknown>,
  successor: GroupOpen,
  predecessor: GroupOpen,
  newHash: string,
  oldHash: string,
  closeHash: string,
  trusted: Set<string>,
): Promise<void> {
  const t = normalizeNumbers(raw, transitionFields) as unknown as GroupTransition;
  await verifySignature(raw, transitionFields, transitionDomain, trusted);
  if (
    t.version !== 1 ||
    t.kind !== "receipt_group_transition" ||
    !canonicalTime(t.created_at) ||
    t.new_group_id !== successor.group_id ||
    t.new_open_manifest_sha256 !== newHash ||
    t.previous_group_id !== predecessor.group_id ||
    t.previous_open_manifest_sha256 !== oldHash ||
    t.previous_close_manifest_sha256 !== closeHash ||
    t.signer_key !== successor.signer_key ||
    t.predecessors.length !== predecessor.shards.length
  )
    throw new Error(
      `receipt group transition does not bind predecessor and successor (ids=${t.previous_group_id}/${predecessor.group_id}, open=${t.previous_open_manifest_sha256}/${oldHash}, close=${t.previous_close_manifest_sha256}/${closeHash}, succ=${t.signer_key}/${successor.signer_key}, count=${t.predecessors.length}/${predecessor.shards.length})`,
    );
  if (
    successor.previous_group_id !== predecessor.group_id ||
    successor.previous_open_manifest_sha256 !== oldHash
  )
    throw new Error("successor opening predecessor binding differs");
  for (let i = 0; i < t.predecessors.length; i++) {
    const rawPredecessor = object(t.predecessors[i], `transition predecessor ${i}`);
    if (
      Object.keys(rawPredecessor).length !== predecessorFields.length ||
      Object.keys(rawPredecessor).some((key) => !predecessorFields.includes(key))
    )
      throw new Error(`invalid transition predecessor ${i} schema`);
    const p = t.predecessors[i] as GroupPredecessor,
      shard = predecessor.shards[i] as GroupShard;
    if (
      p.shard_index !== i ||
      p.session_id !== shard.session_id ||
      !isHex(p.final_chain_hash, 64) ||
      (p.recovery_seal_sha256 && !isHex(p.recovery_seal_sha256, 64))
    )
      throw new Error(`invalid transition predecessor ${i}`);
    if (closeHash) {
      const signedClose = strictObject(
        readChild(`receipt-group-${predecessor.group_id}-close.json`),
        closeFields,
        "predecessor close",
      );
      await verifySignature(signedClose, closeFields, closeDomain, trusted);
      const closeRaw = normalizeNumbers(signedClose, closeFields) as unknown as GroupClose;
      const h = closeRaw.shards[i];
      const actual = await verifyShard(predecessor, oldHash, i);
      if (
        !h ||
        h.shard_index !== p.shard_index ||
        h.session_id !== p.session_id ||
        h.final_chain_seq !== p.final_chain_seq ||
        h.final_chain_hash !== p.final_chain_hash ||
        goJSONMarshal(h) !== goJSONMarshal(actual) ||
        p.recovery_seal_sha256 !== ""
      )
        throw new Error(`transition predecessor ${i} differs from signed close`);
    } else {
      if (p.recovery_seal_sha256) {
        const sealBytes = readChild(`chain-link-${p.session_id}.json`, 64 * 1024);
        if (sha(sealBytes) !== p.recovery_seal_sha256)
          throw new Error(`recovery seal ${i} digest differs`);
        await verifyRecoverySeal(sealBytes, predecessor, successor, p);
      } else {
        await verifyUnsealedPredecessor(predecessor, oldHash, p);
      }
    }
  }
}

async function verifyUnsealedPredecessor(
  open: GroupOpen,
  openHash: string,
  claim: GroupPredecessor,
): Promise<void> {
  const evidence = readSessionEvidence(".", claim.session_id, "prefix"),
    lines = evidence.lines;
  // A torn predecessor tail is only attachable through a recovery seal.
  if (evidence.torn)
    throw new Error(`receipt group predecessor shard ${claim.shard_index} lacks a recovery seal`);
  const binding = {
    group_id: open.group_id,
    shard_index: claim.shard_index,
    session_id: claim.session_id,
    open_manifest_sha256: openHash,
    signer_key: open.signer_key,
    previous_group_id: open.previous_group_id,
    previous_open_manifest_sha256: open.previous_open_manifest_sha256,
  };
  if (
    !lines.length ||
    lines[0]?.entry.type !== "receipt_group_v1" ||
    goJSONMarshal(lines[0]?.entry.detail) !== goJSONMarshal(binding)
  )
    throw new Error("predecessor shard has no signed group gate");
  const outer = verifyRecorderChain(lines);
  if (outer) throw new Error(`predecessor recorder chain failed: ${outer}`);
  const receipts = evidence.typed.action;
  if (!receipts.length) throw new Error("predecessor shard has no signed receipts");
  const verified = await verifyChain(receipts, open.signer_key);
  const last = receipts[receipts.length - 1] as Receipt;
  if (
    !verified.valid ||
    verified.final_seq !== claim.final_chain_seq ||
    verified.root_hash !== claim.final_chain_hash ||
    receiptHash(last) !== claim.final_chain_hash
  )
    throw new Error("predecessor signed chain head differs from transition");
  const ctrl = last.action_record?.session_control as Record<string, unknown> | undefined;
  if (ctrl?.kind === "session_close" && verified.final_seq !== claim.final_chain_seq)
    throw new Error("predecessor close head differs from transition");
}

async function verifyRecoverySeal(
  rawBytes: Buffer,
  predecessor: GroupOpen,
  successor: GroupOpen,
  claim: GroupPredecessor,
): Promise<void> {
  const raw = object(parseJSONStrict(decodeUTF8(rawBytes, "recovery seal")), "recovery seal");
  const sealFields = [
    "kind",
    "version",
    "predecessor_session",
    "shard",
    "shard_size",
    "shard_sha256",
    "damage_offset",
    "last_good_seq",
    "last_good_hash",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "successor_open_hash",
    "observed_at",
    "signature",
  ];
  if (
    Object.keys(raw).length !== sealFields.length ||
    sealFields.some((f) => !Object.hasOwn(raw, f)) ||
    Object.keys(raw).some((f) => !sealFields.includes(f))
  )
    throw new Error("recovery seal schema is invalid");
  const signature = str(raw.signature, "recovery seal signature"),
    signer = str(raw.successor_signer_key, "successor_signer_key");
  if (
    !isHex(signer, 64) ||
    signer !== successor.signer_key ||
    !signature.startsWith("ed25519:") ||
    !isHex(signature.slice(8), 128)
  )
    throw new Error("invalid recovery seal signature identity");
  const fields = sealFields.slice(0, -1);
  const canonical: Record<string, unknown> = {};
  for (const f of fields) canonical[f] = materialize(raw[f]);
  const msg = Buffer.from(recoveryDomain + goJSONMarshal(canonical));
  if (
    !(await ed25519.verifyAsync(
      Buffer.from(signature.slice(8), "hex"),
      msg,
      Buffer.from(signer, "hex"),
      { zip215: false },
    ))
  )
    throw new Error("recovery seal signature verification failed");
  const pred = predecessor.shards[claim.shard_index] as GroupShard,
    succ = successor.shards[claim.shard_index % successor.shards.length] as GroupShard;
  const successorEvidence = readSessionEvidence(".", succ.session_id, "prefix");
  if (successorEvidence.torn)
    throw new Error(`reading ${succ.session_id}: torn JSONL tail after the last complete entry`);
  const firstReceipt = successorEvidence.typed.action[0];
  const successorOpenHash = firstReceipt ? receiptHash(firstReceipt) : "";
  const damagedShard = readChild(str(raw.shard, "recovery seal shard"), 8 << 20);
  const damageOffset = safeNumber(raw.damage_offset, "recovery seal damage offset"),
    shardSize = safeNumber(raw.shard_size, "recovery seal shard size");
  const parsedShard = parseEvidenceFilename(str(raw.shard, "recovery seal shard"));
  if (
    damagedShard.length !== shardSize ||
    sha(damagedShard) !== raw.shard_sha256 ||
    shardSize === 0 ||
    damageOffset >= shardSize ||
    raw.shard_sha256 === "" ||
    !parsedShard ||
    parsedShard.session !== pred.session_id ||
    path.basename(sessionEvidenceFiles(".", pred.session_id).at(-1) ?? "") !== raw.shard
  )
    throw new Error("recovery seal damaged shard bytes or identity differ");
  if (
    raw.kind !== "recovery_seal" ||
    safeNumber(raw.version, "recovery seal version") !== 1 ||
    raw.predecessor_session !== pred.session_id ||
    raw.successor_session !== succ.session_id ||
    raw.predecessor_signer_key !== predecessor.signer_key ||
    raw.successor_signer_key !== successor.signer_key ||
    raw.successor_open_hash !== successorOpenHash ||
    safeNumber(raw.predecessor_tail_seq, "recovery seal tail seq") !== claim.final_chain_seq ||
    raw.predecessor_tail_hash !== claim.final_chain_hash ||
    !canonicalTime(str(raw.observed_at, "observed_at")) ||
    !isHex(str(raw.last_good_hash, "last_good_hash"), 64) ||
    !isHex(str(raw.predecessor_tail_hash, "predecessor_tail_hash"), 64) ||
    !isHex(str(raw.successor_open_hash, "successor_open_hash"), 64)
  )
    throw new Error("recovery seal does not bind transition predecessor");
  await recoveredAELRun(predecessor, claim.shard_index, raw, rawBytes);
}

export async function verifyReceiptGroup(
  dir: string,
  groupID: string,
  trustedKeys: readonly string[],
): Promise<ReceiptGroupResult> {
  try {
    return await withPinnedEvidenceDirectory(dir, () => verifyGroupAt(groupID, trustedKeys));
  } catch (err) {
    return {
      group_id: groupID,
      verdict: "GROUP_INVALID",
      shard_count: 0,
      error: (err as Error).message,
    };
  }
}

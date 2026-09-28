// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Restart continuity across the receipt chains of one base, ported from the
// Go reference internal/receipt/chain_set.go and chain_link.go. Every Pipelock
// process run writes its own chain, "<base>.run.<32hex>", and a restart may
// publish a signed link file "chain-link-<predecessor>.json" naming the exact
// tail it continues. verifyBase verifies every chain of a base and every link
// file that names one, with the same findings Go reports.
//
// Each chain is read the way Go's session reader reads it: a symlinked
// evidence file inside the directory is refused, and every entry must carry
// the session its file name claims. The recorder's own entry hash chain is
// checked (finding outer_chain_broken), and two chains whose signed action
// records carry the same run_nonce are reported (finding duplicate_run_nonce),
// because a process run writes exactly one chain.

import { lstatSync, readdirSync } from "node:fs";
import * as path from "node:path";
import * as ed25519 from "@noble/ed25519";
import { parseJSONStrict, RawNumber } from "./aarp/strictjson.js";
import { evidenceChainKey, receiptHash, verifyChain } from "./chain.js";
import {
  extractTypedFromEntries,
  readEntryLines,
  type ExtractedReceipts,
  type ParsedRecorderLine,
} from "./recorder.js";
import { FindingOuterChainBroken, verifyRecorderChain } from "./recorder-chain.js";
import {
  isCanonicalUTCTimestamp,
  verifyChainWithEndorsements,
  verifyRotationEndorsement,
  type RotationEndorsement,
} from "./rotation.js";
import type { ChainResult, Receipt } from "./types.js";
import { readVerifierBytes } from "./util.js";

export const FindingCorruptChain = "corrupt_chain";
export const FindingInvalidLink = "invalid_link";
export const FindingLinkNameMismatch = "link_name_mismatch";
export const FindingDanglingLink = "dangling_link";
export const FindingPredecessorUnverified = "predecessor_unverified";
export const FindingLinkTailMismatch = "link_tail_mismatch";
export const FindingAppendedAfterLink = "appended_after_link";
export const FindingDoubleSuccessor = "double_successor";
export const FindingUntrustedSuccessorKey = "untrusted_successor_key";
export const FindingDuplicateRunNonce = "duplicate_run_nonce";
export { FindingOuterChainBroken };

export const LinkTrustSameKey = "same_key";
export const LinkTrustTrustedKey = "trusted_key";
export const LinkTrustEndorsed = "endorsed";

const runInfix = ".run.";
const evidencePrefix = "evidence-";
const evidenceSuffix = ".jsonl";
const chainLinkFilePrefix = "chain-link-";
const chainLinkFileSuffix = ".json";
const chainLinkVersion = 1;
const chainLinkDomain = "pipelock-chain-link-v1\u0000";
const signaturePrefix = "ed25519:";
const maxChainLinkFileBytes = 64 << 10;
const maxUint64 = 18446744073709551615n;

// ChainLink mirrors Go's ChainLink. predecessor_tail_seq keeps its decimal
// literal so a uint64 is signed and compared exactly.
export interface ChainLink {
  version: number;
  predecessor_session: string;
  predecessor_tail_seq: string;
  predecessor_tail_hash: string;
  predecessor_signer_key: string;
  successor_session: string;
  successor_signer_key: string;
  linked_at: string;
  signature: string;
}

export interface BaseChain {
  session: string;
  legacy: boolean;
  receipts: number;
  final_seq: number;
  tail_hash: string;
  signer_key: string;
  link?: ChainLink;
  link_file?: string;
  link_trust: string;
  valid: boolean;
  error: string;
}

export interface BaseFinding {
  kind: string;
  session: string;
  detail: string;
}

export interface BaseReport {
  base: string;
  chains: BaseChain[];
  findings: BaseFinding[];
}

export interface BaseVerifyOptions {
  trustedKeys: string[];
  endorsements: RotationEndorsement[];
}

export function baseHealthy(report: BaseReport): boolean {
  return report.findings.length === 0;
}

// baseUnlinked lists every chain no link file continues into. An unlinked
// chain is reported, never a finding: first runs, concurrent runs, and runs
// by older binaries are honestly unlinked, and so is a run whose link file
// was deleted. A healthy report is therefore not proof of continuity.
export function baseUnlinked(report: BaseReport): string[] {
  return report.chains.filter((c) => c.link === undefined).map((c) => c.session);
}

export function runSessionBase(session: string): string | undefined {
  const idx = session.indexOf(runInfix);
  return idx <= 0 ? undefined : session.slice(0, idx);
}

function isBaseChain(session: string, base: string): boolean {
  return session === base || runSessionBase(session) === base;
}

// parseEvidenceFilename mirrors Go evidencename.Parse: the session is
// everything between "evidence-" and the LAST dash, and a sequence that is not
// a uint64 parses as 0.
export function parseEvidenceFilename(
  name: string,
): { session: string; seqStart: bigint } | undefined {
  if (!name.startsWith(evidencePrefix) || !name.endsWith(evidenceSuffix)) return undefined;
  const rest = name.slice(evidencePrefix.length, name.length - evidenceSuffix.length);
  const lastDash = rest.lastIndexOf("-");
  if (lastDash < 0) return undefined;
  const digits = rest.slice(lastDash + 1);
  let seqStart = 0n;
  if (/^[0-9]+$/u.test(digits)) {
    const parsed = BigInt(digits);
    if (parsed <= maxUint64) seqStart = parsed;
  }
  return { session: rest.slice(0, lastDash), seqStart };
}

// EvidenceIndex maps each session to its shard files in order. A symlinked
// evidence file is kept apart: it names its session, so that session is
// listed and then refused, rather than silently read or silently dropped.
interface EvidenceIndex {
  files: Map<string, string[]>;
  symlinks: Map<string, string[]>;
}

function indexRecorderFiles(dir: string): EvidenceIndex {
  const shards = new Map<string, { file: string; name: string; seq: bigint }[]>();
  const symlinks = new Map<string, string[]>();
  for (const de of readdirSync(dir, { withFileTypes: true })) {
    if (de.isDirectory() || !de.name.endsWith(evidenceSuffix)) continue;
    const parsed = parseEvidenceFilename(de.name);
    if (parsed === undefined) continue;
    if (de.isSymbolicLink()) {
      symlinks.set(parsed.session, [...(symlinks.get(parsed.session) ?? []), de.name].sort());
      if (!shards.has(parsed.session)) shards.set(parsed.session, []);
      continue;
    }
    const list = shards.get(parsed.session) ?? [];
    list.push({ file: path.join(dir, de.name), name: de.name, seq: parsed.seqStart });
    shards.set(parsed.session, list);
  }
  const ix: EvidenceIndex = { files: new Map(), symlinks };
  for (const [session, list] of shards) {
    list.sort((a, b) =>
      a.seq !== b.seq ? (a.seq < b.seq ? -1 : 1) : a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    ix.files.set(
      session,
      list.map((s) => s.file),
    );
  }
  return ix;
}

// indexFiles refuses a symlinked evidence file of the session, as Go's
// evidence reader does, and two distinct shard names that start the session at
// the same sequence, as Go's evidencename.CheckNoDuplicateSeqStart does.
function indexFiles(ix: EvidenceIndex, session: string): string[] {
  const linked = ix.symlinks.get(session);
  if (linked !== undefined && linked.length > 0) {
    throw new EvidenceRefusedError(
      `refuse symlink in evidence directory: "${linked[0] as string}"`,
    );
  }
  const files = ix.files.get(session) ?? [];
  for (let i = 1; i < files.length; i++) {
    const prev = parseEvidenceFilename(path.basename(files[i - 1] as string));
    const cur = parseEvidenceFilename(path.basename(files[i] as string));
    if (
      prev !== undefined &&
      cur !== undefined &&
      prev.session === cur.session &&
      prev.seqStart === cur.seqStart
    ) {
      throw new Error(
        `ambiguous evidence shard sequence start: ${path.basename(files[i - 1] as string)} and ${path.basename(files[i] as string)} both start session "${cur.session}" at sequence ${cur.seqStart}`,
      );
    }
  }
  return files;
}

function sortedSessions(ix: EvidenceIndex): string[] {
  return [...ix.files.keys()].sort(compareStrings);
}

function compareStrings(a: string, b: string): number {
  // Go sorts strings by bytes; UTF-8 byte order equals code point order.
  const ca = [...a];
  const cb = [...b];
  for (let i = 0; i < Math.min(ca.length, cb.length); i++) {
    const x = ca[i]?.codePointAt(0) ?? 0;
    const y = cb[i]?.codePointAt(0) ?? 0;
    if (x !== y) return x - y;
  }
  return ca.length - cb.length;
}

// resolveBaseSessions lists the legacy base session and every run session of
// base in dir, sorted.
export function resolveBaseSessions(dir: string, base: string): string[] {
  return sortedSessions(indexRecorderFiles(dir)).filter((s) => isBaseChain(s, base));
}

// EvidenceRefusedError is evidence the verifier will not read as the session
// it claims to be: a symlinked file in the evidence directory, or an entry
// whose session_id differs from the session its file name claims. It is a
// verification failure, never a usage error.
export class EvidenceRefusedError extends Error {}

// readSessionLines reads every recorder entry of one session in shard order.
// Like Go's session reader (internal/recorder/query.go), it refuses an entry
// whose session_id is not the session its file name claims: a file named for
// run X that holds run Y's entries is not run X's evidence.
function readSessionLines(ix: EvidenceIndex, session: string): ParsedRecorderLine[] {
  const out: ParsedRecorderLine[] = [];
  for (const file of indexFiles(ix, session)) {
    for (const l of readEntryLines(file)) {
      if (l.entry.session_id !== session) {
        throw new EvidenceRefusedError(
          `reading ${path.basename(file)}: entry seq ${String(l.entry.seq)} session_id ${JSON.stringify(l.entry.session_id ?? null)} does not match requested session ${JSON.stringify(session)}`,
        );
      }
      out.push(l);
    }
  }
  return out;
}

// checkFileEntrySessions applies the session rule to one evidence file read on
// its own, as Go's receipt.CheckRecorderFile does: when the file name claims a
// session, every entry must carry it, and a file whose name claims none must
// hold one session. A file named for run X that holds run Y's entries is not
// run X's evidence, read alone or in its directory.
export function checkFileEntrySessions(name: string, lines: ParsedRecorderLine[]): void {
  const claimed = parseEvidenceFilename(name);
  if (claimed !== undefined) {
    for (const l of lines) {
      if (l.entry.session_id !== claimed.session) {
        throw new EvidenceRefusedError(
          `reading ${name}: entry seq ${String(l.entry.seq)} session_id ${JSON.stringify(l.entry.session_id ?? null)} does not match requested session ${JSON.stringify(claimed.session)}`,
        );
      }
    }
    return;
  }
  const first = lines[0]?.entry.session_id;
  for (const l of lines.slice(1)) {
    if (l.entry.session_id !== first) {
      throw new EvidenceRefusedError(
        `evidence file mixes recorder sessions ${JSON.stringify(first ?? null)} and ${JSON.stringify(l.entry.session_id ?? null)}`,
      );
    }
  }
}

// SessionEvidence is one session's recorder entries and the two receipt
// chains they hold.
export interface SessionEvidence {
  lines: ParsedRecorderLine[];
  typed: ExtractedReceipts;
}

// readSessionEvidence reads one session of dir with the refusals above.
export function readSessionEvidence(dir: string, session: string): SessionEvidence {
  const lines = readSessionLines(indexRecorderFiles(dir), session);
  return { lines, typed: extractTypedFromEntries(lines.map((l) => l.entry)) };
}

// readSessionReceipts returns the receipts of one session in shard order, as
// action receipts and evidence receipts.
export function readSessionReceipts(dir: string, session: string): ExtractedReceipts {
  return readSessionEvidence(dir, session).typed;
}

function chainLinkFilePredecessor(name: string): string | undefined {
  if (!name.startsWith(chainLinkFilePrefix) || !name.endsWith(chainLinkFileSuffix)) {
    return undefined;
  }
  const pred = name.slice(chainLinkFilePrefix.length, name.length - chainLinkFileSuffix.length);
  return pred === "" ? undefined : pred;
}

// Go's unicode.IsSpace, used by strings.TrimSpace.
function isGoSpace(ch: string): boolean {
  const c = ch.codePointAt(0) ?? 0;
  return (
    (c >= 0x09 && c <= 0x0d) ||
    c === 0x20 ||
    c === 0x85 ||
    c === 0xa0 ||
    c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) ||
    c === 0x2028 ||
    c === 0x2029 ||
    c === 0x202f ||
    c === 0x205f ||
    c === 0x3000
  );
}

function blankAfterGoTrim(value: string): boolean {
  return [...value].every(isGoSpace);
}

// goJSONString encodes value exactly as Go's encoding/json does, followed by
// jsonscan.NormalizeReplacementEscapes: HTML-sensitive characters and U+2028
// and U+2029 are escaped, \b \f \n \r \t use their short escapes (Go 1.22
// and later), other control characters use \u00XX,
// and an unpaired surrogate (which Go decodes to U+FFFD) is written as U+FFFD.
export function goJSONString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += value.slice(i, i + 2);
        i++;
      } else {
        out += "�";
      }
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      out += "�";
      continue;
    }
    switch (unit) {
      case 0x22:
        out += '\\"';
        continue;
      case 0x5c:
        out += "\\\\";
        continue;
      case 0x0a:
        out += "\\n";
        continue;
      case 0x0d:
        out += "\\r";
        continue;
      case 0x09:
        out += "\\t";
        continue;
      case 0x08:
        out += "\\b";
        continue;
      case 0x0c:
        out += "\\f";
        continue;
    }
    if (
      unit < 0x20 ||
      unit === 0x3c ||
      unit === 0x3e ||
      unit === 0x26 ||
      unit === 0x2028 ||
      unit === 0x2029
    ) {
      out += `\\u${unit.toString(16).padStart(4, "0")}`;
      continue;
    }
    out += value[i];
  }
  return `${out}"`;
}

function chainLinkDigest(l: ChainLink): Uint8Array {
  const canonical =
    `{"version":${l.version}` +
    `,"predecessor_session":${goJSONString(l.predecessor_session)}` +
    `,"predecessor_tail_seq":${l.predecessor_tail_seq}` +
    `,"predecessor_tail_hash":${goJSONString(l.predecessor_tail_hash)}` +
    `,"predecessor_signer_key":${goJSONString(l.predecessor_signer_key)}` +
    `,"successor_session":${goJSONString(l.successor_session)}` +
    `,"successor_signer_key":${goJSONString(l.successor_signer_key)}` +
    `,"linked_at":${goJSONString(l.linked_at)}}`;
  return new Uint8Array(Buffer.from(chainLinkDomain + canonical, "utf8"));
}

function validLowerHex(value: string, bytes: number): boolean {
  return new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "u").test(value);
}

const chainLinkFields = [
  "version",
  "predecessor_session",
  "predecessor_tail_seq",
  "predecessor_tail_hash",
  "predecessor_signer_key",
  "successor_session",
  "successor_signer_key",
  "linked_at",
  "signature",
] as const;

// goFoldKey maps a key the way Go's case-insensitive field match sees it
// against these all-ASCII field names: ASCII letters fold, and so do the two
// non-ASCII letters that fold to ASCII (U+017F to s, U+212A to k).
function goFoldKey(key: string): string {
  return [...key].map((ch) => (ch === "ſ" ? "s" : ch === "K" ? "k" : ch.toLowerCase())).join("");
}

// decodeChainLink applies the decoding rules of Go's UnmarshalChainLink:
// duplicate keys, case-folded aliases, unknown fields, and trailing tokens are
// rejected; a JSON null leaves the zero value; numbers must fit their Go type.
export function decodeChainLink(text: string): ChainLink {
  let raw: unknown;
  try {
    raw = parseJSONStrict(text);
  } catch (err) {
    throw new Error(`unmarshal chain link: ${(err as Error).message}`);
  }
  if (raw === null) raw = {};
  if (typeof raw !== "object" || Array.isArray(raw) || raw instanceof RawNumber) {
    throw new Error("unmarshal chain link: not a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const fields = new Set<string>(chainLinkFields);
  for (const key of Object.keys(obj)) {
    if (fields.has(key)) continue;
    for (const name of chainLinkFields) {
      if (goFoldKey(key) === name) {
        throw new Error(`unmarshal chain link: case-folded key: "${key}" aliases "${name}"`);
      }
    }
    throw new Error(`unmarshal chain link: json: unknown field "${key}"`);
  }
  const str = (field: string): string => {
    const value = obj[field];
    if (value === undefined || value === null) return "";
    if (typeof value !== "string") {
      throw new Error(`unmarshal chain link: ${field} must be a string`);
    }
    return value;
  };
  const uint = (field: string, max: bigint): string => {
    const value = obj[field];
    if (value === undefined || value === null) return "0";
    if (!(value instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(value.literal)) {
      throw new Error(`unmarshal chain link: ${field} must be an unsigned integer`);
    }
    if (BigInt(value.literal) > max) {
      throw new Error(`unmarshal chain link: ${field} overflows`);
    }
    return value.literal;
  };
  const versionValue = obj["version"];
  let version = 0;
  if (versionValue !== undefined && versionValue !== null) {
    if (
      !(versionValue instanceof RawNumber) ||
      !/^-?(?:0|[1-9][0-9]*)$/u.test(versionValue.literal)
    ) {
      throw new Error("unmarshal chain link: version must be an integer");
    }
    const parsed = BigInt(versionValue.literal);
    // Any other integer is a well-formed but unsupported version.
    version = parsed === 1n ? 1 : parsed === 0n ? 0 : -1;
  }
  return {
    version,
    predecessor_session: str("predecessor_session"),
    predecessor_tail_seq: uint("predecessor_tail_seq", maxUint64),
    predecessor_tail_hash: str("predecessor_tail_hash"),
    predecessor_signer_key: str("predecessor_signer_key"),
    successor_session: str("successor_session"),
    successor_signer_key: str("successor_signer_key"),
    linked_at: str("linked_at"),
    signature: str("signature"),
  };
}

// verifyChainLink mirrors Go's VerifyChainLink: structure, then the
// successor-key signature over the domain-separated canonical fields.
export async function verifyChainLink(l: ChainLink): Promise<void> {
  if (l.version !== chainLinkVersion) {
    throw new Error("unsupported chain link version");
  }
  if (blankAfterGoTrim(l.predecessor_session) || blankAfterGoTrim(l.successor_session)) {
    throw new Error("chain link sessions must be non-empty");
  }
  if (l.predecessor_session === l.successor_session) {
    throw new Error("chain link must not name its own session as predecessor");
  }
  if (!validLowerHex(l.predecessor_signer_key, 32)) {
    throw new Error("chain link predecessor_signer_key is invalid");
  }
  if (!validLowerHex(l.successor_signer_key, 32)) {
    throw new Error("chain link successor_signer_key is invalid");
  }
  if (!validLowerHex(l.predecessor_tail_hash, 32)) {
    throw new Error("chain link predecessor_tail_hash is invalid");
  }
  if (!isCanonicalUTCTimestamp(l.linked_at) || l.linked_at === "0001-01-01T00:00:00Z") {
    throw new Error("chain link linked_at must be canonical UTC RFC3339Nano");
  }
  if (l.signature === "") throw new Error("chain link signature is empty");
  if (!l.signature.startsWith(signaturePrefix)) {
    throw new Error(`invalid chain link signature format: missing ${signaturePrefix} prefix`);
  }
  const sigHex = l.signature.slice(signaturePrefix.length);
  if (!/^[0-9a-fA-F]{128}$/u.test(sigHex)) throw new Error("invalid chain link signature");
  const valid = await ed25519.verifyAsync(
    new Uint8Array(Buffer.from(sigHex, "hex")),
    chainLinkDigest(l),
    new Uint8Array(Buffer.from(l.successor_signer_key, "hex")),
    { zip215: false },
  );
  if (!valid) throw new Error("chain link signature verification failed");
}

async function readChainLinkFile(file: string): Promise<ChainLink> {
  const info = lstatSync(file);
  if (!info.isFile()) throw new Error("chain link file is not a regular file");
  if (info.size > maxChainLinkFileBytes) {
    throw new Error(`chain link file exceeds ${maxChainLinkFileBytes} bytes`);
  }
  const bytes = readVerifierBytes(file);
  if (bytes.length > maxChainLinkFileBytes) {
    throw new Error(`chain link file exceeds ${maxChainLinkFileBytes} bytes`);
  }
  const link = decodeChainLink(bytes.toString("utf8"));
  await verifyChainLink(link);
  return link;
}

interface ChainLinkRecord {
  name: string;
  namePred: string;
  link?: ChainLink;
  err?: string;
}

async function readChainLinkFiles(dir: string): Promise<ChainLinkRecord[]> {
  const names = readdirSync(dir)
    .filter((name) => chainLinkFilePredecessor(name) !== undefined)
    .sort(compareStrings);
  const out: ChainLinkRecord[] = [];
  for (const name of names) {
    const rec: ChainLinkRecord = { name, namePred: chainLinkFilePredecessor(name) as string };
    try {
      rec.link = await readChainLinkFile(path.join(dir, name));
    } catch (err) {
      rec.err = (err as Error).message;
    }
    out.push(rec);
  }
  return out;
}

function tailSeqString(receipt: Receipt): string {
  return String(receipt.action_record?.chain_seq ?? 0);
}

function safeReceiptHash(receipt: Receipt): string | undefined {
  try {
    return receiptHash(receipt);
  } catch {
    return undefined;
  }
}

// verifyCrossChainEndorsement mirrors Go: the endorsement must verify, be
// signed by the link's predecessor key, name the successor key, and bind the
// predecessor session and its exact linked tail.
export async function verifyCrossChainEndorsement(
  e: RotationEndorsement,
  link: ChainLink,
): Promise<boolean> {
  try {
    await verifyRotationEndorsement(e);
  } catch {
    return false;
  }
  return (
    e.session_id === link.predecessor_session &&
    e.prior_signer_key === link.predecessor_signer_key &&
    e.new_signer_key === link.successor_signer_key &&
    String(e.prior_final_seq) === link.predecessor_tail_seq &&
    e.prior_tail_hash === link.predecessor_tail_hash
  );
}

const appendedAfterLink = "entries were appended to the predecessor after the linked tail";

// checkLinkedTail returns undefined when link names receipts' exact tail,
// appendedAfterLink when it names an earlier receipt, or a mismatch message.
function checkLinkedTail(receipts: Receipt[], link: ChainLink): string | undefined {
  const last = receipts[receipts.length - 1] as Receipt;
  const lastHash = safeReceiptHash(last);
  if (lastHash === undefined) return "hashing predecessor tail failed";
  if (
    tailSeqString(last) === link.predecessor_tail_seq &&
    lastHash === link.predecessor_tail_hash
  ) {
    if (last.signer_key !== link.predecessor_signer_key) {
      return "link predecessor key does not sign the linked tail";
    }
    return undefined;
  }
  for (let i = receipts.length - 2; i >= 0; i--) {
    const r = receipts[i] as Receipt;
    if (
      safeReceiptHash(r) === link.predecessor_tail_hash &&
      tailSeqString(r) === link.predecessor_tail_seq
    ) {
      return appendedAfterLink;
    }
  }
  return `link names tail seq ${link.predecessor_tail_seq} hash ${link.predecessor_tail_hash}, predecessor tail is seq ${tailSeqString(last)} hash ${lastHash}`;
}

interface BaseChainData {
  chain: BaseChain;
  receipts: Receipt[];
  // The run's EvidenceReceipt v2 chain, verified beside its ActionReceipt v1
  // chain: a forged v2 receipt leaves the v1 chain intact.
  evidence: Receipt[];
}

function chainAcceptable(res: ChainResult): boolean {
  return (
    res.valid || (res.failure_kind === "lifecycle_missing_open" && res.integrity_verified === true)
  );
}

// verifyBase verifies every chain of base in dir and every link file that
// names a chain of base, mirroring Go's VerifyBase (non links-only mode).
// It throws only when the directory cannot be enumerated; a caller must treat
// that as incomplete, never as healthy.
export async function verifyBase(
  dir: string,
  base: string,
  opts: BaseVerifyOptions,
): Promise<BaseReport> {
  const report: BaseReport = { base, chains: [], findings: [] };
  const ix = indexRecorderFiles(dir);
  const sessions = sortedSessions(ix).filter((s) => isBaseChain(s, base));
  const links = await readChainLinkFiles(dir);
  const add = (kind: string, session: string, detail: string): void => {
    report.findings.push({ kind, session, detail });
  };

  const scoped = links.filter(
    (lf) =>
      isBaseChain(lf.namePred, base) ||
      (lf.link !== undefined &&
        (isBaseChain(lf.link.predecessor_session, base) ||
          isBaseChain(lf.link.successor_session, base))),
  );

  const data = new Map<string, BaseChainData>();
  for (const s of sessions) {
    const d: BaseChainData = {
      chain: {
        session: s,
        legacy: s === base,
        receipts: 0,
        final_seq: 0,
        tail_hash: "",
        signer_key: "",
        link_trust: "",
        valid: false,
        error: "",
      },
      receipts: [],
      evidence: [],
    };
    data.set(s, d);
    loadBaseChain(ix, d, add);
  }

  const successors = new Map<string, string[]>();
  for (const lf of scoped) {
    if (lf.link === undefined) {
      add(FindingInvalidLink, lf.namePred, `link file ${lf.name}: ${lf.err ?? "unreadable"}`);
      continue;
    }
    const link = lf.link;
    if (link.predecessor_session !== lf.namePred) {
      add(
        FindingLinkNameMismatch,
        lf.namePred,
        `link file ${lf.name} names predecessor "${link.predecessor_session}"`,
      );
    }
    successors.set(link.predecessor_session, [
      ...(successors.get(link.predecessor_session) ?? []),
      link.successor_session,
    ]);
    if (!isBaseChain(link.predecessor_session, base)) {
      add(
        FindingInvalidLink,
        link.successor_session,
        `link file ${lf.name}: predecessor "${link.predecessor_session}" is not a chain of "${base}"`,
      );
      continue;
    }
    if (runSessionBase(link.successor_session) !== base) {
      add(
        FindingInvalidLink,
        link.successor_session,
        `link file ${lf.name}: successor is not a run chain of "${base}"`,
      );
      continue;
    }
    const sd = data.get(link.successor_session);
    if (sd === undefined) {
      add(
        FindingDanglingLink,
        link.successor_session,
        `link file ${lf.name}: successor "${link.successor_session}" not found`,
      );
      continue;
    }
    if (sd.chain.link !== undefined) {
      add(
        FindingInvalidLink,
        link.successor_session,
        `link file ${lf.name}: successor already continues "${sd.chain.link.predecessor_session}"`,
      );
      continue;
    }
    sd.chain.link = link;
    sd.chain.link_file = lf.name;
  }

  // An endorsement vouches for a successor key only once the chain holding
  // the endorsing key has itself verified, so chains resolve in dependency
  // order; a cycle never reaches a verified root and stays unendorsed.
  const endorsed = new Map<string, boolean>();
  const endorsable = new Set<string>();
  const crossUsed = new Set<number>();
  for (const s of sessions) {
    const link = data.get(s)?.chain.link;
    if (link === undefined || link.successor_signer_key === link.predecessor_signer_key) continue;
    for (let i = 0; i < opts.endorsements.length; i++) {
      if (await verifyCrossChainEndorsement(opts.endorsements[i] as RotationEndorsement, link)) {
        endorsable.add(s);
        crossUsed.add(i);
        break;
      }
    }
  }
  const verify = async (s: string): Promise<void> => {
    const d = data.get(s) as BaseChainData;
    const own = opts.endorsements.filter(
      (e, i) => e.session_id === s && !crossUsed.has(i) && !bindsFinalReceipt(e, d.chain),
    );
    await verifyBaseChain(d, opts.trustedKeys, own, endorsed.get(s) === true, add);
  };
  const resolved = new Set<string>();
  let pending = sessions;
  for (let progress = true; progress && pending.length > 0;) {
    progress = false;
    const waiting: string[] = [];
    for (const s of pending) {
      if (endorsable.has(s)) {
        const d = data.get(s) as BaseChainData;
        const predSession = (d.chain.link as ChainLink).predecessor_session;
        const pred = data.get(predSession);
        if (pred !== undefined && !resolved.has(predSession)) {
          waiting.push(s);
          continue;
        }
        endorsed.set(
          s,
          pred !== undefined &&
            pred.chain.valid &&
            pred.receipts.length > 0 &&
            checkLinkedTail(pred.receipts, d.chain.link as ChainLink) === undefined,
        );
      }
      await verify(s);
      resolved.add(s);
      progress = true;
    }
    pending = waiting;
  }
  for (const s of pending) await verify(s);

  for (const s of sessions) checkBaseLink(data, s, opts, endorsed.get(s) === true, add);
  for (const p of [...successors.keys()].sort(compareStrings)) {
    const succ = successors.get(p) as string[];
    if (succ.length > 1) {
      add(FindingDoubleSuccessor, p, `continued by ${succ.length} link files: [${succ.join(" ")}]`);
    }
  }
  checkRunNonces(sessions, data, add);
  for (const s of sessions) report.chains.push((data.get(s) as BaseChainData).chain);
  return report;
}

// checkRunNonces reports two chains of the base that carry the same run_nonce.
// Every action record a process run signs carries that run's nonce, and a run
// writes exactly one chain, so a nonce in two chains means one run's evidence
// appears twice: a replayed or copied run under a second session name. The
// session_id and file name are unsigned; the nonce is signed. Only chains that
// verified are compared, so the nonce is one their signatures cover; a chain
// with no action records has no nonce and is not compared. Each chain sharing
// the nonce is named, because nothing signed says which one is the original.
function checkRunNonces(
  sessions: string[],
  data: Map<string, BaseChainData>,
  add: (kind: string, session: string, detail: string) => void,
): void {
  const holders = new Map<string, string[]>();
  for (const s of sessions) {
    const d = data.get(s) as BaseChainData;
    if (!d.chain.valid || d.receipts.length === 0) continue;
    const nonces = new Set<string>();
    for (const r of d.receipts) {
      const nonce = r.action_record?.run_nonce;
      if (typeof nonce === "string" && nonce !== "") nonces.add(nonce);
    }
    for (const nonce of nonces) holders.set(nonce, [...(holders.get(nonce) ?? []), s]);
  }
  for (const nonce of [...holders.keys()].sort(compareStrings)) {
    const chains = holders.get(nonce) as string[];
    if (chains.length < 2) continue;
    for (const s of chains) {
      const others = chains.filter((c) => c !== s);
      add(
        FindingDuplicateRunNonce,
        s,
        `run_nonce ${nonce} is also carried by ${others.join(", ")}: one run's signed records appear in more than one chain`,
      );
    }
  }
}

function loadBaseChain(
  ix: EvidenceIndex,
  d: BaseChainData,
  add: (kind: string, session: string, detail: string) => void,
): void {
  const s = d.chain.session;
  let lines: ParsedRecorderLine[];
  try {
    lines = readSessionLines(ix, s);
  } catch (err) {
    d.chain.error = (err as Error).message;
    add(FindingCorruptChain, s, d.chain.error);
    return;
  }
  const outer = verifyRecorderChain(lines);
  if (outer !== undefined) add(FindingOuterChainBroken, s, outer);
  try {
    const typed = extractTypedFromEntries(lines.map((l) => l.entry));
    d.receipts = typed.action;
    d.evidence = typed.evidence;
  } catch (err) {
    d.receipts = [];
    d.evidence = [];
    d.chain.error = (err as Error).message;
    add(FindingCorruptChain, s, d.chain.error);
    return;
  }
  if (d.receipts.length === 0) {
    // A chain holding only EvidenceReceipt v2 entries is decided by
    // verifyBaseChain, never passed with nothing verified.
    d.chain.valid = d.evidence.length === 0;
    return;
  }
  const last = d.receipts[d.receipts.length - 1] as Receipt;
  d.chain.receipts = d.receipts.length;
  d.chain.signer_key = d.receipts[0]?.signer_key ?? "";
  d.chain.final_seq = last.action_record?.chain_seq ?? 0;
  d.chain.tail_hash = safeReceiptHash(last) ?? "";
}

async function verifyBaseChain(
  d: BaseChainData,
  trusted: string[],
  own: RotationEndorsement[],
  isEndorsed: boolean,
  add: (kind: string, session: string, detail: string) => void,
): Promise<void> {
  if (d.chain.error !== "" || (d.receipts.length === 0 && d.evidence.length === 0)) return;
  let keys = trusted;
  if (isEndorsed && trusted.length > 0 && d.chain.link !== undefined) {
    keys = [...trusted, d.chain.link.successor_signer_key];
  }
  if (d.receipts.length > 0) {
    const res =
      own.length > 0
        ? await verifyChainWithEndorsements(d.receipts, keys.join(","), {
            sessionID: d.chain.session,
            endorsements: own,
          })
        : await verifyChain(d.receipts, keys.join(","), { allowUnpinned: keys.length === 0 });
    if (!chainAcceptable(res)) {
      d.chain.valid = false;
      d.chain.error = res.error ?? "chain verification failed";
      add(FindingCorruptChain, d.chain.session, d.chain.error);
      return;
    }
  }
  if (d.evidence.length > 0) {
    const res = await verifyChain(d.evidence, evidenceChainKey(keys.join(","), d.evidence), {
      allowUnpinned: keys.length === 0,
    });
    if (!res.valid) {
      d.chain.valid = false;
      d.chain.error = `evidence receipt chain: ${res.error ?? "chain verification failed"}`;
      add(FindingCorruptChain, d.chain.session, d.chain.error);
      return;
    }
  }
  d.chain.valid = true;
}

function checkBaseLink(
  data: Map<string, BaseChainData>,
  s: string,
  opts: BaseVerifyOptions,
  isEndorsed: boolean,
  add: (kind: string, session: string, detail: string) => void,
): void {
  const d = data.get(s) as BaseChainData;
  const link = d.chain.link;
  if (link === undefined) return;
  if (d.receipts.length > 0 && d.receipts[0]?.signer_key !== link.successor_signer_key) {
    add(FindingInvalidLink, s, "link successor key does not sign the chain");
  }
  const pred = data.get(link.predecessor_session);
  if (pred === undefined) {
    add(FindingDanglingLink, s, `predecessor "${link.predecessor_session}" not found`);
    return;
  }
  if (!pred.chain.valid || pred.receipts.length === 0) {
    add(
      FindingPredecessorUnverified,
      s,
      `predecessor "${link.predecessor_session}" did not verify`,
    );
    return;
  }
  const tailErr = checkLinkedTail(pred.receipts, link);
  if (tailErr !== undefined) {
    add(
      tailErr === appendedAfterLink ? FindingAppendedAfterLink : FindingLinkTailMismatch,
      link.predecessor_session,
      `linked by ${s}: ${tailErr}`,
    );
  }
  if (link.successor_signer_key === link.predecessor_signer_key) {
    d.chain.link_trust = LinkTrustSameKey;
  } else if (opts.trustedKeys.includes(link.successor_signer_key)) {
    d.chain.link_trust = LinkTrustTrustedKey;
  } else if (isEndorsed) {
    d.chain.link_trust = LinkTrustEndorsed;
  } else {
    add(
      FindingUntrustedSuccessorKey,
      s,
      "successor key differs from predecessor key and is neither trusted nor endorsed",
    );
  }
}

// bindsFinalReceipt reports whether e hands off from c's last receipt, which
// only a cross-chain endorsement does.
function bindsFinalReceipt(e: RotationEndorsement, c: BaseChain): boolean {
  return (
    c.tail_hash !== "" && e.prior_final_seq === c.final_seq && e.prior_tail_hash === c.tail_hash
  );
}

// chainScopedTrust narrows the operator's endorsements and keys to one chain,
// as Go's verify-receipt does: an endorsement that authorizes a key change
// across a link is placed by the link check, never handed to either chain.
export async function chainScopedTrust(
  report: BaseReport,
  session: string,
  trustedKeys: string[],
  endorsements: RotationEndorsement[],
): Promise<{ keys: string[]; endorsements: RotationEndorsement[] }> {
  const own: RotationEndorsement[] = [];
  for (const e of endorsements) {
    if (e.session_id !== session) continue;
    let crossChain = false;
    for (const c of report.chains) {
      if (c.link !== undefined && (await verifyCrossChainEndorsement(e, c.link))) {
        crossChain = true;
        break;
      }
      if (c.session === session && bindsFinalReceipt(e, c)) {
        crossChain = true;
        break;
      }
    }
    if (!crossChain) own.push(e);
  }
  let keys = trustedKeys;
  for (const c of report.chains) {
    if (c.session === session && c.link !== undefined && c.link_trust === LinkTrustEndorsed) {
      keys = [...trustedKeys, c.link.successor_signer_key];
    }
  }
  return { keys, endorsements: own };
}

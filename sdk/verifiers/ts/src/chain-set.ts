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

import { lstatSync, readdirSync, realpathSync, statSync } from "node:fs";
import * as path from "node:path";
import * as ed25519 from "@noble/ed25519";
import { parseJSONStrict, RawNumber } from "./aarp/strictjson.js";
import { evidenceChainKey, receiptHash, verifyChain } from "./chain.js";
import {
  extractTypedFromEntries,
  parseEntryLinesText,
  readEntryLines,
  readEntryLinesPrefix,
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
import { InvalidError, RuntimeError, decodeUTF8, readVerifierBytes, sha256Hex } from "./util.js";
import { blankAfterGoTrim } from "./line-space.js";
export { blankAfterGoTrim } from "./line-space.js";

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
export const FindingInvalidRecoverySeal = "invalid_recovery_seal";
export const FindingAttestedDiscontinuity = "attested_discontinuity";
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
const recoverySealDomain = "pipelock-recovery-seal-v1\u0000";
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

export interface RecoverySeal {
  kind: "recovery_seal";
  version: 1;
  predecessor_session: string;
  shard: string;
  shard_size: number;
  shard_sha256: string;
  damage_offset: number;
  last_good_seq: number;
  last_good_hash: string;
  predecessor_tail_seq: number;
  predecessor_tail_hash: string;
  predecessor_signer_key: string;
  successor_session: string;
  successor_signer_key: string;
  successor_open_hash: string;
  observed_at: string;
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
  recovery_seal?: RecoverySeal;
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
  return report.chains
    .filter((c) => c.link === undefined && c.recovery_seal === undefined)
    .map((c) => c.session);
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

// refuseSymlinkInEvidenceRootPath applies Go's no-symlink evidence-root rule
// (recorder.refuseSymlinkInWalkedRootPath) to the path the operating system
// walks, before path.normalize turns "link/../ev" into "ev" and hides the
// symlink the open would follow.
export function refuseSymlinkInEvidenceRootPath(root: string): void {
  const volumeRoot = path.parse(root).root;
  const raw = path.isAbsolute(root)
    ? root
    : volumeRoot
      ? `${path.resolve(volumeRoot)}${path.sep}${root.slice(volumeRoot.length)}`
      : `${process.cwd()}${path.sep}${root}`;
  const parsedRoot = path.parse(raw).root;
  let current = path.resolve(parsedRoot);
  // Only the platform's separators split a path: on POSIX a backslash is an
  // ordinary filename character, so "s\.." names one entry, not "s" and "..".
  const separators = path.sep === "\\" ? /[\\/]/u : /\//u;
  for (const component of raw.slice(parsedRoot.length).split(separators)) {
    if (component === "" || component === ".") continue;
    if (component === "..") {
      // Every component walked so far is not a symlink, so the lexical parent
      // is the physical parent. The operating system climbs out of a
      // directory only: "file/.." fails with ENOTDIR, so it fails here too.
      if (!lstatSync(current).isDirectory()) {
        throw new Error(`evidence root component "${current}" is not a directory`);
      }
      current = path.dirname(current);
      continue;
    }
    current = path.join(current, component);
    if (lstatSync(current).isSymbolicLink()) {
      throw new EvidenceRefusedError(`refuse symlink in evidence root path: "${current}"`);
    }
  }
}

// Directory mode runs in one CLI process. Enter each component from the
// kernel-held working directory, then compare its identity and physical path
// with the selected child. A renamed parent cannot redirect later reads.
// A search-only ancestor need not grant read access to open a directory handle.
let evidenceDirectoryActive = false;
function samePhysicalPath(actual: string, expected: string): boolean {
  if (process.platform === "win32") {
    return (
      path.win32.normalize(actual).toLowerCase() === path.win32.normalize(expected).toLowerCase()
    );
  }
  return actual === expected;
}

function enterPinnedEvidenceDirectory(root: string): () => void {
  if (evidenceDirectoryActive)
    throw new Error("concurrent evidence directory reads are unsupported");
  const original = process.cwd();
  evidenceDirectoryActive = true;
  const parents: { dev: bigint; ino: bigint; physical: string }[] = [];
  try {
    const parsed = path.parse(root);
    if (parsed.root !== "") process.chdir(parsed.root);
    const anchor = statSync(".", { bigint: true });
    parents.push({ dev: anchor.dev, ino: anchor.ino, physical: realpathSync.native(".") });
    const separators = path.sep === "\\" ? /[\\/]/u : /\//u;
    for (const component of root.slice(parsed.root.length).split(separators)) {
      if (component === "" || component === ".") continue;
      if (component === "..") {
        // Compare the selected parent after climbing. A rename can move the
        // current child under a different parent between these two steps.
        const initialParent = parents.length === 1;
        const expected = initialParent
          ? {
              ...statSync("..", { bigint: true }),
              physical: realpathSync.native(".."),
            }
          : (parents[parents.length - 2] as { dev: bigint; ino: bigint; physical: string });
        process.chdir("..");
        const entered = statSync(".", { bigint: true });
        const physical = realpathSync.native(".");
        if (
          !entered.isDirectory() ||
          entered.dev !== expected.dev ||
          entered.ino !== expected.ino ||
          entered.ino === 0n ||
          !samePhysicalPath(physical, expected.physical)
        ) {
          throw new EvidenceRefusedError("evidence root parent changed while entering");
        }
        if (initialParent) {
          parents[0] = { dev: entered.dev, ino: entered.ino, physical };
        } else {
          parents.pop();
        }
        continue;
      }
      const expectedPath = path.join(parents[parents.length - 1]!.physical, component);
      // Capture the filesystem's canonical spelling before pinning the entry.
      // A case-insensitive volume may accept a spelling that differs from the
      // stored name; resolving after entry would reopen the replacement race.
      const expectedPhysical = realpathSync.native(expectedPath);
      const before = lstatSync(component, { bigint: true });
      if (before.isSymbolicLink()) {
        throw new EvidenceRefusedError(`refuse symlink in evidence root path: "${component}"`);
      }
      if (!before.isDirectory())
        throw new Error(`evidence root component "${component}" is not a directory`);
      const canonical = lstatSync(expectedPhysical, { bigint: true });
      const parentPhysical = parents[parents.length - 1]!.physical;
      const sameName =
        process.platform === "darwin"
          ? path.basename(expectedPhysical).toLowerCase() === component.toLowerCase()
          : samePhysicalPath(expectedPhysical, expectedPath);
      if (
        !samePhysicalPath(path.dirname(expectedPhysical), parentPhysical) ||
        !sameName ||
        canonical.isSymbolicLink() ||
        !canonical.isDirectory() ||
        canonical.dev !== before.dev ||
        canonical.ino !== before.ino
      ) {
        throw new EvidenceRefusedError(
          `evidence root component changed while entering: "${component}"`,
        );
      }
      process.chdir(component);
      const entered = statSync(".", { bigint: true });
      const physical = realpathSync.native(".");
      if (
        !entered.isDirectory() ||
        entered.dev !== before.dev ||
        entered.ino !== before.ino ||
        entered.ino === 0n ||
        !samePhysicalPath(physical, expectedPhysical)
      ) {
        throw new EvidenceRefusedError(
          `evidence root component changed while entering: "${component}"`,
        );
      }
      parents.push({ dev: entered.dev, ino: entered.ino, physical });
    }
  } catch (err) {
    try {
      process.chdir(original);
    } finally {
      evidenceDirectoryActive = false;
    }
    throw err;
  }
  return () => {
    try {
      process.chdir(original);
    } finally {
      evidenceDirectoryActive = false;
    }
  };
}

// The one-shot CLI owns its process while verification awaits. A caller that
// shares a process with other filesystem work must use the synchronous form.
export async function withPinnedEvidenceDirectory<T>(
  root: string,
  read: () => Promise<T>,
): Promise<T> {
  const leave = enterPinnedEvidenceDirectory(root);
  try {
    return await read();
  } finally {
    leave();
  }
}

export function withPinnedEvidenceDirectorySync<T>(root: string, read: () => T): T {
  const leave = enterPinnedEvidenceDirectory(root);
  try {
    return read();
  } finally {
    leave();
  }
}

function indexRecorderFiles(dir: string): EvidenceIndex {
  const shards = new Map<string, { file: string; name: string; seq: bigint }[]>();
  const symlinks = new Map<string, string[]>();
  for (const de of readdirSync(dir, { withFileTypes: true })) {
    if (!de.name.endsWith(evidenceSuffix)) continue;
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

// Return the validated session order used by the ordinary evidence reader.
export function sessionEvidenceFiles(dir: string, session: string): string[] {
  return indexFiles(indexRecorderFiles(dir), session);
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

// SessionTail selects how a session's final unterminated write is treated.
// "whole" is the ordinary evidence reader: the fragment is parsed like any
// other line, so a torn tail is a parse failure. "prefix" is the receipt group
// reader, where Go's session walker delivers every complete line and then
// reports the fragment as a torn tail the caller must classify.
export type SessionTail = "whole" | "prefix";

interface SessionLinesRead {
  lines: ParsedRecorderLine[];
  torn: boolean;
}

function checkLineSession(l: ParsedRecorderLine, file: string, session: string): void {
  if (l.entry.session_id !== session) {
    throw new EvidenceRefusedError(
      `reading ${path.basename(file)}: entry seq ${String(l.entry.seq)} session_id ${JSON.stringify(l.entry.session_id ?? null)} does not match requested session ${JSON.stringify(session)}`,
    );
  }
}

// readSessionLines reads every recorder entry of one session in shard order.
// Like Go's session reader (internal/recorder/query.go), it refuses an entry
// whose session_id is not the session its file name claims: a file named for
// run X that holds run Y's entries is not run X's evidence.
function readSessionLines(
  ix: EvidenceIndex,
  session: string,
  tail: SessionTail = "whole",
): SessionLinesRead {
  const out: ParsedRecorderLine[] = [];
  const files = indexFiles(ix, session);
  let torn = false;
  for (let i = 0; i < files.length; i++) {
    const file = files[i] as string;
    if (tail === "whole") {
      for (const l of readEntryLines(file, evidenceDirectoryActive)) {
        checkLineSession(l, file, session);
        out.push(l);
      }
      continue;
    }
    const read = readEntryLinesPrefix(file, evidenceDirectoryActive);
    for (const l of read.lines) {
      checkLineSession(l, file, session);
      out.push(l);
    }
    if (!read.torn) continue;
    // A later segment may hold authenticated entries, so only the last
    // segment's fragment is a recoverable final write.
    if (i + 1 < files.length)
      throw new InvalidError(`receipt group session has a torn segment: ${path.basename(file)}`);
    torn = true;
  }
  return { lines: out, torn };
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
  // torn is true only for tail "prefix": the final shard ends in an
  // unterminated fragment that is not part of lines.
  torn: boolean;
}

// readSessionEvidence reads one session of dir with the refusals above. Only a
// receipt group caller passes tail "prefix"; it also accepts the group gate
// entry, which every other reader treats as an unknown entry type.
export function readSessionEvidence(
  dir: string,
  session: string,
  tail: SessionTail = "whole",
): SessionEvidence {
  const before = baseInventory(dir, session, false);
  let read: SessionLinesRead;
  try {
    read = readSessionLines(indexRecorderFiles(dir), session, tail);
  } finally {
    if (baseInventory(dir, session, false) !== before) {
      throw new RuntimeError("evidence changed during verification; no verdict reached");
    }
  }
  return {
    lines: read.lines,
    typed: extractTypedFromEntries(
      read.lines.map((l) => l.entry),
      tail === "prefix",
    ),
    torn: read.torn,
  };
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

const recoverySealFields = [
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
] as const;

function safeSealNumber(obj: Record<string, unknown>, field: string): number {
  const value = obj[field];
  if (!(value instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(value.literal)) {
    throw new Error(`recovery seal ${field} must be an unsigned integer`);
  }
  const n = BigInt(value.literal);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`recovery seal ${field} exceeds the cross-language safe integer limit`);
  }
  return Number(n);
}

// decodeRecoverySeal is strict by design: unlike ChainLink's legacy zero
// values, every signed recovery field is required and has one exact spelling.
export function decodeRecoverySeal(text: string): RecoverySeal {
  const raw = parseJSONStrict(text);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || raw instanceof RawNumber) {
    throw new Error("recovery seal is not a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  const fields = new Set<string>(recoverySealFields);
  for (const key of Object.keys(obj)) {
    if (fields.has(key)) continue;
    for (const name of recoverySealFields) {
      if (goFoldKey(key) === name)
        throw new Error(`recovery seal key alias: ${key} aliases ${name}`);
    }
    throw new Error(`recovery seal unknown field ${key}`);
  }
  for (const field of recoverySealFields) {
    if (!(field in obj) || obj[field] === null) throw new Error(`recovery seal missing ${field}`);
  }
  const str = (field: string): string => {
    const value = obj[field];
    if (typeof value !== "string") throw new Error(`recovery seal ${field} must be a string`);
    return value;
  };
  if (str("kind") !== "recovery_seal") throw new Error("unknown recovery seal kind");
  const versionRaw = obj["version"];
  if (!(versionRaw instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(versionRaw.literal)) {
    throw new Error("recovery seal version must be an unsigned integer");
  }
  if (versionRaw.literal !== "1")
    throw new Error(`unsupported recovery seal version ${versionRaw.literal}`);
  return {
    kind: "recovery_seal",
    version: 1,
    predecessor_session: str("predecessor_session"),
    shard: str("shard"),
    shard_size: safeSealNumber(obj, "shard_size"),
    shard_sha256: str("shard_sha256"),
    damage_offset: safeSealNumber(obj, "damage_offset"),
    last_good_seq: safeSealNumber(obj, "last_good_seq"),
    last_good_hash: str("last_good_hash"),
    predecessor_tail_seq: safeSealNumber(obj, "predecessor_tail_seq"),
    predecessor_tail_hash: str("predecessor_tail_hash"),
    predecessor_signer_key: str("predecessor_signer_key"),
    successor_session: str("successor_session"),
    successor_signer_key: str("successor_signer_key"),
    successor_open_hash: str("successor_open_hash"),
    observed_at: str("observed_at"),
    signature: str("signature"),
  };
}

function recoverySealDigest(s: RecoverySeal): Uint8Array {
  const canonical =
    `{"kind":${goJSONString(s.kind)},"version":${s.version}` +
    `,"predecessor_session":${goJSONString(s.predecessor_session)}` +
    `,"shard":${goJSONString(s.shard)},"shard_size":${s.shard_size}` +
    `,"shard_sha256":${goJSONString(s.shard_sha256)},"damage_offset":${s.damage_offset}` +
    `,"last_good_seq":${s.last_good_seq},"last_good_hash":${goJSONString(s.last_good_hash)}` +
    `,"predecessor_tail_seq":${s.predecessor_tail_seq}` +
    `,"predecessor_tail_hash":${goJSONString(s.predecessor_tail_hash)}` +
    `,"predecessor_signer_key":${goJSONString(s.predecessor_signer_key)}` +
    `,"successor_session":${goJSONString(s.successor_session)}` +
    `,"successor_signer_key":${goJSONString(s.successor_signer_key)}` +
    `,"successor_open_hash":${goJSONString(s.successor_open_hash)}` +
    `,"observed_at":${goJSONString(s.observed_at)}}`;
  return new Uint8Array(Buffer.from(recoverySealDomain + canonical, "utf8"));
}

export function recoverySealSigningBytes(s: RecoverySeal): Uint8Array {
  return recoverySealDigest(s);
}

export async function verifyRecoverySealSignature(s: RecoverySeal): Promise<void> {
  if (s.kind !== "recovery_seal" || s.version !== 1) {
    throw new Error("unsupported recovery seal kind or version");
  }
  if (blankAfterGoTrim(s.predecessor_session) || blankAfterGoTrim(s.successor_session)) {
    throw new Error("recovery seal sessions must be non-empty");
  }
  if (
    [s.predecessor_session, s.successor_session].some(
      (session) => session.includes("/") || session.includes("\\"),
    )
  ) {
    throw new Error("recovery seal session identity is invalid");
  }
  if (s.predecessor_session === s.successor_session)
    throw new Error("recovery seal sessions must differ");
  const base = runSessionBase(s.successor_session);
  if (base === undefined || !isBaseChain(s.predecessor_session, base)) {
    throw new Error("recovery seal must bind distinct sessions of one base");
  }
  if (path.basename(s.shard) !== s.shard || s.shard.includes("/") || s.shard.includes("\\")) {
    throw new Error("recovery seal shard must be a root-relative basename");
  }
  const parsed = parseEvidenceFilename(s.shard);
  if (parsed?.session !== s.predecessor_session)
    throw new Error("recovery seal shard name mismatch");
  for (const [field, value] of [
    ["shard_sha256", s.shard_sha256],
    ["successor_open_hash", s.successor_open_hash],
  ]) {
    if (!validLowerHex(value, 32)) throw new Error(`recovery seal ${field} is invalid`);
  }
  for (const [field, value] of [
    ["last_good_hash", s.last_good_hash],
    ["predecessor_tail_hash", s.predecessor_tail_hash],
  ]) {
    if (value !== "genesis" && !validLowerHex(value, 32)) {
      throw new Error(`recovery seal ${field} is invalid`);
    }
  }
  if (!validLowerHex(s.predecessor_signer_key, 32) || !validLowerHex(s.successor_signer_key, 32)) {
    throw new Error("recovery seal signer key is invalid");
  }
  if (s.shard_size === 0 || s.damage_offset >= s.shard_size) {
    throw new Error("recovery seal damage_offset must be within a non-empty shard");
  }
  if (!isCanonicalUTCTimestamp(s.observed_at) || s.observed_at === "0001-01-01T00:00:00Z") {
    throw new Error("recovery seal observed_at must be canonical UTC RFC3339Nano");
  }
  if (!/^ed25519:[0-9a-f]{128}$/u.test(s.signature))
    throw new Error("invalid recovery seal signature");
  const ok = await ed25519.verifyAsync(
    new Uint8Array(Buffer.from(s.signature.slice(signaturePrefix.length), "hex")),
    recoverySealDigest(s),
    new Uint8Array(Buffer.from(s.successor_signer_key, "hex")),
    { zip215: false },
  );
  if (!ok) throw new Error("recovery seal signature verification failed");
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

async function readChainLinkFile(
  file: string,
): Promise<{ link?: ChainLink; recoverySeal?: RecoverySeal; sealCandidate: boolean }> {
  const info = lstatSync(file);
  if (!info.isFile()) throw new Error("chain link file is not a regular file");
  if (info.size > maxChainLinkFileBytes) {
    throw new Error(`chain link file exceeds ${maxChainLinkFileBytes} bytes`);
  }
  const bytes = readVerifierBytes(file, evidenceDirectoryActive, maxChainLinkFileBytes);
  if (bytes.length > maxChainLinkFileBytes) {
    throw new Error(`chain link file exceeds ${maxChainLinkFileBytes} bytes`);
  }
  const text = decodeUTF8(bytes, "chain link JSON");
  let rawKind: unknown;
  try {
    const raw = parseJSONStrict(text);
    rawKind =
      typeof raw === "object" && raw !== null && !Array.isArray(raw)
        ? (raw as Record<string, unknown>)["kind"]
        : undefined;
  } catch {
    rawKind = undefined;
  }
  if (rawKind !== undefined) {
    if (rawKind !== "recovery_seal")
      throw new Error(`unknown predecessor claim kind ${String(rawKind)}`);
    const recoverySeal = decodeRecoverySeal(text);
    await verifyRecoverySealSignature(recoverySeal);
    return { recoverySeal, sealCandidate: true };
  }
  const link = decodeChainLink(text);
  await verifyChainLink(link);
  return { link, sealCandidate: false };
}

interface ChainLinkRecord {
  name: string;
  namePred: string;
  link?: ChainLink;
  recoverySeal?: RecoverySeal;
  sealCandidate?: boolean;
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
      const decoded = await readChainLinkFile(path.join(dir, name));
      rec.link = decoded.link;
      rec.recoverySeal = decoded.recoverySeal;
      rec.sealCandidate = decoded.sealCandidate;
    } catch (err) {
      let rawText: string | undefined;
      try {
        rawText = decodeUTF8(
          readVerifierBytes(
            evidenceDirectoryActive ? name : path.join(dir, name),
            evidenceDirectoryActive,
            maxChainLinkFileBytes,
          ),
          "chain link JSON",
        );
        const raw = parseJSONStrict(rawText);
        rec.sealCandidate =
          typeof raw === "object" &&
          raw !== null &&
          !Array.isArray(raw) &&
          Object.keys(raw as Record<string, unknown>).some((key) => goFoldKey(key) === "kind");
      } catch {
        try {
          rec.sealCandidate =
            rawText !== undefined && /"kind"\s*:\s*"recovery_seal"/u.test(rawText);
        } catch {
          rec.sealCandidate = false;
        }
      }
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
  return withBaseHistorySnapshot(dir, base, () => verifyBaseInner(dir, base, opts));
}

// Defer publication until all reads used to assemble a base report finish.
export async function withBaseHistorySnapshot<T>(
  dir: string,
  base: string,
  consume: () => Promise<T>,
): Promise<T> {
  const before = baseInventory(dir, base);
  try {
    return await consume();
  } finally {
    let changed = true;
    try {
      changed = baseInventory(dir, base) !== before;
    } catch {
      // Unavailable final inventory cannot support either verdict.
    }
    if (changed) throw new RuntimeError("evidence changed during verification; no verdict reached");
  }
}

function baseInventory(dir: string, base: string, baseMode = true): string {
  const root = statSync(dir, { bigint: true });
  const items: unknown[] = [[root.dev.toString(), root.ino.toString()]];
  for (const name of readdirSync(dir).sort()) {
    const parsed = parseEvidenceFilename(name);
    if (
      !(
        parsed !== undefined &&
        (baseMode ? isBaseChain(parsed.session, base) : parsed.session === base)
      ) &&
      !(baseMode && chainLinkFilePredecessor(name) !== undefined)
    )
      continue;
    const info = lstatSync(path.join(dir, name), { bigint: true });
    items.push(
      [name, info.dev, info.ino, info.mode, info.size, info.mtimeNs, info.ctimeNs].map(String),
    );
  }
  return sha256Hex(JSON.stringify(items));
}

async function verifyBaseInner(
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
          isBaseChain(lf.link.successor_session, base))) ||
      (lf.recoverySeal !== undefined &&
        (isBaseChain(lf.recoverySeal.predecessor_session, base) ||
          isBaseChain(lf.recoverySeal.successor_session, base))),
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
  const recoveryRecords: ChainLinkRecord[] = [];
  for (const lf of scoped) {
    if (lf.sealCandidate || lf.recoverySeal !== undefined) {
      if (lf.recoverySeal === undefined) {
        add(
          FindingInvalidRecoverySeal,
          lf.namePred,
          `recovery seal file ${lf.name}: ${lf.err ?? "invalid recovery seal"}`,
        );
        continue;
      }
      const seal = lf.recoverySeal;
      if (seal.predecessor_session !== lf.namePred) {
        add(
          FindingInvalidRecoverySeal,
          lf.namePred,
          `recovery seal file ${lf.name} names another predecessor`,
        );
        continue;
      }
      if (
        !isBaseChain(seal.predecessor_session, base) ||
        runSessionBase(seal.successor_session) !== base
      ) {
        add(
          FindingInvalidRecoverySeal,
          seal.successor_session,
          "recovery seal sessions do not belong to this base",
        );
        continue;
      }
      successors.set(seal.predecessor_session, [
        ...(successors.get(seal.predecessor_session) ?? []),
        seal.successor_session,
      ]);
      // Queue for binding verification only after the placement checks pass,
      // so a seal rejected above can never attach in the second pass.
      recoveryRecords.push(lf);
      continue;
    }
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
  for (const lf of recoveryRecords) {
    const seal = lf.recoverySeal;
    if (seal === undefined || lf.err !== undefined) continue;
    try {
      const successor = data.get(seal.successor_session);
      if (successor === undefined)
        throw new Error(`successor "${seal.successor_session}" not found`);
      if (successor.chain.link !== undefined || successor.chain.recovery_seal !== undefined)
        throw new Error("recovery successor already has a predecessor claim");
      if (
        seal.successor_signer_key !== seal.predecessor_signer_key &&
        !opts.trustedKeys.includes(seal.successor_signer_key)
      ) {
        throw new Error("recovery successor key differs and is not explicitly trusted");
      }
      await verifyRecoveryBinding(ix, seal, data, opts.trustedKeys);
      successor.chain.recovery_seal = seal;
      successor.chain.link_file = lf.name;
      add(
        FindingAttestedDiscontinuity,
        seal.successor_session,
        `linked across attested discontinuity from ${seal.predecessor_session} at ${seal.shard}:${seal.damage_offset}`,
      );
    } catch (err) {
      add(FindingInvalidRecoverySeal, seal.successor_session, (err as Error).message);
    }
  }
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

// verifyRecoveryBinding checks the signed observation against the bytes and
// independently verifies both receipt chains on the recoverable side of the
// discontinuity. It intentionally does not make the damaged predecessor
// healthy: callers retain the original corruption finding.
async function verifyRecoveryBinding(
  ix: EvidenceIndex,
  seal: RecoverySeal,
  data: Map<string, BaseChainData>,
  trustedKeys: readonly string[] = [],
): Promise<ExtractedReceipts> {
  await verifyRecoverySealSignature(seal);
  const keys = trustedKeys.join(",");
  const files = indexFiles(ix, seal.predecessor_session);
  const final = files.at(-1);
  if (final === undefined || path.basename(final) !== seal.shard) {
    throw new Error("recovery seal shard is not the predecessor's final shard");
  }
  const raw = readVerifierBytes(
    evidenceDirectoryActive ? path.basename(final) : final,
    evidenceDirectoryActive,
  );
  if (raw.length !== seal.shard_size || sha256Hex(raw) !== seal.shard_sha256) {
    throw new Error("recovery seal shard size or digest mismatch");
  }
  if (
    seal.damage_offset > raw.length ||
    (seal.damage_offset > 0 && raw[seal.damage_offset - 1] !== 0x0a)
  ) {
    throw new Error("recovery seal damage_offset is not an LF-terminated prefix boundary");
  }
  const prefixBytes = raw.subarray(0, seal.damage_offset);
  const suffix = raw.subarray(seal.damage_offset);
  if (suffix.length === 0)
    throw new Error("recovery seal does not identify damaged trailing bytes");
  let tailKind: "nul" | "partial" | "missing_newline" = "partial";
  let tailContent = suffix;
  while (tailContent.length > 0 && tailContent[tailContent.length - 1] === 0) {
    tailContent = tailContent.subarray(0, tailContent.length - 1);
  }
  if (tailContent.length > 1 << 20) {
    throw new Error("recovery torn tail exceeds 1048576-byte recorder entry limit");
  }
  if (tailContent.length === 0) {
    tailKind = "nul";
  } else {
    if (tailContent.includes(0) || tailContent.includes(0x0a))
      throw new Error("recovery seal suffix is not a supported torn tail");
    // Replacement decoding is only a JSON syntax probe, matching Go's tail
    // classification. Complete values still pass fatal UTF-8 decoding below;
    // incomplete byte fragments can remain torn without becoming evidence.
    const suffixText = new TextDecoder("utf-8").decode(tailContent);
    let validJSON = true;
    try {
      JSON.parse(suffixText);
    } catch {
      validJSON = false;
    }
    if (!validJSON) {
      tailKind = "partial";
    } else {
      // A complete JSON value must be one known recorder entry, including
      // checkpoints. Validate its schema, outer chain and any embedded receipt
      // signature before the seal can attach.
      const candidate = parseEntryLinesText(suffixText);
      if (candidate.length !== 1) {
        throw new Error("missing-newline tail is not one recorder entry");
      }
      tailKind = "missing_newline";
    }
  }

  const prefixText = decodeUTF8(prefixBytes, "recovery seal complete prefix");
  const lines: ParsedRecorderLine[] = [];
  for (const file of files.slice(0, -1)) {
    lines.push(
      ...readEntryLines(
        evidenceDirectoryActive ? path.basename(file) : file,
        evidenceDirectoryActive,
      ),
    );
  }
  const prefixLines = parseEntryLinesText(prefixText);
  for (const line of lines.concat(prefixLines)) {
    if (line.entry.session_id !== seal.predecessor_session)
      throw new Error("recovery prefix session mismatch");
  }
  lines.push(...prefixLines);
  const sequenceErr = verifyRecoveryOuterSequence(lines);
  if (sequenceErr !== undefined) throw new Error(`recovery prefix sequence: ${sequenceErr}`);
  const fullLines = [...lines];
  if (tailKind === "missing_newline") {
    const candidate = parseEntryLinesText(decodeUTF8(tailContent, "recovery seal final record"))[0];
    if (candidate === undefined || candidate.entry.session_id !== seal.predecessor_session) {
      throw new Error("recovery final record session mismatch");
    }
    fullLines.push(candidate);
    const fullSequenceErr = verifyRecoveryOuterSequence(fullLines);
    if (fullSequenceErr !== undefined)
      throw new Error(`missing-newline final record sequence: ${fullSequenceErr}`);
  }
  const outerErr = verifyRecorderChain(lines);
  if (outerErr !== undefined) throw new Error(`recovery prefix recorder chain: ${outerErr}`);
  if (fullLines.length !== lines.length) {
    const candidateOuterErr = verifyRecorderChain(fullLines);
    if (candidateOuterErr !== undefined)
      throw new Error(`missing-newline final record is invalid: ${candidateOuterErr}`);
  }
  const lastLine = lines.at(-1);
  let outerSeq = 0;
  let outerHash = "genesis";
  if (lastLine !== undefined) {
    const rawEntry = parseJSONStrict(lastLine.line) as Record<string, unknown>;
    const seq = rawEntry["seq"];
    if (
      !(seq instanceof RawNumber) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(seq.literal) ||
      BigInt(seq.literal) > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      throw new Error("recovery outer sequence exceeds the cross-language safe integer range");
    }
    outerSeq = Number(seq.literal);
    if (typeof rawEntry["hash"] !== "string") throw new Error("recovery outer hash is missing");
    outerHash = rawEntry["hash"];
  }
  if (seal.last_good_seq !== outerSeq || seal.last_good_hash !== outerHash) {
    throw new Error("recovery seal outer prefix head mismatch");
  }
  const typed = extractTypedFromEntries(lines.map((line) => line.entry));
  const lastReceipt = typed.action.at(-1);
  const tailSeq = lastReceipt?.action_record?.chain_seq ?? 0;
  const tailHash = lastReceipt === undefined ? "genesis" : receiptHash(lastReceipt);
  const tailKey = lastReceipt?.signer_key ?? seal.successor_signer_key;
  if (
    tailSeq !== seal.predecessor_tail_seq ||
    tailHash !== seal.predecessor_tail_hash ||
    tailKey !== seal.predecessor_signer_key
  ) {
    throw new Error("recovery seal predecessor receipt tail mismatch");
  }
  if (typed.action.length > 0) {
    const verified = await verifyChain(typed.action, keys, { allowUnpinned: true });
    if (!chainAcceptable(verified))
      throw new Error(`recovery predecessor action chain: ${verified.error ?? "invalid"}`);
  }
  if (typed.evidence.length > 0) {
    const verified = await verifyChain(typed.evidence, evidenceChainKey(keys, typed.evidence), {
      allowUnpinned: true,
    });
    if (!verified.valid)
      throw new Error(`recovery predecessor evidence chain: ${verified.error ?? "invalid"}`);
  }
  let extracted = typed;
  if (tailKind === "missing_newline") {
    const fullTyped = extractTypedFromEntries(fullLines.map((line) => line.entry));
    if (fullTyped.action.length > 0) {
      const verified = await verifyChain(fullTyped.action, keys, { allowUnpinned: true });
      if (!chainAcceptable(verified))
        throw new Error(
          `missing-newline final action receipt signature is invalid: ${verified.error ?? "invalid"}`,
        );
    }
    if (fullTyped.evidence.length > 0) {
      const verified = await verifyChain(
        fullTyped.evidence,
        evidenceChainKey(keys, fullTyped.evidence),
        { allowUnpinned: true },
      );
      if (!verified.valid)
        throw new Error(
          `missing-newline final evidence receipt signature is invalid: ${verified.error ?? "invalid"}`,
        );
    }
    extracted = fullTyped;
  }
  for (const receipt of extracted.action) {
    const action = receipt.action_record?.session_control as Record<string, unknown> | undefined;
    const open =
      action?.["kind"] === "session_open"
        ? (action["open"] as Record<string, unknown> | undefined)
        : undefined;
    if (open !== undefined && open["recorder_session"] !== seal.predecessor_session) {
      throw new Error("recovery predecessor session_open binding mismatch");
    }
  }
  const successor = data.get(seal.successor_session);
  if (successor === undefined || !successor.chain.valid || successor.receipts.length === 0) {
    throw new Error("recovery successor chain did not verify");
  }
  const first = successor.receipts[0] as Receipt;
  const control = first.action_record?.session_control as Record<string, unknown> | undefined;
  if (
    first.signer_key !== seal.successor_signer_key ||
    receiptHash(first) !== seal.successor_open_hash ||
    control?.["kind"] !== "session_open" ||
    first.action_record?.chain_seq !== 0
  ) {
    throw new Error("recovery seal successor opening receipt mismatch");
  }
  const open = control["open"] as Record<string, unknown> | undefined;
  if (open?.["recorder_session"] !== seal.successor_session) {
    throw new Error("recovery successor session_open recorder session mismatch");
  }
  // Identity trust is applied by verifyBase after this self-consistency and
  // placement check. Empty pins retain the existing per-chain TOFU policy.
  return extracted;
}

// Recovery seals bind a complete prefix, so every recorder entry in that
// prefix must occupy its original zero-based position. Hash links alone do
// not detect a consistently resequenced or omitted entry.
export function verifyRecoveryOuterSequence(
  lines: readonly ParsedRecorderLine[],
): string | undefined {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    let raw: unknown;
    try {
      raw = parseJSONStrict(line.line);
    } catch (err) {
      return `entry ${i}: ${(err as Error).message}`;
    }
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      return `entry ${i}: recorder entry is not an object`;
    }
    const seq = (raw as Record<string, unknown>)["seq"];
    let value: bigint;
    if (seq instanceof RawNumber && /^(?:0|[1-9][0-9]*)$/u.test(seq.literal)) {
      value = BigInt(seq.literal);
    } else {
      return `entry ${i}: recorder sequence is not an unsigned integer`;
    }
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      return `entry ${i}: recorder sequence exceeds the cross-language safe integer range`;
    }
    if (value !== BigInt(i))
      return `entry ${i}: expected zero-based contiguous sequence ${i}, got ${value}`;
  }
  return undefined;
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
    lines = readSessionLines(ix, s).lines;
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

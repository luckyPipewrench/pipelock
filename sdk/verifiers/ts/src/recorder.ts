import { readFileSync, readdirSync, statSync } from "node:fs";
import * as path from "node:path";
import type { Receipt, RecorderEntry } from "./types.js";
import { validateV1Receipt } from "./strict.js";
import { InvalidError, RuntimeError, decodeUTF8, parseJSON, rejectDuplicateKeys } from "./util.js";

const actionReceiptType = "action_receipt";
const evidenceReceiptType = "evidence_receipt";

// AF-37 receipt-chain mode: the known non-receipt operational entry types that
// extraction legitimately skips. Any entry whose type is outside the union of
// the receipt types and this set is REJECTED (fail-closed) rather than silently
// skipped, so a file mixing a valid chain with an unknown record type cannot be
// reported as a valid receipt subsequence.
const skippableEntryTypes = new Set([
  "checkpoint",
  "transcript_root",
  "decision",
  "capture",
  "capture_drop",
]);

export function readEntries(file: string): RecorderEntry[] {
  const text = decodeUTF8(readFileSync(path.normalize(file)), "evidence jsonl");
  const entries: RecorderEntry[] = [];
  const lines = text.split(/\r?\n/u);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim() ?? "";
    if (line === "") continue;
    const entry = parseJSON<RecorderEntry>(line, `line ${i + 1}`);
    rejectDuplicateKeys(line);
    if (entry.v !== 1 && entry.v !== 2) {
      throw new RuntimeError(
        `line ${i + 1}: unsupported entry version ${String(entry.v)} (accepted: 1, 2)`,
      );
    }
    entries.push(entry);
  }
  return entries;
}

export function extractReceipts(file: string): Receipt[] {
  const receipts: Receipt[] = [];
  for (const entry of readEntries(file)) {
    const isReceipt = entry.type === actionReceiptType || entry.type === evidenceReceiptType;
    if (!isReceipt) {
      if (entry.type !== undefined && skippableEntryTypes.has(entry.type)) continue;
      throw new InvalidError(
        `unexpected recorder entry type "${String(entry.type)}" at seq ${String(entry.seq)}`,
      );
    }
    if (typeof entry.detail !== "object" || entry.detail === null) {
      throw new RuntimeError(`entry seq ${String(entry.seq)}: receipt detail is not an object`);
    }
    // EV2-FU-1: an extracted v1 action receipt must satisfy the strict
    // unknown-field contract (evidence_receipt v2 has its own schema).
    if (entry.type === actionReceiptType) {
      try {
        validateV1Receipt(entry.detail);
      } catch (err) {
        throw new InvalidError(`entry seq ${String(entry.seq)}: ${(err as Error).message}`);
      }
    }
    receipts.push(entry.detail as Receipt);
  }
  return receipts;
}

function seqStart(file: string): number {
  const base = path.basename(file, ".jsonl");
  const dash = base.lastIndexOf("-");
  const suffix = dash < 0 ? "" : base.slice(dash + 1);
  const parsed = Number.parseInt(suffix, 10);
  if (!/^\d+$/u.test(suffix) || !Number.isFinite(parsed)) {
    throw new RuntimeError(`evidence file has non-numeric sequence suffix: ${file}`);
  }
  return parsed;
}

export function extractReceiptsFromSessionDir(dir: string, sessionId: string): Receipt[] {
  const clean = path.normalize(dir);
  const prefix = `evidence-${sessionId}-`;
  const files = readdirSync(clean)
    .filter((name) => {
      const full = path.join(clean, name);
      return !statSync(full).isDirectory() && name.startsWith(prefix) && name.endsWith(".jsonl");
    })
    .map((name) => path.join(clean, name))
    .sort((a, b) => seqStart(a) - seqStart(b));
  return files.flatMap((file) => extractReceipts(file));
}

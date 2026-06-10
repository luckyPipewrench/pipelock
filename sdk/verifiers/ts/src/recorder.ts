import { readFileSync, readdirSync, statSync } from "node:fs";
import * as path from "node:path";
import type { Receipt, RecorderEntry } from "./types.js";
import { RuntimeError, parseJSON, rejectDuplicateKeys } from "./util.js";

const actionReceiptType = "action_receipt";
const evidenceReceiptType = "evidence_receipt";

export function readEntries(file: string): RecorderEntry[] {
  const text = readFileSync(path.normalize(file), "utf8");
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
  return readEntries(file)
    .filter((entry) => entry.type === actionReceiptType || entry.type === evidenceReceiptType)
    .map((entry) => {
      if (typeof entry.detail !== "object" || entry.detail === null) {
        throw new RuntimeError(`entry seq ${String(entry.seq)}: receipt detail is not an object`);
      }
      return entry.detail as Receipt;
    });
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

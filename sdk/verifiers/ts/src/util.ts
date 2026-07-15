import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import * as path from "node:path";

export class UsageError extends Error {
  readonly code = 64;
}

export class RuntimeError extends Error {
  readonly code = 2;
}

export class InvalidError extends Error {
  readonly code = 1;
}

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function parseJSONFile<T>(file: string): T {
  try {
    return JSON.parse(readFileSync(path.normalize(file), "utf8")) as T;
  } catch (err) {
    if (err instanceof SyntaxError) throw new RuntimeError(`malformed JSON: ${err.message}`);
    throw new RuntimeError(`read ${file}: ${(err as Error).message}`);
  }
}

export function parseJSON<T>(text: string, label: string): T {
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new RuntimeError(`${label}: ${(err as Error).message}`);
  }
}

// rejectDuplicateKeys throws InvalidError if text contains a duplicate object
// key at any nesting depth. JSON.parse silently keeps the last value for a
// duplicate key, so {"verdict":"allow","verdict":"block"} parses as "block"
// with no error — a parser-differential smuggling vector where a display or log
// layer reading the first occurrence sees a different value than the one the
// signature was checked against. This scanner only needs to locate object-key
// string positions, not validate the full structure; malformed JSON is still
// reported by the caller's normal JSON.parse path.
// maxDuplicateKeyScanDepth bounds nesting so the scanner agrees with the other
// reference verifiers on rejecting absurdly deep input. Receipts nest ~4
// levels, so this never affects honest input.
const maxDuplicateKeyScanDepth = 128;
const maxExactJSONInteger = Number.MAX_SAFE_INTEGER;

export function rejectDuplicateKeys(text: string): void {
  interface Frame {
    isObject: boolean;
    keys: Set<string>;
    expectKey: boolean;
  }
  const stack: Frame[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let str = "";
      i++; // opening quote
      while (i < n) {
        const ch = text[i];
        if (ch === "\\") {
          const esc = text[i + 1];
          if (esc === "u") {
            const code = Number.parseInt(text.slice(i + 2, i + 6), 16);
            i += 6;
            // Merge a UTF-16 surrogate pair into one code point so this scanner
            // decodes keys identically to Go/Rust/Python (which all merge). A
            // lone high surrogate is kept as-is.
            if (code >= 0xd800 && code <= 0xdbff && text[i] === "\\" && text[i + 1] === "u") {
              const low = Number.parseInt(text.slice(i + 2, i + 6), 16);
              if (low >= 0xdc00 && low <= 0xdfff) {
                str += String.fromCodePoint((code - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000);
                i += 6;
              } else {
                str += String.fromCharCode(code);
              }
            } else {
              str += String.fromCharCode(code);
            }
          } else {
            const simple: Record<string, string> = {
              '"': '"',
              "\\": "\\",
              "/": "/",
              b: "\b",
              f: "\f",
              n: "\n",
              r: "\r",
              t: "\t",
            };
            str += simple[esc] ?? esc;
            i += 2;
          }
        } else if (ch === '"') {
          i++; // closing quote
          break;
        } else {
          str += ch;
          i++;
        }
      }
      const top = stack[stack.length - 1];
      if (top !== undefined && top.isObject && top.expectKey) {
        if (top.keys.has(str)) throw new InvalidError(`duplicate object key: ${str}`);
        top.keys.add(str);
      }
      continue;
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      const match = text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u);
      if (match !== null) {
        const numberText = match[0];
        const value = Number(numberText);
        // A magnitude JS cannot represent (1e999) parses to Infinity, which is
        // not finite. Gating the check on isFinite would SKIP it and accept a
        // number Go and Rust reject as out of range, reintroducing the
        // cross-language differential this guard exists to close.
        if (!Number.isFinite(value) || Math.abs(value) > maxExactJSONInteger) {
          throw new InvalidError(`JSON number ${numberText} exceeds cross-language exact range`);
        }
        i += numberText.length;
        continue;
      }
    }
    if (c === "{" || c === "[") {
      if (stack.length >= maxDuplicateKeyScanDepth) {
        throw new InvalidError(`JSON nesting exceeds maximum depth ${maxDuplicateKeyScanDepth}`);
      }
    }
    if (c === "{") {
      stack.push({ isObject: true, keys: new Set(), expectKey: true });
    } else if (c === "[") {
      stack.push({ isObject: false, keys: new Set(), expectKey: false });
    } else if (c === "}" || c === "]") {
      stack.pop();
    } else if (c === ":") {
      const top = stack[stack.length - 1];
      if (top !== undefined && top.isObject) top.expectKey = false;
    } else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top !== undefined && top.isObject) top.expectKey = true;
    }
    i++;
  }
}

export function decodeUTF8(data: Buffer, label: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    throw new InvalidError(`${label}: invalid UTF-8`);
  }
}

export function decodeHex(input: string, byteLength: number, label: string): Uint8Array {
  const trimmed = input.trim().toLowerCase();
  if (!/^[0-9a-f]*$/u.test(trimmed) || trimmed.length !== byteLength * 2) {
    throw new Error(`invalid ${label} length: got ${trimmed.length / 2}, want ${byteLength}`);
  }
  return Uint8Array.from(Buffer.from(trimmed, "hex"));
}

export function resolveSignerKey(input: string): string {
  const trimmed = input.trim();
  if (trimmed === "") return "";

  let value = trimmed;
  if (existsSync(trimmed)) {
    value = readFileSync(trimmed, "utf8").trim();
  }

  if (value.startsWith("pipelock-ed25519-public-v1\n")) {
    const body = value.split(/\n/u)[1]?.trim() ?? "";
    value = Buffer.from(body, "base64").toString("hex");
  }

  decodeHex(value, 32, "public key");
  return value.toLowerCase();
}

export function resolvePacketPath(target: string): { packetPath: string; baseDir: string } {
  const clean = path.normalize(target);
  let info;
  try {
    info = statSync(clean);
  } catch (err) {
    throw new RuntimeError(`stat ${target}: ${(err as Error).message}`);
  }
  if (info.isDirectory()) return { packetPath: path.join(clean, "packet.json"), baseDir: clean };
  return { packetPath: clean, baseDir: path.dirname(clean) };
}

export function resolveArtifactPath(baseDir: string, rel: string): string {
  if (rel === "") throw new Error("artifact path is empty");
  if (path.isAbsolute(rel)) throw new Error(`artifact path must be relative: ${rel}`);
  if (rel.includes("\\") || rel.includes(":")) {
    throw new Error(`artifact path contains forbidden character: ${rel}`);
  }
  const clean = path.normalize(rel);
  if (clean === "." || clean === ".." || clean.startsWith(`..${path.sep}`)) {
    throw new Error(`artifact path escapes packet directory: ${rel}`);
  }
  const absBase = path.resolve(baseDir);
  const absFull = path.resolve(baseDir, clean);
  const relToBase = path.relative(absBase, absFull);
  if (relToBase === ".." || relToBase.startsWith(`..${path.sep}`) || path.isAbsolute(relToBase)) {
    throw new Error(`artifact path escapes packet directory after resolution: ${rel}`);
  }
  if (existsSync(absFull)) {
    const resolved = realpathSync(absFull);
    const realRel = path.relative(absBase, resolved);
    if (realRel === ".." || realRel.startsWith(`..${path.sep}`) || path.isAbsolute(realRel)) {
      throw new Error(`artifact path escapes packet directory via symlink: ${rel}`);
    }
  }
  return absFull;
}

export function usage(message: string): never {
  throw new UsageError(message);
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

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
  realpathSync,
  statSync,
} from "node:fs";
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

export const maxVerifierInputBytes = 8 << 20;
export const maxRecorderLineBytes = 1 << 20;

// Node normalizes "symlink/.." before realpathSync sees it. Walk each path
// component so a parent traversal applies to the symlink's target, as it does
// when the operating system opens the path supplied by the operator.
export function resolveOperatorFilePath(file: string): string {
  const root = path.parse(file).root;
  // On Windows, "C:name" starts at C's working directory, which need not be
  // the process working directory. Resolve the volume before walking.
  let current = root ? path.resolve(root) : process.cwd();
  const components = file.slice(root.length).split(path.sep === "\\" ? /[\\/]/u : /\//u);
  for (const component of components) {
    if (component === "" || component === ".") {
      // "file/" and "file/." name the file as a directory, which the
      // operating system refuses to open (ENOTDIR). The root or working
      // directory the walk starts from is always a directory.
      if (!statSync(current).isDirectory()) {
        throw new RuntimeError(`path component is not a directory: ${current}`);
      }
      continue;
    }
    if (component === "..") {
      if (!statSync(current).isDirectory()) {
        throw new RuntimeError(`path component is not a directory: ${current}`);
      }
      current = path.dirname(current);
    } else {
      current = realpathSync(path.join(current, component));
    }
  }
  return current;
}

export function readVerifierBytes(
  file: string,
  directoryChild = false,
  maxBytes = maxVerifierInputBytes,
): Buffer {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > maxVerifierInputBytes) {
    throw new RuntimeError("invalid input byte limit");
  }
  // Directory children are opened relative to the pinned working directory.
  // Never resolve them by pathname: that would follow a replacement symlink.
  if (directoryChild && (path.basename(file) !== file || file === "." || file === "..")) {
    throw new RuntimeError("evidence filename must be a base name");
  }
  const clean = directoryChild ? file : resolveOperatorFilePath(file);
  const before = directoryChild ? lstatSync(clean, { bigint: true }) : undefined;
  if (before?.isSymbolicLink()) throw new RuntimeError("refuse symlink in evidence directory");
  const fd = openSync(
    clean,
    constants.O_RDONLY | constants.O_NONBLOCK | (directoryChild ? (constants.O_NOFOLLOW ?? 0) : 0),
  );
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new RuntimeError("input must be a regular file");
    if (before !== undefined) {
      const opened = fstatSync(fd, { bigint: true });
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.ino === 0n) {
        throw new RuntimeError("evidence file changed while opening");
      }
    }
    if (info.size > maxBytes) {
      throw new RuntimeError(`input exceeds ${maxBytes} bytes`);
    }
    const data = Buffer.allocUnsafe(maxBytes + 1);
    let length = 0;
    while (length <= maxBytes) {
      const n = readSync(fd, data, length, data.length - length, null);
      if (n === 0) break;
      length += n;
    }
    if (length > maxBytes) {
      throw new RuntimeError(`input exceeds ${maxBytes} bytes`);
    }
    return data.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}

export function forEachVerifierJSONLLine(
  file: string,
  directoryChild: boolean,
  visit: (line: string, lineNumber: number) => void,
  includeUnterminated = true,
): boolean {
  if (directoryChild && (path.basename(file) !== file || file === "." || file === "..")) {
    throw new RuntimeError("evidence filename must be a base name");
  }
  const clean = directoryChild ? file : resolveOperatorFilePath(file);
  const before = directoryChild ? lstatSync(clean, { bigint: true }) : undefined;
  if (before?.isSymbolicLink()) throw new RuntimeError("refuse symlink in evidence directory");
  const fd = openSync(
    clean,
    constants.O_RDONLY | constants.O_NONBLOCK | (directoryChild ? (constants.O_NOFOLLOW ?? 0) : 0),
  );
  try {
    const initial = fstatSync(fd, { bigint: true });
    if (!initial.isFile()) throw new RuntimeError("input must be a regular file");
    if (
      before !== undefined &&
      (initial.dev !== before.dev || initial.ino !== before.ino || initial.ino === 0n)
    ) {
      throw new RuntimeError("evidence file changed while opening");
    }
    const chunk = Buffer.allocUnsafe(64 << 10);
    let pending = Buffer.alloc(0);
    let lineNumber = 1;
    let torn = false;
    let failure: unknown;
    let remaining = initial.size;
    const emit = (raw: Buffer, terminated: boolean): void => {
      let payloadLength = raw.length;
      if (terminated && payloadLength > 0 && raw[payloadLength - 1] === 0x0d) payloadLength--;
      if (payloadLength > maxRecorderLineBytes) {
        throw new RuntimeError(
          `line ${lineNumber}: exceeds ${maxRecorderLineBytes}-byte recorder entry limit`,
        );
      }
      if (raw.length !== 0 && !(terminated && raw.length === 1 && raw[0] === 0x0d)) {
        visit(decodeUTF8(raw, "evidence jsonl"), lineNumber);
      }
      lineNumber++;
    };
    try {
      while (true) {
        if (remaining === 0n) break;
        const n = readSync(
          fd,
          chunk,
          0,
          Number(remaining < BigInt(chunk.length) ? remaining : BigInt(chunk.length)),
          null,
        );
        if (n === 0) break;
        remaining -= BigInt(n);
        let start = 0;
        for (let i = 0; i < n; i++) {
          if (chunk[i] !== 0x0a) continue;
          const part = chunk.subarray(start, i);
          const raw = pending.length === 0 ? part : Buffer.concat([pending, part]);
          emit(raw, true);
          pending = Buffer.alloc(0);
          start = i + 1;
        }
        if (start < n) {
          const tail = chunk.subarray(start, n);
          pending = pending.length === 0 ? Buffer.from(tail) : Buffer.concat([pending, tail]);
          if (pending.length > maxRecorderLineBytes + 1) {
            throw new RuntimeError(
              `line ${lineNumber}: exceeds ${maxRecorderLineBytes}-byte recorder entry limit`,
            );
          }
        }
        if (start === n) pending = Buffer.alloc(0);
      }
      if (pending.length > 0) {
        if (pending.length > maxRecorderLineBytes) {
          throw new RuntimeError(
            `line ${lineNumber}: exceeds ${maxRecorderLineBytes}-byte recorder entry limit`,
          );
        }
        if (includeUnterminated) emit(pending, false);
        else torn = true;
      }
    } catch (error) {
      // Still inspect the descriptor and pathname after parser/consumer errors.
      failure = error;
    }
    const final = fstatSync(fd, { bigint: true });
    // ctime catches a same-inode overwrite whose mtime is restored on Unix.
    // On Windows and filesystems with coarse/change-time semantics, an
    // unchanged size and reported timestamp cannot prove an atomic snapshot.
    if (
      final.dev !== initial.dev ||
      final.ino !== initial.ino ||
      final.size !== initial.size ||
      final.mtimeNs !== initial.mtimeNs ||
      final.ctimeNs !== initial.ctimeNs
    ) {
      throw new RuntimeError("input changed while reading");
    }
    const after = directoryChild
      ? lstatSync(clean, { bigint: true })
      : statSync(clean, { bigint: true });
    if (
      after.isSymbolicLink() ||
      after.dev !== initial.dev ||
      after.ino !== initial.ino ||
      after.size !== initial.size ||
      after.mtimeNs !== initial.mtimeNs ||
      after.ctimeNs !== initial.ctimeNs ||
      after.ino === 0n
    ) {
      throw new RuntimeError("evidence file changed while reading");
    }
    if (failure !== undefined) throw failure;
    return torn;
  } finally {
    closeSync(fd);
  }
}

export function parseJSONFile<T>(file: string): T {
  try {
    return JSON.parse(readVerifierBytes(file).toString("utf8")) as T;
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
    // ignoreBOM keeps a leading U+FEFF in the output, so it reaches the JSON
    // parser and is rejected like Go's encoding/json does, instead of being
    // stripped silently.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
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

  // Both supported literal forms are unambiguously key material. Parse them
  // before consulting the filesystem so an untrusted working directory
  // cannot replace a pinned literal with a same-named file.
  if (/^[0-9a-f]{64}$/iu.test(trimmed) || /^pipelock-ed25519-public-v1\r?\n/u.test(trimmed)) {
    return parseSignerKeyValue(trimmed);
  }

  let value = trimmed;
  if (existsSync(trimmed)) {
    value = readVerifierBytes(trimmed).toString("utf8").trim();
  }

  return parseSignerKeyValue(value);
}

function parseSignerKeyValue(value: string): string {
  if (/^pipelock-ed25519-public-v1\r?\n/u.test(value)) {
    const body = value.split(/\r?\n/u)[1]?.trim() ?? "";
    if (!/^[A-Za-z0-9+/]{43}=$/u.test(body)) {
      throw new Error("invalid public key: malformed base64");
    }
    value = Buffer.from(body, "base64").toString("hex");
  }

  decodeHex(value, 32, "public key");
  return value.toLowerCase();
}

export function resolvePacketPath(target: string): { packetPath: string; baseDir: string } {
  let clean: string;
  let info;
  try {
    clean = resolveOperatorFilePath(target);
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

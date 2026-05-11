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

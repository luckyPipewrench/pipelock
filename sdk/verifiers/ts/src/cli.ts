#!/usr/bin/env node
import { statSync } from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";
import { verifyAuditPacket } from "./audit-packet.js";
import { verifyChain } from "./chain.js";
import { emitAuditPacket, emitChain, emitReceipt } from "./output.js";
import { extractReceipts, extractReceiptsFromSessionDir } from "./recorder.js";
import { runReceipt } from "./receipt.js";
import { runAARPCommand } from "./aarp/cli.js";
import { RuntimeError, UsageError, errorMessage, resolveSignerKey } from "./util.js";

export interface ChainCommandReport {
  path: string;
  valid: boolean;
  receipt_count: number;
  final_seq: number;
  root_hash?: string;
  error?: string;
  broken_at_seq?: number;
}

function usage(command?: string): string {
  if (command === "audit-packet") {
    return "Usage: pipelock-verifier-ts audit-packet PATH [--json] [--key HEX_OR_FILE] [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]";
  }
  if (command === "chain") {
    return "Usage: pipelock-verifier-ts chain PATH [--json] [--key HEX_OR_FILE] [--dir] [--session-id ID]";
  }
  if (command === "receipt") {
    return "Usage: pipelock-verifier-ts receipt PATH [--json] [--key HEX_OR_FILE]";
  }
  if (command === "aarp") {
    return "Usage: pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--chain] [--json]";
  }
  return "Usage: pipelock-verifier-ts {audit-packet|chain|receipt|aarp} PATH [flags]";
}

function requireOneArg(positionals: string[], command: string): string {
  if (positionals.length !== 1)
    throw new UsageError(`${usage(command)}\naccepts 1 arg, received ${positionals.length}`);
  return positionals[0] as string;
}

async function runAuditPacketCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      key: { type: "string", default: "" },
      offline: { type: "boolean", default: false },
      "allow-self-consistent-only": { type: "boolean", default: false },
      "no-trust-required": { type: "boolean", default: false },
      "expect-sha256": { type: "string", default: "" },
    },
  });
  const target = requireOneArg(parsed.positionals, "audit-packet");
  const report = await verifyAuditPacket(target, {
    signerKey: parsed.values.key ?? "",
    offline: parsed.values.offline === true,
    allowSelfConsistentOnly: parsed.values["allow-self-consistent-only"] === true,
    noTrustRequired: parsed.values["no-trust-required"] === true,
    expectSha256: parsed.values["expect-sha256"] ?? "",
  });
  emitAuditPacket(report, parsed.values.json === true);
  return report.valid ? 0 : 1;
}

async function runChainCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      key: { type: "string", default: "" },
      dir: { type: "boolean", default: false },
      "session-id": { type: "string", default: "proxy" },
    },
  });
  const target = requireOneArg(parsed.positionals, "chain");
  const keyHex = resolveSignerKey(parsed.values.key ?? "");
  const asDir = parsed.values.dir === true;
  const sessionID = parsed.values["session-id"] ?? "proxy";
  let receipts;
  let label: string;
  try {
    if (asDir) {
      const clean = path.normalize(target);
      receipts = extractReceiptsFromSessionDir(clean, sessionID);
      label = `${clean} (session ${sessionID})`;
    } else {
      const clean = path.normalize(target);
      if (statSync(clean).isDirectory()) {
        throw new RuntimeError(
          `${target} is a directory; pass --dir to verify a session directory`,
        );
      }
      receipts = extractReceipts(clean);
      label = clean;
    }
  } catch (err) {
    throw new RuntimeError(`extract receipts: ${errorMessage(err)}`);
  }
  if (receipts.length === 0) {
    const report: ChainCommandReport = {
      path: label,
      valid: false,
      receipt_count: 0,
      final_seq: 0,
      error: "no receipts in chain",
    };
    emitChain(report, parsed.values.json === true);
    return 1;
  }
  const result = await verifyChain(receipts, keyHex);
  const report: ChainCommandReport = {
    path: label,
    valid: result.valid,
    receipt_count: result.receipt_count,
    final_seq: result.final_seq,
    root_hash: result.root_hash || undefined,
    error: result.error,
    broken_at_seq: result.broken_at_seq,
  };
  emitChain(report, parsed.values.json === true);
  return result.valid ? 0 : 1;
}

async function runReceiptCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      key: { type: "string", default: "" },
    },
  });
  const target = requireOneArg(parsed.positionals, "receipt");
  const report = await runReceipt(target, parsed.values.key ?? "");
  emitReceipt(report, parsed.values.json === true);
  return report.valid ? 0 : 1;
}

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  if (!command) throw new UsageError(usage());
  switch (command) {
    case "audit-packet":
      return runAuditPacketCommand(args);
    case "chain":
      return runChainCommand(args);
    case "receipt":
      return runReceiptCommand(args);
    case "aarp":
      return runAARPCommand(args);
    default:
      throw new UsageError(`unknown command ${command}\n${usage()}`);
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = errorMessage(err);
    if (err instanceof UsageError || message.startsWith("Unknown option")) {
      process.stderr.write(`${message}\n`);
      process.exitCode = 64;
      return;
    }
    if (err instanceof RuntimeError) {
      process.stderr.write(`${message}\n`);
      process.exitCode = 2;
      return;
    }
    // Coded errors (e.g. the aarp subcommand's usage/IO/trust errors) carry an
    // explicit numeric exit code; honor it.
    if (
      typeof err === "object" &&
      err !== null &&
      typeof (err as { code?: unknown }).code === "number"
    ) {
      process.stderr.write(`${message}\n`);
      process.exitCode = (err as { code: number }).code;
      return;
    }
    process.stderr.write(`${message}\n`);
    process.exitCode = 2;
  });

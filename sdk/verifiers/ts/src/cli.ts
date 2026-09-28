#!/usr/bin/env node
// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { statSync } from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";
import { verifyAuditPacket } from "./audit-packet.js";
import { evidenceChainKey, verifyChain } from "./chain.js";
import { analyzeLifecycle } from "./lifecycle.js";
import {
  baseHealthy,
  baseUnlinked,
  chainScopedTrust,
  checkFileEntrySessions,
  EvidenceRefusedError,
  readSessionEvidence,
  readSessionReceipts,
  resolveBaseSessions,
  runSessionBase,
  verifyBase,
  type BaseFinding,
  type ChainLink,
} from "./chain-set.js";
import { emitAuditPacket, emitChain, emitChainSet, emitReceipt, reportFailure } from "./output.js";
import {
  extractTypedFromEntries,
  readEntryLines,
  selectReceiptChain,
  type ExtractedReceipts,
} from "./recorder.js";
import { FindingOuterChainBroken, verifyRecorderChain } from "./recorder-chain.js";
import { runReceipt } from "./receipt.js";
import {
  loadRotationEndorsementFile,
  verifyChainWithEndorsements,
  type RotationEndorsement,
} from "./rotation.js";
import type { Receipt } from "./types.js";
import { runAARPCommand } from "./aarp/cli.js";
import { comparableProvenance, runProvenanceFixture } from "./provenance-proof.js";
import {
  RuntimeError,
  UsageError,
  errorMessage,
  resolveOperatorFilePath,
  resolveSignerKey,
} from "./util.js";

export interface ChainCommandReport {
  path: string;
  valid: boolean;
  unpinned?: boolean;
  receipt_count: number;
  final_seq: number;
  root_hash?: string;
  error?: string;
  broken_at_seq?: number;
  // Receipts of each kind the session or file holds. Both chains present
  // must verify for the report to be valid.
  action_receipts?: number;
  evidence_receipts?: number;
}

function usage(command?: string): string {
  if (command === "audit-packet") {
    return "Usage: pipelock-verifier-ts audit-packet PATH [--json] [--key HEX_OR_FILE]... [--offline] [--allow-self-consistent-only] [--no-trust-required] [--expect-sha256 HEX]";
  }
  if (command === "chain") {
    return "Usage: pipelock-verifier-ts chain PATH [--json] [--key HEX_OR_FILE]... [--rotation-endorsement FILE]... [--allow-unpinned] [--dir] [--session-id ID]";
  }
  if (command === "receipt") {
    return "Usage: pipelock-verifier-ts receipt PATH [--json] [--key HEX_OR_FILE] [--allow-unpinned]";
  }
  if (command === "aarp") {
    return "Usage: pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--chain] [--json]";
  }
  if (command === "provenance") {
    return "Usage: pipelock-verifier-ts provenance PATH [--allow-incomplete]";
  }
  return "Usage: pipelock-verifier-ts {audit-packet|chain|receipt|aarp|provenance} PATH [flags]";
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
      key: { type: "string", multiple: true, default: [] },
      offline: { type: "boolean", default: false },
      "allow-self-consistent-only": { type: "boolean", default: false },
      "no-trust-required": { type: "boolean", default: false },
      "expect-sha256": { type: "string", default: "" },
    },
  });
  const target = requireOneArg(parsed.positionals, "audit-packet");
  const report = await verifyAuditPacket(target, {
    signerKey: "",
    signerKeys: parsed.values.key ?? [],
    offline: parsed.values.offline === true,
    allowSelfConsistentOnly: parsed.values["allow-self-consistent-only"] === true,
    noTrustRequired: parsed.values["no-trust-required"] === true,
    expectSha256: parsed.values["expect-sha256"] ?? "",
  });
  emitAuditPacket(report, parsed.values.json === true);
  if (!report.valid) {
    reportFailure(`audit packet ${report.path}: ${report.errors?.[0] ?? "not valid"}`);
  }
  return report.valid ? 0 : 1;
}

// resolveSignerKeys resolves every --key value and joins the trusted set.
function resolveSignerKeys(values: string[]): string {
  return values
    .filter((value) => value.trim() !== "")
    .map((value) => resolveSignerKey(value))
    .join(",");
}

// ChainSetReport is the directory-mode report when the evidence directory
// holds per-run receipt chains: one chain report per run, then the restart
// continuity of the base. Unlinked runs are always listed, because a passing
// result is not proof that no run's evidence is missing.
export interface ChainSetReport {
  path: string;
  base: string;
  valid: boolean;
  chains: (ChainCommandReport & { session: string })[];
  continuity: {
    healthy: boolean;
    // Every chain of the base, which a named run's report lists alongside
    // the one chain it verifies.
    chain_count: number;
    linked: {
      session: string;
      predecessor_session: string;
      predecessor_tail_seq: number;
      trust: string;
    }[];
    unlinked: string[];
    findings: BaseFinding[];
  };
}

async function chainReportFor(
  label: string,
  receipts: Receipt[],
  keyHex: string,
  allowUnpinned: boolean,
  endorsements: RotationEndorsement[],
  sessionID: string,
): Promise<ChainCommandReport> {
  if (receipts.length === 0) {
    return {
      path: label,
      valid: false,
      receipt_count: 0,
      final_seq: 0,
      error: "no receipts in chain",
    };
  }
  const result =
    endorsements.length > 0
      ? await verifyChainWithEndorsements(receipts, keyHex, {
          sessionID,
          endorsements,
        })
      : await verifyChain(receipts, keyHex, { allowUnpinned });
  const lifecycle = analyzeLifecycle(receipts, result);
  const lifecycleBroken = lifecycle.status === "BROKEN";
  return {
    path: label,
    valid: result.valid && !lifecycleBroken,
    unpinned:
      keyHex === "" &&
      (result.error?.includes("UNPINNED") === true || (result.valid && !lifecycleBroken))
        ? true
        : undefined,
    receipt_count: result.receipt_count,
    final_seq: result.final_seq,
    root_hash: result.root_hash || undefined,
    // Preserve the verifier's concrete cryptographic, hash, trust, or
    // sequence failure. Lifecycle is a supplemental gate only when the chain
    // itself verified successfully.
    error: lifecycleBroken && result.valid ? `lifecycle: ${lifecycle.reason}` : result.error,
    broken_at_seq: result.broken_at_seq,
  };
}

// typedChainReport verifies every receipt chain one session or file holds. A
// current run writes an ActionReceipt v1 chain and an EvidenceReceipt v2 chain
// into the same files, each signed on its own, so a forged receipt in one
// leaves the other intact: verifying only the chain selectReceiptChain picks
// reported a session valid while its v2 chain was forged. Both chains must
// verify. The action report stays the primary one, so a session whose chains
// both pass prints exactly what it did before, and a failure names the chain
// it came from.
async function typedChainReport(
  label: string,
  typed: ExtractedReceipts,
  keyHex: string,
  allowUnpinned: boolean,
  endorsements: RotationEndorsement[],
  sessionID: string,
): Promise<ChainCommandReport> {
  return {
    ...(await bothChainsReport(label, typed, keyHex, allowUnpinned, endorsements, sessionID)),
    action_receipts: typed.action.length,
    evidence_receipts: typed.evidence.length,
  };
}

async function bothChainsReport(
  label: string,
  typed: ExtractedReceipts,
  keyHex: string,
  allowUnpinned: boolean,
  endorsements: RotationEndorsement[],
  sessionID: string,
): Promise<ChainCommandReport> {
  const primaryReceipts = selectReceiptChain(typed);
  const primary = await chainReportFor(
    label,
    primaryReceipts,
    typed.action.length === 0 ? evidenceChainKey(keyHex, primaryReceipts) : keyHex,
    allowUnpinned,
    typed.action.length === 0 ? [] : endorsements,
    sessionID,
  );
  if (typed.action.length === 0 || typed.evidence.length === 0) return primary;
  const evidence = await chainReportFor(
    label,
    typed.evidence,
    evidenceChainKey(keyHex, typed.evidence),
    allowUnpinned,
    [],
    sessionID,
  );
  if (primary.valid && evidence.valid) return primary;
  // Without a key and without --allow-unpinned both chains fail only for being
  // unpinned; the action report already says so.
  if (primary.unpinned === true && evidence.unpinned === true) return primary;
  const reasons: string[] = [];
  if (!primary.valid) reasons.push(`action receipt chain: ${primary.error ?? ""}`);
  if (!evidence.valid) reasons.push(`evidence receipt chain: ${evidence.error ?? ""}`);
  return {
    ...primary,
    valid: false,
    unpinned: undefined,
    error: reasons.join("; "),
    broken_at_seq: primary.valid ? evidence.broken_at_seq : primary.broken_at_seq,
  };
}

async function loadEndorsements(
  endorsementPaths: string[],
  allowUnpinned: boolean,
  keyHex: string,
): Promise<RotationEndorsement[]> {
  if (endorsementPaths.length > 0 && allowUnpinned) {
    throw new UsageError("--rotation-endorsement cannot be combined with --allow-unpinned");
  }
  if (endorsementPaths.length > 0 && keyHex.trim() === "") {
    throw new UsageError(
      "--rotation-endorsement requires --key: an endorsement is authority only under a trusted root key",
    );
  }
  return Promise.all(
    endorsementPaths.map((endorsementPath) => loadRotationEndorsementFile(endorsementPath)),
  );
}

// runChainSetCommand verifies chains of base in dir and the base's restart
// continuity, matching the Go reference verify-receipt --chain. Without
// targets every chain of the base is verified. With targets (a named run) only
// those chains are verified, and the whole base is still checked: a named run
// fails on any finding in its base, and the finding names the run it concerns,
// because a run's standing depends on facts only the base shows (its
// predecessor's tail, a second successor, a replayed copy of it).
async function runChainSetCommand(
  dir: string,
  base: string,
  keyHex: string,
  allowUnpinned: boolean,
  endorsementPaths: string[],
  json: boolean,
  targets?: string[],
): Promise<number> {
  const endorsements = await loadEndorsements(endorsementPaths, allowUnpinned, keyHex);
  const trustedKeys = keyHex
    .split(",")
    .map((key) => key.trim())
    .filter((key) => key !== "");
  let baseReport;
  let sessions: string[];
  try {
    sessions = resolveBaseSessions(dir, base);
    baseReport = await verifyBase(dir, base, { trustedKeys, endorsements });
  } catch (err) {
    throw new RuntimeError(`restart continuity check incomplete: ${errorMessage(err)}`);
  }
  const chains: ChainSetReport["chains"] = [];
  for (const session of targets ?? sessions) {
    const label = `${dir} (session ${session})`;
    const scoped = await chainScopedTrust(baseReport, session, trustedKeys, endorsements);
    let chainReport: ChainCommandReport;
    try {
      chainReport = await typedChainReport(
        label,
        readSessionReceipts(dir, session),
        scoped.keys.join(","),
        allowUnpinned,
        scoped.endorsements,
        session,
      );
    } catch (err) {
      chainReport = {
        path: label,
        valid: false,
        receipt_count: 0,
        final_seq: 0,
        error: `extract receipts: ${errorMessage(err)}`,
      };
    }
    chains.push({ session, ...chainReport });
  }
  const healthy = baseHealthy(baseReport);
  const report: ChainSetReport = {
    path: dir,
    base,
    valid: healthy && chains.every((c) => c.valid),
    chains,
    continuity: {
      healthy,
      chain_count: baseReport.chains.length,
      linked: baseReport.chains
        .filter((c) => c.link !== undefined)
        .map((c) => ({
          session: c.session,
          predecessor_session: (c.link as ChainLink).predecessor_session,
          predecessor_tail_seq: Number((c.link as ChainLink).predecessor_tail_seq),
          trust: c.link_trust === "" ? "untrusted" : c.link_trust,
        })),
      unlinked: baseUnlinked(baseReport),
      findings: baseReport.findings,
    },
  };
  emitChainSet(report, json);
  if (!report.valid) {
    const reasons: string[] = [];
    const failed = chains.filter((c) => !c.valid).map((c) => c.session);
    if (failed.length > 0) {
      reasons.push(
        `chain verification failed for ${failed.length} of ${chains.length} chain(s): ${failed.join(", ")}`,
      );
    }
    if (!healthy) {
      reasons.push(
        `restart continuity: ${baseReport.findings.length} finding(s): ${baseReport.findings
          .map((f) => `${f.kind} (${f.session})`)
          .join(", ")}`,
      );
    }
    reportFailure(`${dir}: ${reasons.join("; ")}`);
  }
  return report.valid ? 0 : 1;
}

// withRecorderChain folds the recorder entry hash chain into a chain report:
// a report whose receipts verify is still broken when the entries around them
// were edited without recomputing the recorder hashes.
function withRecorderChain(
  report: ChainCommandReport,
  outer: string | undefined,
): ChainCommandReport {
  if (outer === undefined) return report;
  const reason = `${FindingOuterChainBroken}: recorder entry hash chain: ${outer}`;
  return {
    ...report,
    valid: false,
    unpinned: undefined,
    error: report.valid || report.error === undefined ? reason : `${reason}; ${report.error}`,
  };
}

function emitChainResult(report: ChainCommandReport, json: boolean): number {
  emitChain(report, json);
  if (report.valid) return 0;
  reportFailure(
    `${report.path}: ${report.unpinned === true ? "chain unpinned" : "chain broken"}: ${report.error ?? "no receipts in chain"}`,
  );
  return 1;
}

async function runChainCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      key: { type: "string", multiple: true, default: [] },
      "allow-unpinned": { type: "boolean", default: false },
      dir: { type: "boolean", default: false },
      "session-id": { type: "string" },
      "rotation-endorsement": { type: "string", multiple: true, default: [] },
    },
  });
  const target = requireOneArg(parsed.positionals, "chain");
  const keyHex = resolveSignerKeys(parsed.values.key ?? []);
  const asDir = parsed.values.dir === true;
  const explicitSession = parsed.values["session-id"] !== undefined;
  const sessionID = parsed.values["session-id"] ?? "proxy";
  const allowUnpinned = parsed.values["allow-unpinned"] === true;
  const endorsementPaths = parsed.values["rotation-endorsement"] ?? [];
  const json = parsed.values.json === true;
  // Resolve an explicit file before normalizing it: symlink/.. can reach a
  // different file from the one selected by lexical normalization.
  const clean = asDir ? path.normalize(target) : resolveOperatorFilePath(target);
  // A directory whose base has per-run chains is verified as a base, as the Go
  // reference does: the base of a run session is its prefix, and any other
  // session is its own base. Without --session-id every chain of the base is
  // verified; with it only that chain, plus the whole-base checks.
  if (asDir) {
    const base = runSessionBase(sessionID) ?? sessionID;
    let runs: string[];
    try {
      runs = resolveBaseSessions(clean, base).filter((s) => runSessionBase(s) !== undefined);
    } catch (err) {
      throw new RuntimeError(`extract receipts: ${errorMessage(err)}`);
    }
    if (runs.length > 0) {
      return runChainSetCommand(
        clean,
        base,
        keyHex,
        allowUnpinned,
        endorsementPaths,
        json,
        explicitSession ? [sessionID] : undefined,
      );
    }
  }
  const label = asDir ? `${clean} (session ${sessionID})` : clean;
  let typed: ExtractedReceipts;
  let outer: string | undefined;
  try {
    if (asDir) {
      const evidence = readSessionEvidence(clean, sessionID);
      typed = evidence.typed;
      outer = verifyRecorderChain(evidence.lines);
    } else {
      if (statSync(clean).isDirectory()) {
        throw new RuntimeError(
          `${target} is a directory; pass --dir to verify a session directory`,
        );
      }
      // A file named on the command line is read as given, even through a
      // symlink: the operator chose it.
      const lines = readEntryLines(clean);
      checkFileEntrySessions(path.basename(clean), lines);
      typed = extractTypedFromEntries(lines.map((l) => l.entry));
      outer = verifyRecorderChain(lines);
    }
  } catch (err) {
    if (err instanceof EvidenceRefusedError) {
      return emitChainResult(
        { path: label, valid: false, receipt_count: 0, final_seq: 0, error: err.message },
        json,
      );
    }
    throw new RuntimeError(`extract receipts: ${errorMessage(err)}`);
  }
  if (typed.action.length === 0 && typed.evidence.length === 0) {
    const report = await chainReportFor(label, [], keyHex, allowUnpinned, [], sessionID);
    return emitChainResult(withRecorderChain(report, outer), json);
  }
  const endorsements = await loadEndorsements(endorsementPaths, allowUnpinned, keyHex);
  const report = await typedChainReport(
    label,
    typed,
    keyHex,
    allowUnpinned,
    endorsements,
    sessionID,
  );
  return emitChainResult(withRecorderChain(report, outer), json);
}

async function runReceiptCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      key: { type: "string", default: "" },
      "allow-unpinned": { type: "boolean", default: false },
    },
  });
  const target = requireOneArg(parsed.positionals, "receipt");
  const report = await runReceipt(
    target,
    parsed.values.key ?? "",
    parsed.values["allow-unpinned"] === true,
  );
  emitReceipt(report, parsed.values.json === true);
  return report.valid ? 0 : 1;
}

async function runProvenanceCommand(args: string[]): Promise<number> {
  const parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      "allow-incomplete": { type: "boolean", default: false },
    },
  });
  const target = requireOneArg(parsed.positionals, "provenance");
  const report = await runProvenanceFixture(target);
  process.stdout.write(`${comparableProvenance(report)}\n`);
  return report.overall === "invalid" ||
    (report.overall === "incomplete" && parsed.values["allow-incomplete"] !== true)
    ? 1
    : 0;
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
    case "provenance":
      return runProvenanceCommand(args);
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

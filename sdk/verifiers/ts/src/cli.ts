#!/usr/bin/env node
// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { prefixStatus } from "./output.js";

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
  refuseSymlinkInEvidenceRootPath,
  withPinnedEvidenceDirectory,
  readSessionEvidence,
  readSessionReceipts,
  resolveBaseSessions,
  runSessionBase,
  verifyBase,
  withBaseHistorySnapshot,
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
import { receiptGroupEvidencePresent, verifyReceiptGroup } from "./group.js";
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
  integrity?: string;
  end_proof?: { proven: boolean; evidence: string[] };
  scope?: string;
  status?: string;
  companion_end_proven?: boolean;
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
    return "Usage: pipelock-verifier-ts chain PATH [--json] [--key HEX_OR_FILE]... [--rotation-endorsement FILE]... [--allow-unpinned] [--allow-prefix] [--expect-head HASH] [--expect-seq N] [--dir] [--session-id ID] [--group ID]";
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
  integrity?: string;
  end_proof?: { proven: boolean; evidence: string[] };
  scope?: string;
  status?: string;
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
    discontinuities: {
      session: string;
      predecessor_session: string;
      shard: string;
      damage_offset: number;
    }[];
    unlinked: string[];
    findings: BaseFinding[];
  };
}

// A trailing session_close ends its run, and it ends the chain only when no
// later run can continue that chain. Pipelock never resumes a per-run recorder
// session ("<base>.run.<hex>"); a restart resumed a legacy shared session
// ("proxy") after its close, so deleting the later runs leaves a chain that
// ends at a genuine close. The session comes from the closed run's signed
// session_open. Called only after the chain verified.
function closeEndsChain(receipts: Receipt[]): boolean {
  const close = receipts.at(-1)?.action_record?.session_control;
  if (close?.["kind"] !== "session_close") return false;
  const runNonce = (close["close"] as Record<string, unknown> | undefined)?.["run_nonce"];
  for (let i = receipts.length - 1; i >= 0; i--) {
    const ctrl = receipts[i]?.action_record?.session_control;
    const open = ctrl?.["open"] as Record<string, unknown> | undefined;
    if (ctrl?.["kind"] !== "session_open" || open === undefined || open["run_nonce"] !== runNonce)
      continue;
    const session = open["recorder_session"];
    return typeof session === "string" && runSessionBase(session) !== undefined;
  }
  return false;
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
    end_proof: {
      proven: result.valid && !lifecycleBroken && closeEndsChain(receipts),
      evidence:
        result.valid && !lifecycleBroken && closeEndsChain(receipts) ? ["session_close"] : [],
    },
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
  const primaryReceipts = typed.evidence.length > 0 ? typed.evidence : selectReceiptChain(typed);
  const primary = await chainReportFor(
    label,
    primaryReceipts,
    typed.evidence.length > 0 ? evidenceChainKey(keyHex, primaryReceipts) : keyHex,
    allowUnpinned,
    typed.evidence.length > 0 ? [] : endorsements,
    sessionID,
  );
  if (typed.action.length === 0 || typed.evidence.length === 0) return primary;
  const evidence = await chainReportFor(
    label,
    typed.action,
    keyHex,
    allowUnpinned,
    endorsements,
    sessionID,
  );
  if (primary.valid && evidence.valid)
    return { ...primary, companion_end_proven: evidence.end_proof?.proven === true };
  // Without a key and without --allow-unpinned both chains fail only for being
  // unpinned; the action report already says so.
  if (primary.unpinned === true && evidence.unpinned === true) return primary;
  const reasons: string[] = [];
  if (!primary.valid) reasons.push(`evidence receipt chain: ${primary.error ?? ""}`);
  if (!evidence.valid) reasons.push(`action receipt chain: ${evidence.error ?? ""}`);
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
  checkEndorsementUsage(endorsementPaths, allowUnpinned, keyHex);
  return Promise.all(
    endorsementPaths.map((endorsementPath) => loadRotationEndorsementFile(endorsementPath)),
  );
}

function checkEndorsementUsage(
  endorsementPaths: string[],
  allowUnpinned: boolean,
  keyHex: string,
): void {
  if (endorsementPaths.length > 0 && allowUnpinned) {
    throw new UsageError("--rotation-endorsement cannot be combined with --allow-unpinned");
  }
  if (endorsementPaths.length > 0 && keyHex.trim() === "") {
    throw new UsageError(
      "--rotation-endorsement requires --key: an endorsement is authority only under a trusted root key",
    );
  }
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
  displayDir: string,
  base: string,
  keyHex: string,
  allowUnpinned: boolean,
  endorsementPaths: string[],
  json: boolean,
  targets?: string[],
  endOptions = defaultEndOptions,
): Promise<number> {
  const report = await withBaseHistorySnapshot(dir, base, async () => {
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
    if ((endOptions.head || endOptions.seq !== undefined) && (targets ?? sessions).length > 1)
      throw new UsageError("endpoint pins require one selected run; pass --session-id");
    for (const session of targets ?? sessions) {
      const label = `${displayDir} (session ${session})`;
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
      chains.push({ session, ...withEndProof(chainReport, endOptions) });
    }
    const healthy = baseHealthy(baseReport);
    const report: ChainSetReport = {
      path: displayDir,
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
        discontinuities: baseReport.chains
          .filter((c) => c.recovery_seal !== undefined)
          .map((c) => ({
            session: c.session,
            predecessor_session: (c.recovery_seal as NonNullable<typeof c.recovery_seal>)
              .predecessor_session,
            shard: (c.recovery_seal as NonNullable<typeof c.recovery_seal>).shard,
            damage_offset: (c.recovery_seal as NonNullable<typeof c.recovery_seal>).damage_offset,
          })),
        unlinked: baseUnlinked(baseReport),
        findings: baseReport.findings,
      },
    };
    return report;
  });
  const chains = report.chains;
  const healthy = report.continuity.healthy;
  report.integrity = report.valid ? "valid" : "invalid";
  const proven = report.valid && report.chains.every((c) => c.end_proof?.proven === true);
  report.end_proof = { proven, evidence: proven ? ["selected_chain_ends"] : [] };
  report.scope = "chain_set";
  report.status = !report.valid ? "CHAIN BROKEN" : proven ? "CHAIN VALID" : prefixStatus;
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
        `restart continuity: ${report.continuity.findings.length} finding(s): ${report.continuity.findings
          .map((f) => `${f.kind} (${f.session})`)
          .join(", ")}`,
      );
    }
    reportFailure(`${displayDir}: ${reasons.join("; ")}`);
  }
  return !report.valid
    ? 1
    : report.chains.every((c) => c.end_proof?.proven === true) || endOptions.allowPrefix
      ? 0
      : 3;
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

interface EndOptions {
  allowPrefix: boolean;
  head: string;
  seq?: string;
}
const defaultEndOptions: EndOptions = { allowPrefix: false, head: "" };

function withEndProof(report: ChainCommandReport, opts: EndOptions): ChainCommandReport {
  let evidence = report.end_proof?.evidence ?? [];
  if (
    report.valid &&
    ((opts.head !== "" && opts.head !== report.root_hash) ||
      (opts.seq !== undefined &&
        (!/^(0|[1-9][0-9]*)$/u.test(opts.seq) || BigInt(opts.seq) !== BigInt(report.final_seq))))
  ) {
    report = {
      ...report,
      valid: false,
      error: "chain endpoint does not match expected head/seq (tail truncated or different scope)",
    };
  }
  if (report.valid) {
    if (opts.head !== "") evidence = [...evidence, "operator_head"];
    if (opts.seq !== undefined) evidence = [...evidence, "operator_seq"];
  } else evidence = [];
  const proven = report.valid && evidence.length > 0 && report.companion_end_proven !== false;
  return {
    ...report,
    integrity: report.valid ? "valid" : "invalid",
    scope: "receipt_chain",
    end_proof: { proven, evidence },
    status: !report.valid ? "CHAIN BROKEN" : proven ? "CHAIN VALID" : prefixStatus,
  };
}

function emitChainResult(
  report: ChainCommandReport,
  json: boolean,
  opts = defaultEndOptions,
): number {
  report = withEndProof(report, opts);
  emitChain(report, json);
  if (report.valid) return report.end_proof?.proven === true || opts.allowPrefix ? 0 : 3;
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
      "allow-prefix": { type: "boolean", default: false },
      "expect-head": { type: "string", default: "" },
      "expect-seq": { type: "string" },
      dir: { type: "boolean", default: false },
      "session-id": { type: "string" },
      "rotation-endorsement": { type: "string", multiple: true, default: [] },
      group: { type: "string" },
    },
  });
  const target = requireOneArg(parsed.positionals, "chain");
  const endOptions: EndOptions = {
    allowPrefix: parsed.values["allow-prefix"] === true,
    head: parsed.values["expect-head"] ?? "",
    ...(parsed.values["expect-seq"] !== undefined ? { seq: parsed.values["expect-seq"] } : {}),
  };
  if (
    endOptions.seq !== undefined &&
    (!/^[0-9]+$/u.test(endOptions.seq) || BigInt(endOptions.seq) > 18446744073709551615n)
  )
    throw new UsageError("--expect-seq requires an unsigned 64-bit integer");
  const keyHex = resolveSignerKeys(parsed.values.key ?? []);
  const asDir = parsed.values.dir === true;
  const explicitSession = parsed.values["session-id"] !== undefined;
  const sessionID = parsed.values["session-id"] ?? "proxy";
  const allowUnpinned = parsed.values["allow-unpinned"] === true;
  let endorsementPaths = parsed.values["rotation-endorsement"] ?? [];
  const json = parsed.values.json === true;
  const groupID = parsed.values.group;
  if (groupID !== undefined) {
    if (!asDir) throw new UsageError("--group requires --dir");
    if (
      allowUnpinned ||
      endorsementPaths.length > 0 ||
      explicitSession ||
      endOptions.head !== "" ||
      endOptions.seq !== undefined
    ) {
      throw new UsageError(
        "--group cannot be combined with --allow-unpinned, --session-id, or rotation endorsements",
      );
    }
    const group = await verifyReceiptGroup(target, groupID, keyHex.split(",").filter(Boolean));
    if (json)
      process.stdout.write(
        `${JSON.stringify({ ...group, integrity: group.verdict === "GROUP_VALID" ? "valid" : "invalid", end_proof: { proven: group.verdict === "GROUP_VALID", evidence: group.verdict === "GROUP_VALID" ? ["receipt_group_close"] : [] }, scope: "receipt_group", status: group.verdict === "GROUP_VALID" ? "CHAIN VALID" : "CHAIN BROKEN" }, null, 2)}\n`,
      );
    else {
      process.stdout.write(
        `${group.verdict}: ${group.group_id}${group.base_session ? ` (${group.base_session})` : ""}\n`,
      );
      if (group.error) process.stderr.write(`  error: ${group.error}\n`);
      if (group.shard_count) process.stdout.write(`  shards: ${group.shard_count}\n`);
    }
    if (group.verdict !== "GROUP_VALID")
      reportFailure(`receipt group ${group.group_id}: ${group.error ?? group.verdict}`);
    return group.verdict === "GROUP_VALID" ? 0 : 1;
  }
  // Resolve an explicit file before normalizing it: symlink/.. can reach a
  // different file from the one selected by lexical normalization.
  if (asDir) {
    try {
      refuseSymlinkInEvidenceRootPath(target);
    } catch (err) {
      if (err instanceof EvidenceRefusedError) {
        return emitChainResult(
          { path: target, valid: false, receipt_count: 0, final_seq: 0, error: err.message },
          json,
        );
      }
      throw new RuntimeError(`resolve evidence location: ${errorMessage(err)}`);
    }
    // Endorsements are read after the working directory is pinned, so
    // resolve them against the operator's directory first. Usage errors
    // outrank path resolution, as in the Rust verifier.
    checkEndorsementUsage(endorsementPaths, allowUnpinned, keyHex);
    endorsementPaths = endorsementPaths.map((p) => {
      try {
        return resolveOperatorFilePath(p);
      } catch (err) {
        throw new RuntimeError(`resolve rotation endorsement ${p}: ${errorMessage(err)}`);
      }
    });
  }
  const display = path.normalize(target);
  const readPath = asDir ? "." : resolveOperatorFilePath(target);
  const runAt = async (clean: string): Promise<number> => {
    if (asDir && receiptGroupEvidencePresent(clean)) {
      return emitChainResult(
        {
          path: display,
          valid: false,
          receipt_count: 0,
          final_seq: 0,
          error: "GROUP_INVALID: receipt group evidence requires --group",
        },
        json,
      );
    }
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
          display,
          base,
          keyHex,
          allowUnpinned,
          endorsementPaths,
          json,
          explicitSession ? [sessionID] : undefined,
          endOptions,
        );
      }
    }
    const label = asDir ? `${display} (session ${sessionID})` : display;
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
        checkFileEntrySessions(path.basename(target), lines);
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
      return emitChainResult(withRecorderChain(report, outer), json, endOptions);
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
    return emitChainResult(withRecorderChain(report, outer), json, endOptions);
  };
  if (!asDir) return runAt(readPath);
  try {
    return await withPinnedEvidenceDirectory(target, () => runAt(readPath));
  } catch (err) {
    if (err instanceof EvidenceRefusedError) {
      return emitChainResult(
        { path: display, valid: false, receipt_count: 0, final_seq: 0, error: err.message },
        json,
      );
    }
    throw err;
  }
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
  // An input the operating system cannot open is exit 2 with no report, as in
  // the Go and Rust verifiers. The library call reports it as a failed
  // verification instead of rejecting.
  try {
    resolveOperatorFilePath(target);
  } catch (err) {
    throw new RuntimeError(errorMessage(err));
  }
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

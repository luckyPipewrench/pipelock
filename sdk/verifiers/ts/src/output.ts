// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import type { AuditPacketReport } from "./types.js";
import type { ReceiptReport } from "./receipt.js";
import type { ChainCommandReport, ChainSetReport } from "./cli.js";

// reportFailure writes the one-line reason a verification failed to stderr,
// in text and JSON mode alike, so no failing exit is silent.
export function reportFailure(reason: string): void {
  process.stderr.write(`verification failed: ${reason.replace(/[\r\n]+/gu, " ")}\n`);
}

export function writeJSON(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function emitAuditPacket(report: AuditPacketReport, json: boolean): void {
  if (json) {
    writeJSON(report);
    return;
  }
  const verdict = report.verdict === "" ? "(unset)" : report.verdict;
  process.stdout.write(`Audit Packet:   ${report.path}\n`);
  process.stdout.write(`  schema:       ${report.schema_check}\n`);
  process.stdout.write(`  chain:        ${report.chain_check}\n`);
  process.stdout.write(`  cross-check:  ${report.cross_check}\n`);
  if (report.lifecycle_assessment !== "assessed") {
    process.stdout.write(
      `  lifecycle:    not assessed (${report.lifecycle_assessment_reason ?? "chain re-verification did not complete"})\n`,
    );
  } else {
    process.stdout.write(
      `  lifecycle:    ${report.lifecycle_status} (${report.lifecycle_reason})\n`,
    );
  }
  process.stdout.write(`  verdict:      ${verdict}\n`);
  process.stdout.write(`  trusted:      ${String(report.trusted)}\n`);
  process.stdout.write(`  receipts:     ${report.summary.receipt_count}\n`);
  if (report.run.provider) process.stdout.write(`  provider:     ${report.run.provider}\n`);
  if (report.run.repository) process.stdout.write(`  repository:   ${report.run.repository}\n`);
  if (report.run.sha) process.stdout.write(`  sha:          ${report.run.sha}\n`);
  if (report.run.agent_identity)
    process.stdout.write(`  agent:        ${report.run.agent_identity}\n`);
  if (report.posture.enforcement_mode)
    process.stdout.write(`  enforcement:  ${report.posture.enforcement_mode}\n`);
  if (report.posture.unsupported_paths.length > 0) {
    process.stdout.write(`  unsupported:  ${report.posture.unsupported_paths.join(", ")}\n`);
  }
  for (const err of report.errors ?? []) process.stderr.write(`ERROR: ${err}\n`);
  for (const warning of report.warnings ?? []) process.stderr.write(`WARN:  ${warning}\n`);
  process.stdout.write(`  result:       ${report.valid ? "VALID" : "INVALID"}\n`);
}

export function emitReceipt(report: ReceiptReport, json: boolean): void {
  if (json) {
    writeJSON(report);
    return;
  }
  if (report.valid) {
    process.stdout.write(`RECEIPT ${report.unpinned ? "UNPINNED" : "VALID"}: ${report.path}\n`);
    if (report.unpinned && report.error) process.stdout.write(`  warning:      ${report.error}\n`);
    process.stdout.write(`  action_id:    ${report.action_id ?? ""}\n`);
    process.stdout.write(`  verdict:      ${report.verdict ?? ""}\n`);
    process.stdout.write(`  transport:    ${report.transport ?? ""}\n`);
    process.stdout.write(`  signer:       ${report.signer_key ?? ""}\n`);
    process.stdout.write(`  policy_hash:  ${report.policy_hash ?? ""}\n`);
    process.stdout.write(`  chain_seq:    ${report.chain_seq ?? 0}\n`);
    return;
  }
  if (report.unpinned) {
    process.stderr.write(`RECEIPT UNPINNED: ${report.path}\n`);
    if (report.error) process.stderr.write(`  warning: ${report.error}\n`);
    return;
  }
  process.stderr.write(`RECEIPT INVALID: ${report.path}\n`);
  if (report.error) process.stderr.write(`  error: ${report.error}\n`);
}

export function emitChain(report: ChainCommandReport, json: boolean): void {
  if (json) {
    writeJSON(report);
    return;
  }
  if (report.valid) {
    process.stdout.write(`CHAIN ${report.unpinned ? "UNPINNED" : "VALID"}: ${report.path}\n`);
    if (report.unpinned && report.error) process.stdout.write(`  warning:    ${report.error}\n`);
    process.stdout.write(`  receipts:   ${report.receipt_count}\n`);
    if (report.action_receipts !== undefined && report.evidence_receipts !== undefined) {
      process.stdout.write(
        `  by kind:    ${report.action_receipts} action_receipt, ${report.evidence_receipts} evidence_receipt\n`,
      );
    }
    process.stdout.write(`  final seq:  ${report.final_seq}\n`);
    process.stdout.write(`  root hash:  ${report.root_hash}\n`);
    return;
  }
  if (report.unpinned) {
    process.stderr.write(`CHAIN UNPINNED: ${report.path}\n`);
    if (report.error) process.stderr.write(`  warning:    ${report.error}\n`);
    return;
  }
  process.stderr.write(`CHAIN BROKEN: ${report.path}\n`);
  if (report.error) process.stderr.write(`  error:      ${report.error}\n`);
  if ((report.broken_at_seq ?? 0) !== 0 || report.error) {
    process.stderr.write(`  broken at:  seq ${report.broken_at_seq ?? 0}\n`);
  }
}

// emitChainSet prints each run's chain report, then the base's restart
// continuity in the same shape as the Go reference.
export function emitChainSet(report: ChainSetReport, json: boolean): void {
  if (json) {
    writeJSON(report);
    return;
  }
  for (const chain of report.chains) emitChain(chain, false);
  const c = report.continuity;
  const label = c.healthy ? "RESTART CONTINUITY OK" : "RESTART CONTINUITY FAILED";
  process.stdout.write(
    `${label}: base "${report.base}": ${c.chain_count} chain(s), ${c.linked.length} linked, ${c.unlinked.length} unlinked, ${c.findings.length} link finding(s)\n`,
  );
  for (const l of c.linked) {
    process.stdout.write(
      `  linked:   ${l.session} continues ${l.predecessor_session} at seq ${l.predecessor_tail_seq} (${l.trust})\n`,
    );
  }
  for (const s of c.unlinked) process.stdout.write(`  unlinked: ${s}\n`);
  for (const f of c.findings) process.stdout.write(`  - ${f.kind}: ${f.session}: ${f.detail}\n`);
  process.stdout.write(
    "  Note: an unlinked run claims no predecessor. That is normal for a first run or concurrent runs,\n",
  );
  process.stdout.write(
    "  and it is also what a deleted link file looks like: this does not prove no run's evidence is missing.\n",
  );
  process.stdout.write(`  result:     ${report.valid ? "VALID" : "INVALID"}\n`);
}

import type { AuditPacketReport } from "./types.js";
import type { ReceiptReport } from "./receipt.js";
import type { ChainCommandReport } from "./cli.js";

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

import { readFileSync } from "node:fs";
import type { AuditPacket, AuditPacketReport, ChainResult, Receipt, Totals } from "./types.js";
import { computeTotals, verifyChain } from "./chain.js";
import { extractReceipts } from "./recorder.js";
import { validateAuditPacket } from "./schema.js";
import { resolveArtifactPath, resolvePacketPath, resolveSignerKey, sha256Hex } from "./util.js";

export interface AuditPacketOptions {
  signerKey: string;
  offline: boolean;
  allowSelfConsistentOnly: boolean;
  noTrustRequired: boolean;
  expectSha256: string;
}

const zeroTotals: Totals = {
  allow: 0,
  block: 0,
  warn: 0,
  ask: 0,
  strip: 0,
  forward: 0,
  redirect: 0,
  other: 0,
};

function reportFromPacket(packetPath: string, packet?: AuditPacket): AuditPacketReport {
  return {
    path: packetPath,
    verdict: packet?.verifier?.verdict ?? "",
    trusted: packet?.verifier?.trusted ?? false,
    valid: false,
    summary: {
      receipt_count: packet?.summary?.receipt_count ?? 0,
      totals: { ...zeroTotals, ...(packet?.summary?.totals ?? {}) },
    },
    posture: {
      enforcement_mode: packet?.posture?.enforcement_mode ?? "",
      unsupported_paths: packet?.posture?.unsupported_paths ?? [],
    },
    run: {
      provider: packet?.run?.provider ?? "",
      repository: packet?.run?.repository,
      sha: packet?.run?.sha,
      agent_identity: packet?.run?.agent_identity ?? "",
    },
    schema_check: "skipped",
    chain_check: "skipped",
    cross_check: "skipped",
  };
}

function pushError(report: AuditPacketReport, message: string): void {
  report.errors = [...(report.errors ?? []), message];
}

function trustVerdict(packet: AuditPacket, opts: AuditPacketOptions): boolean {
  if (opts.noTrustRequired) return true;
  switch (packet.verifier?.verdict) {
    case "valid":
      return packet.verifier.trusted === true;
    case "self_consistent_only":
      return opts.allowSelfConsistentOnly;
    default:
      return false;
  }
}

function crossCheck(packet: AuditPacket, chain: ChainResult, receipts: Receipt[]): string[] {
  const errors: string[] = [];
  const receiptCount = packet.summary?.receipt_count ?? -1;
  if (chain.receipt_count !== receiptCount) {
    errors.push(
      `chain receipt_count ${chain.receipt_count} != packet.summary.receipt_count ${receiptCount}`,
    );
  }
  const expectedTotals = computeTotals(receipts);
  const gotTotals = { ...zeroTotals, ...(packet.summary?.totals ?? {}) };
  for (const key of Object.keys(expectedTotals).sort() as (keyof Totals)[]) {
    if (expectedTotals[key] !== gotTotals[key]) {
      errors.push(`totals[${key}]: chain=${expectedTotals[key]} packet=${gotTotals[key]}`);
    }
  }
  if (packet.verifier?.root_hash && packet.verifier.root_hash !== chain.root_hash) {
    errors.push(`root_hash mismatch: chain=${chain.root_hash} packet=${packet.verifier.root_hash}`);
  }
  if ((packet.verifier?.final_seq ?? 0) !== 0 && packet.verifier?.final_seq !== chain.final_seq) {
    errors.push(
      `final_seq mismatch: chain=${chain.final_seq} packet=${String(packet.verifier?.final_seq)}`,
    );
  }
  switch (packet.verifier?.verdict) {
    case "valid":
    case "self_consistent_only":
      if (!chain.valid) {
        errors.push(`verdict=${packet.verifier.verdict} but chain rejected: ${chain.error ?? ""}`);
      }
      break;
    case "invalid":
      if (chain.valid) errors.push("verdict=invalid but chain re-verified successfully");
      break;
  }
  return errors;
}

export async function verifyAuditPacket(
  target: string,
  opts: AuditPacketOptions,
): Promise<AuditPacketReport> {
  const { packetPath, baseDir } = resolvePacketPath(target);
  const rawPacket = readFileSync(packetPath);
  const report = reportFromPacket(packetPath);

  if (opts.expectSha256 !== "") {
    const got = sha256Hex(rawPacket);
    const want = opts.expectSha256.trim().toLowerCase();
    if (got !== want) {
      pushError(report, `packet sha256 mismatch: got ${got}, want ${want}`);
      return report;
    }
  }

  let packet: AuditPacket;
  try {
    packet = JSON.parse(rawPacket.toString("utf8")) as AuditPacket;
  } catch (err) {
    pushError(report, `packet json: ${(err as Error).message}`);
    return report;
  }
  Object.assign(report, reportFromPacket(packetPath, packet));

  const schemaErrors = validateAuditPacket(packet);
  if (schemaErrors.length > 0) {
    report.schema_check = "fail";
    for (const err of schemaErrors) pushError(report, `schema: ${err}`);
    return report;
  }
  report.schema_check = "pass";

  if (opts.offline) {
    report.valid = trustVerdict(packet, opts);
    return report;
  }

  let receipts: Receipt[];
  let chain: ChainResult;
  try {
    const evidencePath = resolveArtifactPath(baseDir, packet.artifacts?.evidence ?? "");
    receipts = extractReceipts(evidencePath);
    const keyInput =
      opts.signerKey.trim() === "" ? (packet.verifier?.signer_key ?? "") : opts.signerKey;
    chain = await verifyChain(receipts, resolveSignerKey(keyInput), {
      allowUnpinned: opts.allowSelfConsistentOnly,
    });
  } catch (err) {
    report.chain_check = "fail";
    pushError(report, `chain: ${(err as Error).message}`);
    return report;
  }
  report.chain_check = chain.valid ? "pass" : "fail";

  const crossErrors = crossCheck(packet, chain, receipts);
  if (crossErrors.length > 0) {
    report.cross_check = "fail";
    for (const err of crossErrors) pushError(report, `cross-check: ${err}`);
    return report;
  }
  report.cross_check = "pass";
  report.valid = chain.valid && trustVerdict(packet, opts);
  if (!report.valid) pushError(report, "packet not trusted");
  return report;
}

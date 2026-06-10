import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { runReceipt } from "../src/receipt.js";
import { verifyReceipt } from "../src/signing.js";
import type { Receipt } from "../src/types.js";

const validSingle = "../../conformance/testdata/valid-single.json";
const invalidSignature = "../../conformance/testdata/invalid-signature.json";
const validSpannedV2 =
  "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision_with_spans.json";
const validPlainV2 =
  "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json";
const v2GoldenPublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const v2GoldenPolicyHash =
  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test("receipt command accepts a valid Go-generated receipt", async () => {
  const report = await runReceipt(validSingle, "");
  assert.equal(report.valid, false);
  assert.equal(report.unpinned, true);
  assert.match(report.error ?? "", /UNPINNED/u);
});

test("receipt command explicitly allows unpinned structural verification", async () => {
  const report = await runReceipt(validSingle, "", true);
  assert.equal(report.valid, true);
  assert.equal(report.unpinned, true);
  assert.equal(report.action_id, "conformance-00000");
});

test("receipt command rejects a tampered signature", async () => {
  const receipt = JSON.parse(readFileSync(invalidSignature, "utf8")) as Receipt;
  const report = await runReceipt(invalidSignature, receipt.signer_key ?? "");
  assert.equal(report.valid, false);
  assert.match(report.error ?? "", /signature verification failed/u);
});

test("receipt verifier rejects a pinned-key mismatch", async () => {
  const receipt = JSON.parse(readFileSync(validSingle, "utf8")) as Receipt;
  await assert.rejects(verifyReceipt(receipt, "0".repeat(64)), /does not match expected key/u);
});

test("receipt command rejects duplicate keys before populating metadata", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-dup-${process.pid}.json`,
  );
  writeFileSync(
    pathname,
    '{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","verdict":"allow","verdict":"block","target":"https://e.example","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"}',
    { mode: 0o600 },
  );
  try {
    const report = await runReceipt(pathname, "");
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /duplicate object key/u);
    assert.equal(report.verdict, undefined);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command accepts a valid EvidenceReceipt v2 spanned proxy decision", async () => {
  const report = await runReceipt(validSpannedV2, v2GoldenPublicKey);
  assert.equal(report.valid, true, report.error);
  assert.equal(report.action_id, "01F8MECHZX3TBDSZ7XRADM79ZS");
  assert.equal(report.verdict, "block");
  assert.equal(report.transport, "forward");
  assert.equal(report.signer_key, v2GoldenPublicKey);
  assert.equal(report.policy_hash, v2GoldenPolicyHash);
});

test("receipt command accepts a valid EvidenceReceipt v2 plain proxy decision", async () => {
  const report = await runReceipt(validPlainV2, v2GoldenPublicKey);
  assert.equal(report.valid, true, report.error);
  assert.equal(report.policy_hash, v2GoldenPolicyHash);
});

test("receipt command rejects EvidenceReceipt v2 decisions missing policy_hash", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-missing-policy-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Record<string, unknown>;
  delete receipt["policy_hash"];
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /policy_hash/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects reserved EvidenceReceipt v2 defer payload kinds", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-defer-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Record<string, unknown>;
  receipt["payload_kind"] = "defer_opened";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /known but not implemented/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects a tampered EvidenceReceipt v2 span", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-tamper-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<{ rule_id: string }> };
  payload.source_spans[0]!.rule_id = "aws_access_key_tampered";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /signature verification failed/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects unknown EvidenceReceipt v2 span fields", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-unknown-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<Record<string, unknown>> };
  payload.source_spans[0]!["raw_match"] = "lowentropy";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /unknown field raw_match/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects empty dlp normalized suffix", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-empty-view-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<Record<string, unknown>> };
  payload.source_spans[0]!["normalized_view"] = "dlp_normalized:";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /normalized_view is invalid/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects unsupported EvidenceReceipt v2 canonicalization", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-bad-canon-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  (receipt.canonicalization as Record<string, unknown>)["jcs_profile"] = "rfc8785";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /canonicalization\.jcs_profile is invalid/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects missing source_spans critical marker", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-missing-crit-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization"];
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit must include source_spans/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects unknown EvidenceReceipt v2 critical marker", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-unknown-crit-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization", "source_spans", "future_extension"];
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit has unknown field future_extension/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("receipt command rejects source_spans critical marker on plain EvidenceReceipt v2", async () => {
  const pathname = join(
    process.env["TMPDIR"] ?? "/tmp",
    `pipelock-verifier-ts-v2-plain-span-crit-${process.pid}.json`,
  );
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization", "source_spans"];
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit source_spans is invalid for proxy_decision/u);
  } finally {
    rmSync(pathname, { force: true });
  }
});

test("EvidenceReceipt v2 source spans do not expose an offline low-entropy oracle", () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<Record<string, string>> };
  const span = payload.source_spans[0]!;
  assert.equal(span["match_hash_alg"], "hmac-sha256");
  assert.match(span["match_hash"] ?? "", /^hmac-sha256:[0-9a-f]{64}$/u);
  assert.equal(JSON.stringify(receipt).includes("golden-span-mac-key"), false);
});

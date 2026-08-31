// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

function writeTempJSON(name: string, contents: string | Buffer): string {
  const dir = mkdtempSync(join(process.env["TMPDIR"] ?? tmpdir(), `pipelock-verifier-ts-${name}-`));
  const pathname = join(dir, "receipt.json");
  writeFileSync(pathname, contents, { flag: "wx", mode: 0o600 });
  return pathname;
}

function removeTempJSON(pathname: string): void {
  rmSync(dirname(pathname), { recursive: true, force: true });
}

function writeCanonicalV2Receipt(source: string, name: string): string {
  const receipt = JSON.parse(readFileSync(source, "utf8")) as Receipt;
  (receipt.signature as Record<string, unknown>)["signer_key_id"] = v2GoldenPublicKey;
  return writeTempJSON(`v2-${name}`, JSON.stringify(receipt));
}

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
  const pathname = writeTempJSON(
    "dup",
    '{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","verdict":"allow","verdict":"block","target":"https://e.example","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"}',
  );
  try {
    const report = await runReceipt(pathname, "");
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /duplicate object key/u);
    assert.equal(report.verdict, undefined);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects invalid UTF-8 before parsing", async () => {
  const pathname = writeTempJSON(
    "utf8",
    Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]),
  );
  try {
    const report = await runReceipt(pathname, "");
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /invalid UTF-8/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command accepts a valid EvidenceReceipt v2 spanned proxy decision", async () => {
  const pathname = writeCanonicalV2Receipt(validSpannedV2, "valid-spanned");
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, true, report.error);
    assert.equal(report.action_id, "01F8MECHZX3TBDSZ7XRADM79ZS");
    assert.equal(report.verdict, "block");
    assert.equal(report.transport, "forward");
    assert.equal(report.signer_key, v2GoldenPublicKey);
    assert.equal(report.policy_hash, v2GoldenPolicyHash);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command accepts a valid EvidenceReceipt v2 plain proxy decision", async () => {
  const pathname = writeCanonicalV2Receipt(validPlainV2, "valid-plain");
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, true, report.error);
    assert.equal(report.policy_hash, v2GoldenPolicyHash);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects a relabeled EvidenceReceipt v2 signer", async () => {
  const pathname = writeCanonicalV2Receipt(validPlainV2, "relabeled");
  const receipt = JSON.parse(readFileSync(pathname, "utf8")) as Receipt;
  (receipt.signature as Record<string, unknown>)["signer_key_id"] = "attacker-label";
  writeFileSync(pathname, JSON.stringify(receipt), { mode: 0o600 });
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /signer_key_id.*pinned public key/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects EvidenceReceipt v2 decisions missing policy_hash", async () => {
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Record<string, unknown>;
  delete receipt["policy_hash"];
  const pathname = writeTempJSON("v2-missing-policy", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /policy_hash/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects reserved EvidenceReceipt v2 defer payload kinds", async () => {
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Record<string, unknown>;
  receipt["payload_kind"] = "defer_opened";
  const pathname = writeTempJSON("v2-defer", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /known but not implemented/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects a tampered EvidenceReceipt v2 span", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<{ rule_id: string }> };
  payload.source_spans[0]!.rule_id = "aws_access_key_tampered";
  const pathname = writeTempJSON("v2-tamper", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /signature verification failed/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects unknown EvidenceReceipt v2 span fields", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<Record<string, unknown>> };
  payload.source_spans[0]!["raw_match"] = "lowentropy";
  const pathname = writeTempJSON("v2-unknown", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /unknown field raw_match/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects empty dlp normalized suffix", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  const payload = receipt.payload as { source_spans: Array<Record<string, unknown>> };
  payload.source_spans[0]!["normalized_view"] = "dlp_normalized:";
  const pathname = writeTempJSON("v2-empty-view", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /normalized_view is invalid/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects unsupported EvidenceReceipt v2 canonicalization", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  (receipt.canonicalization as Record<string, unknown>)["jcs_profile"] = "rfc8785";
  const pathname = writeTempJSON("v2-bad-canon", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /canonicalization\.jcs_profile is invalid/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects missing source_spans critical marker", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization"];
  const pathname = writeTempJSON("v2-missing-crit", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit must include source_spans/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects unknown EvidenceReceipt v2 critical marker", async () => {
  const receipt = JSON.parse(readFileSync(validSpannedV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization", "source_spans", "future_extension"];
  const pathname = writeTempJSON("v2-unknown-crit", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit has unknown field future_extension/u);
  } finally {
    removeTempJSON(pathname);
  }
});

test("receipt command rejects source_spans critical marker on plain EvidenceReceipt v2", async () => {
  const receipt = JSON.parse(readFileSync(validPlainV2, "utf8")) as Receipt;
  receipt.crit = ["canonicalization", "source_spans"];
  const pathname = writeTempJSON("v2-plain-span-crit", JSON.stringify(receipt));
  try {
    const report = await runReceipt(pathname, v2GoldenPublicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /crit source_spans is invalid for proxy_decision/u);
  } finally {
    removeTempJSON(pathname);
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

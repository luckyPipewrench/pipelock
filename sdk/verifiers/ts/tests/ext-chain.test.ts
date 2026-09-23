// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { extractReceipts, extractReceiptsFromSessionDir } from "../src/recorder.js";
import { receiptHash, verifyChain } from "../src/chain.js";
import { goRawMessageBytes, objectMemberSpan } from "../src/rawjson.js";

const testKey = "../../conformance/testdata/test-key.json";
const extChain = "../../conformance/testdata/g1-ext-chain.jsonl";
const extTampered = "../../conformance/testdata/g1-ext-tampered-invalid.jsonl";
const validPlainV2 =
  "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json";
// Root hash the Go reference verifier reports for g1-ext-chain.jsonl. Every
// verifier pins the same value, so a divergence in ext link bytes fails here.
const extChainRootHash = "19805bc704923ef6a602abdfa3dc4982134997a69e3fff7a627b3f1805511d1b";

function keyHex(): string {
  return (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string }).public_key_hex;
}

test("ext chain vector verifies with the Go root hash", async () => {
  const receipts = extractReceipts(extChain);
  assert.equal(receipts.length, 5);
  const result = await verifyChain(receipts, keyHex());
  assert.equal(result.valid, true, result.error);
  assert.equal(result.root_hash, extChainRootHash);
});

test("ext bytes edited after linking break the chain at seq 1", async () => {
  const result = await verifyChain(extractReceipts(extTampered), keyHex());
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 1);
  assert.match(result.error ?? "", /chain_prev_hash mismatch/u);
});

test("removing or changing ext in memory breaks the link", async () => {
  const removed = extractReceipts(extChain);
  delete removed[0]!["ext"];
  assert.equal((await verifyChain(removed, keyHex())).valid, false);

  const changed = extractReceipts(extChain);
  (changed[0]!["ext"] as Record<string, unknown>)["posture_proof_availability"] = "readable";
  assert.equal((await verifyChain(changed, keyHex())).valid, false);
});

test("receiptHash covers an explicit null ext", () => {
  const receipts = extractReceipts(extChain);
  const withNull = receipts[2]!;
  assert.equal(withNull["ext"], null);
  const withoutExt = { ...withNull };
  delete withoutExt["ext"];
  assert.notEqual(receiptHash(withNull), receiptHash(withoutExt));
});

test("goRawMessageBytes compacts and HTML-escapes like encoding/json", () => {
  const lineSep = String.fromCharCode(0x2028);
  const escA = "\\" + "u0041";
  const raw = `{ "10" : [ 1.0 , 1E+2 ] ,\t"a" : "<&> ${escA}\\/ ${lineSep}" }`;
  assert.equal(
    goRawMessageBytes(raw),
    `{"10":[1.0,1E+2],"a":"\\u003c\\u0026\\u003e ${escA}\\/ \\u2028"}`,
  );
  const line = `{"detail" : {"ext" : { "x" : "}" } , "version":1}}`;
  const detail = objectMemberSpan(line, 0, "detail");
  assert.ok(detail !== undefined);
  const ext = objectMemberSpan(line, detail.start, "ext");
  assert.ok(ext !== undefined);
  assert.equal(line.slice(ext.start, ext.end), `{ "x" : "}" }`);
});

test("interleaved evidence_receipt entries are skipped like the Go receipt-chain mode", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-ext-mixed-"));
  try {
    const lines = readFileSync(extChain, "utf8").trimEnd().split("\n");
    const evidence = JSON.parse(readFileSync(validPlainV2, "utf8")) as unknown;
    const evidenceLine = JSON.stringify({
      v: 2,
      seq: 99,
      ts: "2026-04-15T12:00:00Z",
      session_id: "conformance-session",
      type: "evidence_receipt",
      transport: "fetch",
      summary: "evidence",
      detail: evidence,
      prev_hash: "genesis",
      hash: "0",
    });
    const mixed = [lines[0], evidenceLine, ...lines.slice(1, 3), evidenceLine, ...lines.slice(3)];
    const file = join(dir, "evidence-mixed-0.jsonl");
    writeFileSync(file, `${mixed.join("\n")}\n`);
    for (const receipts of [extractReceipts(file), extractReceiptsFromSessionDir(dir, "mixed")]) {
      assert.equal(receipts.length, 5);
      const result = await verifyChain(receipts, keyHex());
      assert.equal(result.valid, true, result.error);
      assert.equal(result.root_hash, extChainRootHash);
    }

    const evidenceOnly = join(dir, "evidence-only-0.jsonl");
    writeFileSync(evidenceOnly, `${evidenceLine}\n`);
    const onlyEvidence = extractReceipts(evidenceOnly);
    assert.equal(onlyEvidence.length, 1);
    assert.equal(onlyEvidence[0]!.record_type, "evidence_receipt_v2");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

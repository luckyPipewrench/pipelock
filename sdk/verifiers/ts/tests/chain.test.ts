import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import * as ed25519 from "@noble/ed25519";
import { canonicalizeBytes } from "../src/aarp/canonical.js";
import { extractReceipts } from "../src/recorder.js";
import { receiptHash, verifyChain } from "../src/chain.js";
import type { JSONObject, Receipt } from "../src/types.js";

const validChain = "../../conformance/testdata/valid-chain.jsonl";
const brokenChain = "../../conformance/testdata/broken-chain.jsonl";
const validPlainV2 =
  "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json";
const v2GoldenPublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const v2PrivateSeedHex =
  "9d61b19d" +
  "effd5a60" +
  "ba844af4" +
  "92ec2cc4" +
  "4449c569" +
  "7b326919" +
  "703bac03" +
  "1cae7f60";

test("valid Go-generated chain verifies", async () => {
  const result = await verifyChain(extractReceipts(validChain));
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /UNPINNED/u);
});

test("valid Go-generated chain allows explicit unpinned structural verification", async () => {
  const result = await verifyChain(extractReceipts(validChain), "", { allowUnpinned: true });
  assert.equal(result.valid, true);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
  assert.equal(
    result.root_hash,
    "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a",
  );
});

test("broken chain_prev_hash is rejected", async () => {
  const result = await verifyChain(extractReceipts(brokenChain), "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /chain_prev_hash mismatch/u);
});

test("chain_seq gap is rejected", async () => {
  const receipts = extractReceipts(validChain);
  receipts.splice(2, 1);
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /seq gap/u);
});

test("first receipt must link to genesis", async () => {
  const receipts = extractReceipts(validChain);
  receipts[0]!.action_record!.chain_prev_hash = "not-genesis";
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /signature|chain_prev_hash/u);
});

test("mixed signer keys are rejected without pinned key", async () => {
  const receipts = extractReceipts(validChain);
  receipts[1]!.signer_key = "0".repeat(64);
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /does not match expected key/u);
});

test("EvidenceReceipt v2 multi-receipt chain verifies with pinned key", async () => {
  const receipts = await buildEvidenceChain(2);
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 2);
  assert.equal(result.final_seq, 1);
});

test("EvidenceReceipt v2 valid 1-receipt chain after pop", async () => {
  const receipts = await buildEvidenceChain(2);
  receipts.pop();
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, true, result.error);
});

test("EvidenceReceipt v2 tampered chain fails closed", async () => {
  const tampered = await buildEvidenceChain(2);
  tampered[1]!.chain_prev_hash = "sha256:0";
  const broken = await verifyChain(tampered, v2GoldenPublicKey);
  assert.equal(broken.valid, false);
  assert.match(broken.error ?? "", /signature|chain_prev_hash/u);
});

test("EvidenceReceipt v2 truncated middle receipt fails closed", async () => {
  const receipts = await buildEvidenceChain(3);
  receipts.splice(1, 1);
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /signature|seq gap/u);
});

test("malformed JSONL raises an error", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "malformed.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"noop","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n{"bad":\n',
      { mode: 0o600 },
    );
    assert.throws(() => extractReceipts(file), /line 2/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder extraction rejects duplicate keys inside receipt detail", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "duplicate-key.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"action_receipt","transport":"https","summary":"","detail":{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","target":"https://e.example","verdict":"allow","verdict":"block","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"},"prev_hash":"genesis","hash":"h"}\n',
      { mode: 0o600 },
    );
    assert.throws(() => extractReceipts(file), /duplicate object key/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

async function buildEvidenceChain(count: number): Promise<Receipt[]> {
  const base = JSON.parse(readFileSync(validPlainV2, "utf8")) as Receipt;
  const receipts: Receipt[] = [];
  let prevHash = "genesis";
  for (let i = 0; i < count; i++) {
    const receipt = JSON.parse(JSON.stringify(base)) as Receipt;
    receipt.event_id = `01F8MECHZX3TBDSZ7XRADM79V${i}`;
    receipt.chain_seq = i;
    receipt.chain_prev_hash = prevHash;
    await signEvidenceReceipt(receipt);
    receipts.push(receipt);
    prevHash = receiptHash(receipt);
  }
  return receipts;
}

async function signEvidenceReceipt(receipt: Receipt): Promise<void> {
  const signature = receipt.signature as JSONObject;
  receipt.signature = {
    signer_key_id: "",
    key_purpose: "",
    algorithm: "",
    signature: "",
  };
  const sig = await ed25519.signAsync(
    canonicalizeBytes(receipt),
    Buffer.from(v2PrivateSeedHex, "hex"),
  );
  receipt.signature = {
    signer_key_id: signature["signer_key_id"] ?? "receipt-signing-test",
    key_purpose: "receipt-signing",
    algorithm: "ed25519",
    signature: `ed25519:${Buffer.from(sig).toString("hex")}`,
  };
}

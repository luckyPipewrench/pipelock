import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { extractReceipts } from "../src/recorder.js";
import { verifyChain } from "../src/chain.js";

const validChain = "../../conformance/testdata/valid-chain.jsonl";
const brokenChain = "../../conformance/testdata/broken-chain.jsonl";

test("valid Go-generated chain verifies", async () => {
  const result = await verifyChain(extractReceipts(validChain));
  assert.equal(result.valid, true);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
  assert.equal(result.root_hash, "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a");
});

test("broken chain_prev_hash is rejected", async () => {
  const result = await verifyChain(extractReceipts(brokenChain));
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /chain_prev_hash mismatch/u);
});

test("chain_seq gap is rejected", async () => {
  const receipts = extractReceipts(validChain);
  receipts.splice(2, 1);
  const result = await verifyChain(receipts);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /seq gap/u);
});

test("first receipt must link to genesis", async () => {
  const receipts = extractReceipts(validChain);
  receipts[0]!.action_record!.chain_prev_hash = "not-genesis";
  const result = await verifyChain(receipts);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /signature/u);
});

test("mixed signer keys are rejected without pinned key", async () => {
  const receipts = extractReceipts(validChain);
  receipts[1]!.signer_key = "0".repeat(64);
  const result = await verifyChain(receipts);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /does not match expected key/u);
});

test("malformed JSONL raises an error", () => {
  assert.throws(() => {
    JSON.parse(readFileSync(validChain, "utf8").split("\n")[0] ?? "");
    extractReceipts("/nonexistent/evidence.jsonl");
  });
});

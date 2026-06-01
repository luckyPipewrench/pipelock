import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  assert.equal(
    result.root_hash,
    "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a",
  );
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

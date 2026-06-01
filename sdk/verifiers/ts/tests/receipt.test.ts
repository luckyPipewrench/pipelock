import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { runReceipt } from "../src/receipt.js";
import { verifyReceipt } from "../src/signing.js";
import type { Receipt } from "../src/types.js";

const validSingle = "../../conformance/testdata/valid-single.json";
const invalidSignature = "../../conformance/testdata/invalid-signature.json";

test("receipt command accepts a valid Go-generated receipt", async () => {
  const report = await runReceipt(validSingle, "");
  assert.equal(report.valid, true);
  assert.equal(report.action_id, "conformance-00000");
});

test("receipt command rejects a tampered signature", async () => {
  const report = await runReceipt(invalidSignature, "");
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

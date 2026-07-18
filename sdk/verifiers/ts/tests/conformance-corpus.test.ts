// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { runReceipt } from "../src/receipt.js";
import { rejectDuplicateKeys } from "../src/util.js";

// Paths are relative to the test CWD (sdk/verifiers/ts), matching the existing
// receipt.test.ts convention. The corpus is the vendored conformance corpus
// shared by all four reference verifiers.
const corpus = "../../conformance/testdata/corpus";
const corpusKey = (
  JSON.parse(readFileSync(`${corpus}/test-key.json`, "utf8")) as { public_key_hex: string }
).public_key_hex;

test("canonical: shield-bearing corpus receipt verifies", async () => {
  // 09 carries a nested `shield` object that the canonical field list omitted
  // before this change, which broke signature verification on shield-bearing
  // receipts. It must now verify against the Go signer's key.
  const report = await runReceipt(`${corpus}/golden/09-allow-shield-summary.json`, corpusKey);
  assert.equal(report.valid, true, report.error);
});

test("canonical: full-field differential corpus receipt verifies", async () => {
  // 10 carries parent_action_id, the taint block (incl. a nested
  // recent_taint_sources entry), the contract block, redaction, and shield —
  // every field block previously missing from at least one verifier.
  const report = await runReceipt(`${corpus}/golden/10-full-field-differential.json`, corpusKey);
  assert.equal(report.valid, true, report.error);
});

test("canonical: run-nonce corpus receipt verifies", async () => {
  const report = await runReceipt(`${corpus}/golden/11-run-nonce-bound.json`, corpusKey);
  assert.equal(report.valid, true, report.error);
});

test("canonical: tampered run-nonce corpus receipt is rejected", async () => {
  const report = await runReceipt(`${corpus}/malicious/m15-run-nonce-tampered.json`, corpusKey);
  assert.equal(report.valid, false);
  assert.match(report.error ?? "", /signature verification failed/u);
});

test("duplicate-key: corpus dup-key receipt is rejected", async () => {
  const report = await runReceipt(`${corpus}/malicious/m13-duplicate-key-verdict.json`, corpusKey);
  assert.equal(report.valid, false);
});

test("rejectDuplicateKeys: clean nested JSON passes", () => {
  assert.doesNotThrow(() => rejectDuplicateKeys('{"a":1,"b":{"c":2},"d":[{"e":3},{"e":4}]}'));
});

test("rejectDuplicateKeys: top-level duplicate throws", () => {
  assert.throws(() => rejectDuplicateKeys('{"a":1,"a":2}'), /duplicate object key/u);
});

test("rejectDuplicateKeys: nested-object duplicate throws", () => {
  assert.throws(() => rejectDuplicateKeys('{"x":{"a":1,"a":2}}'), /duplicate object key/u);
});

test("rejectDuplicateKeys: duplicate inside array element throws", () => {
  assert.throws(
    () => rejectDuplicateKeys('{"arr":[{"a":1},{"a":1,"a":2}]}'),
    /duplicate object key/u,
  );
});

test("rejectDuplicateKeys: delimiters inside string values do not confuse scope", () => {
  // A value string containing { } : , must not corrupt object-key tracking.
  assert.doesNotThrow(() => rejectDuplicateKeys('{"a":"}{:,quoted","b":2}'));
  assert.throws(() => rejectDuplicateKeys('{"a":"x","a":"y"}'), /duplicate object key/u);
});

test("rejectDuplicateKeys: unicode-escaped duplicate key throws", () => {
  // "a" decodes to "a"; must be caught or it is a cross-language
  // smuggling vector (some scanners decode, some don't).
  assert.throws(() => rejectDuplicateKeys('{"a":1,"\\u0061":2}'), /duplicate object key/u);
});

test("rejectDuplicateKeys: surrogate-pair key matches its escaped form", () => {
  // Literal U+1F600 vs 😀 (its surrogate pair) decode to the same key.
  assert.throws(
    () => rejectDuplicateKeys('{"\u{1F600}":1,"\\uD83D\\uDE00":2}'),
    /duplicate object key/u,
  );
});

test("rejectDuplicateKeys: over-deep nesting throws, exact max passes", () => {
  assert.doesNotThrow(() => rejectDuplicateKeys("[".repeat(128) + "1" + "]".repeat(128)));
  assert.throws(
    () => rejectDuplicateKeys("[".repeat(129) + "1" + "]".repeat(129)),
    /maximum depth/u,
  );
});

test("rejectDuplicateKeys: escaped quote inside key is handled", () => {
  // Key with an escaped quote; duplicate of the same decoded key must throw.
  assert.throws(() => rejectDuplicateKeys('{"a\\"b":1,"a\\"b":2}'), /duplicate object key/u);
});

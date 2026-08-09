// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { analyzeLifecycle } from "../src/lifecycle.js";
import type { ChainResult, Receipt } from "../src/types.js";

interface LifecycleVector {
  name: string;
  receipts: Receipt[];
  expected: { status: string; reason: string };
}

const validChain: ChainResult = {
  valid: true,
  receipt_count: 3,
  final_seq: 2,
  root_hash: "test-root",
};

test("lifecycle verdict vectors match the Go verifier", () => {
  const vectors = JSON.parse(
    readFileSync("../../conformance/testdata/lifecycle-verdict-vectors.json", "utf8"),
  ) as LifecycleVector[];
  for (const vector of vectors) {
    const actual = analyzeLifecycle(vector.receipts, validChain);
    assert.deepEqual(actual, vector.expected, vector.name);
  }
});

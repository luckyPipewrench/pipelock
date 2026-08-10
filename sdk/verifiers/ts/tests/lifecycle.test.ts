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
  chain_result: Partial<ChainResult>;
  expected: { status: string; reason: string };
}

interface LifecycleVectorFile {
  generated_by: string;
  vectors: LifecycleVector[];
}

const defaultChain: ChainResult = {
  valid: true,
  receipt_count: 3,
  final_seq: 2,
  root_hash: "test-root",
};

test("lifecycle verdict vectors match the Go verifier", () => {
  const file = JSON.parse(
    readFileSync("../../conformance/testdata/lifecycle-verdict-vectors.json", "utf8"),
  ) as LifecycleVectorFile;
  assert.match(file.generated_by, /^go test /u);
  assert.ok(file.vectors.length > 0, "lifecycle vector file is empty");
  for (const vector of file.vectors) {
    const actual = analyzeLifecycle(vector.receipts, { ...defaultChain, ...vector.chain_result });
    assert.deepEqual(actual, vector.expected, vector.name);
  }
});

test("missing durability fields remain unknown instead of resetting cumulative counters", () => {
  const record = (kind: string, payload: Record<string, unknown>) => ({
    action_record: {
      run_nonce: "run-missing-durability",
      session_control: {
        kind,
        [kind === "session_open" ? "open" : kind === "session_close" ? "close" : "heartbeat"]:
          payload,
      },
    },
  });
  const receipts = [
    record("session_open", { run_nonce: "run-missing-durability", open_nonce: "open" }),
    record("heartbeat", {
      run_nonce: "run-missing-durability",
      open_nonce: "open",
      beat: 1,
      fsync_errors_gated: 2,
      durability_blocks: 2,
    }),
    record("heartbeat", { run_nonce: "run-missing-durability", open_nonce: "open", beat: 2 }),
    record("session_close", { run_nonce: "run-missing-durability", open_nonce: "open" }),
  ] as Receipt[];

  assert.deepEqual(analyzeLifecycle(receipts, defaultChain), {
    status: "LIMITED",
    reason: "bounded_closed",
  });
});

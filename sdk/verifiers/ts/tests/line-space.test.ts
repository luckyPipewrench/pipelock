// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { trimGoSpace } from "../src/line-space.js";

const path = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../conformance/testdata/receipt-line-whitespace.json",
);
const vectors = JSON.parse(readFileSync(path, "utf8")).vectors as Array<{
  name: string;
  line: string;
  expected: string;
}>;

test("shared Go evidence-line whitespace vectors", () => {
  assert.equal(vectors.length, 93);
  for (const vector of vectors) {
    const trimmed = trimGoSpace(vector.line);
    let outcome = "reject";
    if (trimmed === "") outcome = "skip";
    else {
      try {
        JSON.parse(trimmed);
        outcome = "parse";
      } catch {
        /* expected for invalid input */
      }
    }
    assert.equal(outcome, vector.expected, vector.name);
  }
});

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";
import { rejectFoldedKeys } from "../src/util.js";

test("JSON key folding matches shared parity fixture", () => {
  const fixture = JSON.parse(
    readFileSync("../../conformance/testdata/json-key-folding.json", "utf8"),
  ) as { cases: { name: string; raw: string; valid: boolean }[]; groups: string[] };
  for (const group of fixture.groups) {
    const chars = [...group];
    for (const char of chars.slice(1)) {
      assert.throws(
        () => rejectFoldedKeys(JSON.stringify({ [chars[0]]: 1, [char]: 2 })),
        /duplicate object key/u,
        group,
      );
    }
  }
  for (const entry of fixture.cases) {
    if (entry.valid) assert.doesNotThrow(() => rejectFoldedKeys(entry.raw), entry.name);
    else assert.throws(() => rejectFoldedKeys(entry.raw), /duplicate object key/u, entry.name);
  }
});

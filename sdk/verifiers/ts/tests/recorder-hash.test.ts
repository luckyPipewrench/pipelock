// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { recorderEntryHash, verifyRecorderChain } from "../src/recorder-chain.js";
import { parseEntryLinesText } from "../src/recorder.js";
import { findPackageRoot } from "./paths.js";

// Written by the Go conformance test from internal/recorder itself, so the
// port is held to Go's ComputeHash and VerifyChain rather than to a reading
// of them.
const packageRoot = findPackageRoot(import.meta.url);
const VECTORS = resolve(packageRoot, "../../conformance/testdata/recorder-hash/vectors.json");

interface Fixture {
  hashes: { name: string; line: string; hash: string }[];
  rejects: { name: string; line: string; error: string }[];
  chains: { name: string; lines: string[]; error: string }[];
}

const fixture = JSON.parse(readFileSync(VECTORS, "utf8")) as Fixture;

test("null recorder entry reports an unsupported version", () => {
  assert.throws(() => parseEntryLinesText("null\n"), /unsupported entry version null/u);
});

test("recorder entry hash matches Go ComputeHash for every vector", () => {
  assert.ok(fixture.hashes.length >= 15);
  for (const v of fixture.hashes) {
    assert.equal(recorderEntryHash(v.line), v.hash, v.name);
  }
});

test("recorder entry hash refuses every line Go refuses", () => {
  assert.ok(fixture.rejects.length >= 8);
  for (const v of fixture.rejects) {
    assert.throws(() => recorderEntryHash(v.line), Error, v.name);
  }
});

test("recorder chain verdicts and messages match Go VerifyChain", () => {
  let broken = 0;
  for (const c of fixture.chains) {
    const got = verifyRecorderChain(c.lines.map((line) => ({ line })));
    assert.equal(got ?? "", c.error, c.name);
    if (c.error !== "") broken++;
  }
  assert.ok(broken >= 4);
});

test("a one-character edit to a sealed line breaks the chain", () => {
  const valid = fixture.chains.find((c) => c.error === "" && c.lines.length >= 3);
  assert.ok(valid);
  const lines = [...valid.lines];
  lines[1] = (lines[1] as string).replace('"summary":"b"', '"summary":"B"');
  assert.notEqual(lines[1], valid.lines[1]);
  assert.match(verifyRecorderChain(lines.map((line) => ({ line }))) ?? "", /hash mismatch/u);
});

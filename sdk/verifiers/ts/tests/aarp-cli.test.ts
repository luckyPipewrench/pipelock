// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// End-to-end CLI tests for the aarp subcommand: exit codes (0 appraised/linked,
// 1 fatal/not-linked, 2 I/O or trust error, 64 usage), --json output, the human
// non-json path, and the --chain path. The CLI is run as a subprocess against
// the built dist so exit-code wiring through main() is exercised.

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { findPackageRoot } from "./paths.js";

const packageRoot = findPackageRoot(import.meta.url);
const CLI = resolve(packageRoot, "dist/src/cli.js");
const corpus = resolve(packageRoot, "../../conformance/testdata/aarp-corpus");
const trust = `${corpus}/trust.json`;
const provenanceFixture = resolve(
  packageRoot,
  "../../conformance/testdata/provenance/p00-valid.json",
);

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runCLI(args: string[]): RunResult {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
  return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

test("cli aarp: appraise golden fixture exits 0 with comparable JSON", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    trust,
    "--json",
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /"assertion_signed":true/u);
  assert.ok(r.stdout.endsWith("\n"));
});

test("cli aarp: human (non-json) appraise path exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    trust,
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /AARP appraisal \(aarp\/v0\.1\)/u);
});

test("cli aarp: fatal envelope exits 1 and prints envelope_fatal in json mode", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/malicious/m09-profile-mismatch.aarp.json`,
    "--trust",
    trust,
    "--json",
  ]);
  assert.equal(r.status, 1);
  assert.equal(r.stdout.trim(), '{"envelope_fatal":true}');
});

test("cli aarp: fatal envelope non-json prints to stderr and exits 1", () => {
  const r = runCLI(["aarp", `${corpus}/edge/p07-unknown-field.aarp.json`, "--trust", trust]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /ENVELOPE FATAL/u);
});

test("cli aarp: --chain linked stream exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), '{"chain_linked":true,"length":3}');
});

test("cli aarp: --chain non-json human path exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /AARP chain: 3 envelopes/u);
});

test("cli aarp: --chain broken stream exits 1", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c02-reordered-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 1);
});

test("cli aarp: --chain fatal line exits 1 with marker", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c03-mixed-issuer-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 1);
});

test("cli aarp: missing positional is usage error (64)", () => {
  const r = runCLI(["aarp", "--trust", trust]);
  assert.equal(r.status, 64);
});

test("cli aarp: unknown flag is usage error (64)", () => {
  const r = runCLI(["aarp", `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "--bogus"]);
  assert.equal(r.status, 64);
});

test("cli aarp: missing envelope file is I/O error (2)", () => {
  const r = runCLI(["aarp", "/nonexistent/file.aarp.json", "--trust", trust]);
  assert.equal(r.status, 2);
});

test("cli aarp: missing trust file is I/O error (2)", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    "/nonexistent/trust.json",
  ]);
  assert.equal(r.status, 2);
});

test("cli aarp: no --trust runs with empty trust (every sig unknown_key)", () => {
  const r = runCLI(["aarp", `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "--json"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /"status":"unknown_key"/u);
  assert.match(r.stdout, /"assertion_signed":false/u);
});

test("cli provenance: incomplete verification requires explicit opt-in", () => {
  const strict = runCLI(["provenance", provenanceFixture]);
  assert.equal(strict.status, 1);
  assert.equal(JSON.parse(strict.stdout).overall, "incomplete");

  const inspection = runCLI(["provenance", provenanceFixture, "--allow-incomplete"]);
  assert.equal(inspection.status, 0);
  assert.equal(JSON.parse(inspection.stdout).overall, "incomplete");
});

test("cli provenance: unreadable and invalid fixtures remain rejected", () => {
  const missing = runCLI(["provenance", resolve(packageRoot, "does-not-exist.json")]);
  assert.equal(missing.status, 1);
  assert.equal(JSON.parse(missing.stdout).overall, "invalid");

  const invalidFixture = resolve(
    packageRoot,
    "../../conformance/testdata/provenance/p02-bad-signature.json",
  );
  const invalid = runCLI(["provenance", invalidFixture, "--allow-incomplete"]);
  assert.equal(invalid.status, 1);
  assert.equal(JSON.parse(invalid.stdout).overall, "invalid");
});

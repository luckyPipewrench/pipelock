// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { extractReceiptsFromSessionDir } from "../src/recorder.js";
import { findPackageRoot } from "./paths.js";

// Every current run writes an ActionReceipt v1 chain and an EvidenceReceipt v2
// chain into the same files. These tests hold the CLI to verifying both.
const packageRoot = findPackageRoot(import.meta.url);
const CLI = resolve(packageRoot, "dist/src/cli.js");
const FIXTURES = resolve(packageRoot, "../../conformance/testdata/run-chains");
const KEY = readFileSync(join(FIXTURES, "signer-key.hex"), "utf8").trim();
// The run whose action chain the tampered-predecessor variant forges.
const SESSION = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe";

function runFile(dir: string): string {
  return join(dir, `evidence-${SESSION}-0.jsonl`);
}

function runCLI(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// v2TamperedDir copies the valid fixture and edits one field of the run's last
// EvidenceReceipt v2, leaving its action chain untouched.
function v2TamperedDir(root: string): string {
  const dir = join(root, "v2-forged");
  cpSync(join(FIXTURES, "valid"), dir, { recursive: true });
  const lines = readFileSync(runFile(dir), "utf8").split("\n");
  let last = -1;
  lines.forEach((l, i) => {
    if (l.includes('"type":"evidence_receipt"')) last = i;
  });
  const line = lines[last] ?? "";
  assert.equal(line.split('"actor":"pipelock"').length, 2, "fixture shape changed");
  lines[last] = line.replace('"actor":"pipelock"', '"actor":"pipelocx"');
  writeFileSync(runFile(dir), lines.join("\n"));
  return dir;
}

test("a session holding both receipt chains is valid only when both verify", () => {
  const root = mkdtempSync(join(tmpdir(), "mixed-chains-"));
  try {
    const cases: [string, string, string][] = [
      ["valid", join(FIXTURES, "valid"), ""],
      ["v1-forged", join(FIXTURES, "tampered-predecessor"), "action receipt chain: "],
      ["v2-forged", v2TamperedDir(root), "evidence receipt chain: "],
    ];
    for (const [name, dir, wantErr] of cases) {
      for (const [mode, args] of [
        ["explicit-session", ["chain", dir, "--dir", "--session-id", SESSION]],
        ["file", ["chain", runFile(dir)]],
      ] as [string, string[]][]) {
        const r = runCLI([...args, "--key", KEY, "--json"]);
        // A named run reports its own chain inside the base report.
        const parsed = JSON.parse(r.stdout) as {
          valid: boolean;
          error?: string;
          chains?: { session: string; valid: boolean; error?: string }[];
        };
        const report =
          parsed.chains === undefined
            ? parsed
            : (parsed.chains.find((c) => c.session === SESSION) ?? { valid: true });
        if (wantErr === "") {
          assert.equal(r.status, 0, `${name}/${mode}: ${r.stdout}`);
          assert.equal(report.valid, true);
          assert.equal(report.error, undefined);
        } else {
          assert.equal(r.status, 1, `${name}/${mode}: ${r.stdout}`);
          assert.equal(report.valid, false);
          assert.ok(
            report.error?.includes(wantErr),
            `${name}/${mode}: error ${String(report.error)} should name ${wantErr}`,
          );
        }
      }
      const set = runCLI(["chain", dir, "--dir", "--key", KEY, "--json"]);
      const setReport = JSON.parse(set.stdout) as {
        valid: boolean;
        chains: { session: string; valid: boolean }[];
      };
      const line = setReport.chains.find((c) => c.session === SESSION);
      assert.ok(line, `${name}: no line for ${SESSION}`);
      assert.equal(line.valid, wantErr === "", `${name}/directory line`);
      assert.equal(set.status, wantErr === "" ? 0 : 1, `${name}/directory exit`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an unpinned mixed session reports the unpinned banner once", () => {
  const r = runCLI(["chain", runFile(join(FIXTURES, "valid")), "--json"]);
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stdout) as { unpinned?: boolean; error?: string };
  assert.equal(report.unpinned, true);
  assert.ok(!report.error?.includes("receipt chain:"), String(report.error));
  const allowed = runCLI(["chain", runFile(join(FIXTURES, "valid")), "--allow-unpinned"]);
  assert.equal(allowed.status, 0, allowed.stdout);
});

// For session S the name evidence-S-evil-0.jsonl belongs to session S-evil
// under Go's parsed-equality rule, so it must not be read into S's chain even
// though it starts with "evidence-S-". The -evil file holds S's entries, so
// the base pass refuses it by entry session_id, and a named run fails on any
// finding in its base while its own chain stays valid.
test("an explicit session does not read a prefix-sibling session's files", () => {
  const dir = mkdtempSync(join(tmpdir(), "session-prefix-"));
  try {
    cpSync(runFile(join(FIXTURES, "valid")), runFile(dir));
    const control = runCLI(["chain", dir, "--dir", "--session-id", SESSION, "--key", KEY]);
    assert.equal(control.status, 0, control.stdout);
    const alone = extractReceiptsFromSessionDir(dir, SESSION).length;
    assert.ok(alone > 0);

    cpSync(
      runFile(join(FIXTURES, "tampered-predecessor")),
      join(dir, `evidence-${SESSION}-evil-0.jsonl`),
    );
    const r = runCLI(["chain", dir, "--dir", "--session-id", SESSION, "--key", KEY, "--json"]);
    assert.equal(r.status, 1, r.stdout);
    const report = JSON.parse(r.stdout) as {
      chains: { session: string; valid: boolean; action_receipts: number }[];
      continuity: { findings: { kind: string; session: string; detail: string }[] };
    };
    assert.deepEqual(
      report.chains.map((c) => [c.session, c.valid, c.action_receipts]),
      [[SESSION, true, alone]],
    );
    assert.deepEqual(
      report.continuity.findings.map((f) => [f.kind, f.session]),
      [["corrupt_chain", `${SESSION}-evil`]],
    );
    assert.match(report.continuity.findings[0]?.detail ?? "", /does not match requested session/u);
    assert.equal(extractReceiptsFromSessionDir(dir, SESSION).length, alone);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

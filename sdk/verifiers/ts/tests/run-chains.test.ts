// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { baseHealthy, baseUnlinked, verifyBase } from "../src/chain-set.js";
import { loadRotationEndorsementFile, type RotationEndorsement } from "../src/rotation.js";
import { findPackageRoot } from "./paths.js";

// Real evidence directories written by two and three pipelock runs (see
// sdk/conformance/testdata/run-chains/README.md). expect.json in each variant
// is generated from the Go reference, so these tests hold the TypeScript
// verifier to Go's verdict on every one.
const packageRoot = findPackageRoot(import.meta.url);
const CLI = resolve(packageRoot, "dist/src/cli.js");
const FIXTURES = resolve(packageRoot, "../../conformance/testdata/run-chains");
const KEY = readFileSync(join(FIXTURES, "signer-key.hex"), "utf8").trim();
const ROTATED_KEY = readFileSync(join(FIXTURES, "rotated-signer-key.hex"), "utf8").trim();
const VARIANTS = [
  "valid",
  "tampered-predecessor",
  "tampered-successor",
  "link-edited",
  "link-deleted",
  "double-successor",
  "link-wrong-tail",
  "link-appended",
  "key-rotated",
];

// Each case is a variant under one trust input, matching the Go generator.
interface Case {
  variant: string;
  expectFile: string;
  bothKeys: boolean;
  endorse: boolean;
}
const CASES: Case[] = [
  ...VARIANTS.map((variant) => ({
    variant,
    expectFile: "expect.json",
    bothKeys: false,
    endorse: false,
  })),
  { variant: "key-rotated", expectFile: "expect-both-keys.json", bothKeys: true, endorse: false },
  { variant: "key-rotated", expectFile: "expect-endorsed.json", bothKeys: false, endorse: true },
];

function caseKeys(c: Case): string[] {
  return c.bothKeys ? [KEY, ROTATED_KEY] : [KEY];
}

function endorsementPath(c: Case): string {
  return join(FIXTURES, c.variant, "rotation-endorsement.json");
}

async function caseEndorsements(c: Case): Promise<RotationEndorsement[]> {
  return c.endorse ? [await loadRotationEndorsementFile(endorsementPath(c))] : [];
}
// Found from the recorder entry hash chain, which only the Go verifiers check.
interface Expect {
  valid: boolean;
  healthy: boolean;
  chains: { session: string; valid: boolean }[];
  linked: {
    session: string;
    predecessor_session: string;
    predecessor_tail_seq: number;
    trust: string;
  }[];
  unlinked: string[];
  findings: { kind: string; session: string }[];
}

function expectFor(variant: string, expectFile = "expect.json"): Expect {
  return JSON.parse(readFileSync(join(FIXTURES, variant, expectFile), "utf8")) as Expect;
}

function goFindings(expect: Expect): { kind: string; session: string }[] {
  return expect.findings;
}

function sortFindings(
  list: { kind: string; session: string }[],
): { kind: string; session: string }[] {
  return [...list].sort((a, b) =>
    a.kind !== b.kind ? (a.kind < b.kind ? -1 : 1) : a.session < b.session ? -1 : 1,
  );
}

function runCLI(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

for (const c of CASES) {
  const variant = c.variant;
  const name = `${variant}/${c.expectFile}`;
  test(`run-chain fixture ${name}: verifyBase matches the Go reference`, async () => {
    const exp = expectFor(variant, c.expectFile);
    const report = await verifyBase(join(FIXTURES, variant), "proxy", {
      trustedKeys: caseKeys(c),
      endorsements: await caseEndorsements(c),
    });
    assert.deepEqual(
      report.chains.map((c) => ({ session: c.session, valid: c.valid })),
      exp.chains,
    );
    assert.deepEqual(
      report.chains
        .filter((c) => c.link !== undefined)
        .map((c) => ({
          session: c.session,
          predecessor_session: c.link?.predecessor_session,
          predecessor_tail_seq: Number(c.link?.predecessor_tail_seq),
          trust: c.link_trust,
        })),
      exp.linked,
    );
    assert.deepEqual(baseUnlinked(report), exp.unlinked);
    assert.deepEqual(
      sortFindings(report.findings.map((f) => ({ kind: f.kind, session: f.session }))),
      goFindings(exp),
    );
    assert.equal(baseHealthy(report), goFindings(exp).length === 0);
  });

  // The CLI takes one --key, so the two-key trust input exists only in the API.
  if (c.bothKeys) continue;
  test(`run-chain fixture ${name}: CLI directory mode reaches the Go verdict`, () => {
    const exp = expectFor(variant, c.expectFile);
    const args = ["chain", join(FIXTURES, variant), "--dir", "--key", KEY, "--json"];
    if (c.endorse) args.push("--rotation-endorsement", endorsementPath(c));
    const r = runCLI(args);
    assert.equal(r.status, exp.valid ? 0 : 1, r.stderr);
    const report = JSON.parse(r.stdout) as {
      valid: boolean;
      base: string;
      chains: { session: string; valid: boolean }[];
      continuity: { healthy: boolean; unlinked: string[]; linked: { trust: string }[] };
    };
    assert.equal(report.valid, exp.valid);
    assert.equal(report.base, "proxy");
    assert.deepEqual(
      report.chains.map((c) => c.session),
      exp.chains.map((c) => c.session),
    );
    assert.deepEqual(report.continuity.unlinked, exp.unlinked);
    assert.deepEqual(
      report.continuity.linked.map((l) => l.trust),
      exp.linked.map((l) => (l.trust === "" ? "untrusted" : l.trust)),
    );
  });
}

test("run-chain CLI human output lists linked and unlinked runs", () => {
  const r = runCLI(["chain", join(FIXTURES, "valid"), "--dir", "--key", KEY]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(
    r.stdout,
    /RESTART CONTINUITY OK: base "proxy": 2 chain\(s\), 1 linked, 1 unlinked/u,
  );
  assert.match(
    r.stdout,
    /linked: {3}proxy\.run\.[0-9a-f]{32} continues proxy\.run\.[0-9a-f]{32} at seq \d+ \(same_key\)/u,
  );
  assert.match(r.stdout, /result: {5}VALID/u);
});

test("run-chain CLI with a wrong key fails every run", () => {
  const wrong = "11".repeat(32);
  const r = runCLI(["chain", join(FIXTURES, "valid"), "--dir", "--key", wrong, "--json"]);
  assert.equal(r.status, 1);
  const report = JSON.parse(r.stdout) as { valid: boolean; chains: { valid: boolean }[] };
  assert.equal(report.valid, false);
  assert.deepEqual(
    report.chains.map((c) => c.valid),
    [false, false],
  );
});

// A named run verifies that run's chain and still runs the whole-base pass,
// as the Go reference does, so its report carries the base's continuity.
test("an explicit --session-id verifies that run and checks its base", () => {
  const exp = expectFor("valid");
  const session = exp.chains[0]?.session as string;
  const r = runCLI([
    "chain",
    join(FIXTURES, "valid"),
    "--dir",
    "--key",
    KEY,
    "--session-id",
    session,
    "--json",
  ]);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout) as Record<string, unknown>;
  const chains = report["chains"] as { session: string; path: string; valid: boolean }[];
  assert.deepEqual(
    chains.map((c) => [c.session, c.path, c.valid]),
    [[session, `${join(FIXTURES, "valid")} (session ${session})`, true]],
  );
  assert.equal(report["valid"], true);
  const continuity = report["continuity"] as { chain_count: number; healthy: boolean };
  assert.equal(continuity.chain_count, exp.chains.length);
  assert.equal(continuity.healthy, true);

  // The legacy base session named explicitly has no shards here, so its
  // chain has no receipts.
  const legacy = runCLI([
    "chain",
    join(FIXTURES, "valid"),
    "--dir",
    "--key",
    KEY,
    "--session-id",
    "proxy",
    "--json",
  ]);
  assert.equal(legacy.status, 1);
  const legacyReport = JSON.parse(legacy.stdout) as { chains: { error: string }[] };
  assert.equal(legacyReport.chains[0]?.error, "no receipts in chain");
  assert.match(legacy.stderr, /^verification failed: .*proxy/mu);
});

test("a directory with no run chains keeps single-session verification", () => {
  const dir = mkdtempSync(join(tmpdir(), "run-chains-legacy-"));
  try {
    const r = runCLI(["chain", dir, "--dir", "--key", KEY, "--json"]);
    assert.equal(r.status, 1);
    const report = JSON.parse(r.stdout) as Record<string, unknown>;
    assert.equal(report["error"], "no receipts in chain");
    assert.equal(report["continuity"], undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Each malformed link below must be rejected as an invalid link, never
// silently skipped (which would read as an honest unlinked restart).
test("malformed link files are findings, not skipped", async () => {
  const valid = join(FIXTURES, "valid");
  const linkName = readdirSync(valid).find((n) => n.startsWith("chain-link-")) as string;
  const original = readFileSync(join(valid, linkName), "utf8").trim();
  const obj = JSON.parse(original) as Record<string, unknown>;
  const cases: [string, string, RegExp][] = [
    ["duplicate key", original.replace(/^\{/u, '{"version":1,'), /duplicate/u],
    ["case-folded alias", JSON.stringify({ ...obj, Version: 1 }), /aliases "version"/u],
    ["unknown field", JSON.stringify({ ...obj, extra: true }), /unknown field "extra"/u],
    ["trailing tokens", `${original} {}`, /trailing/u],
    ["version 2", JSON.stringify({ ...obj, version: 2 }), /unsupported chain link version/u],
    [
      "uppercase key hex",
      JSON.stringify({
        ...obj,
        successor_signer_key: String(obj["successor_signer_key"]).toUpperCase(),
      }),
      /successor_signer_key is invalid/u,
    ],
    [
      "non-canonical linked_at",
      JSON.stringify({ ...obj, linked_at: "2026-09-27T17:12:14.500Z0" }),
      /linked_at/u,
    ],
    ["not an object", "[]", /not a JSON object/u],
  ];
  for (const [name, body, detail] of cases) {
    const dir = mkdtempSync(join(tmpdir(), "run-chains-link-"));
    try {
      cpSync(valid, dir, { recursive: true });
      writeFileSync(join(dir, linkName), body);
      const report = await verifyBase(dir, "proxy", { trustedKeys: [KEY], endorsements: [] });
      const finding = report.findings.find((f) => f.kind === "invalid_link");
      assert.ok(
        finding !== undefined,
        `${name}: want invalid_link, got ${JSON.stringify(report.findings)}`,
      );
      assert.match(finding.detail, detail, name);
      assert.equal(
        report.chains.filter((c) => c.link !== undefined).length,
        0,
        `${name}: a rejected link must not attach`,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  // Positive control: the unmodified link attaches with no finding.
  const control = await verifyBase(valid, "proxy", { trustedKeys: [KEY], endorsements: [] });
  assert.deepEqual(control.findings, []);
  assert.equal(control.chains.filter((c) => c.link !== undefined).length, 1);
});

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  goJSONMarshal,
  loadRotationEndorsementFile,
  verifyRotationEndorsement,
} from "../src/rotation.js";
import { canonicalize } from "../src/aarp/canonical.js";
import { canonicalJSONString } from "../src/canonical.js";
import { decodeChainLink, goJSONString, verifyChainLink } from "../src/chain-set.js";
import { findPackageRoot } from "./paths.js";

// Written by the Go conformance test from encoding/json itself, so this holds
// the TypeScript encoder to Go's bytes rather than to a recollection of them.
const packageRoot = findPackageRoot(import.meta.url);
const FIXTURES = resolve(packageRoot, "../../conformance/testdata/go-json-escapes");

interface Table {
  entries: { codepoint: string; go_json_hex: string }[];
}

test("goJSONMarshal writes every ASCII character and U+2028/U+2029 as Go does", () => {
  const table = JSON.parse(readFileSync(join(FIXTURES, "table.json"), "utf8")) as Table;
  assert.equal(table.entries.length, 130);
  for (const entry of table.entries) {
    const ch = String.fromCodePoint(Number.parseInt(entry.codepoint, 16));
    const got = Buffer.from(goJSONMarshal(ch), "utf8").toString("hex");
    assert.equal(got, entry.go_json_hex, `U+${entry.codepoint}`);
  }
});

test("a Go-signed endorsement whose session_id needs every escape verifies", async () => {
  const endorsement = await loadRotationEndorsementFile(join(FIXTURES, "endorsement.json"));
  await verifyRotationEndorsement(endorsement);

  const dir = mkdtempSync(join(tmpdir(), "go-json-escapes-"));
  try {
    const raw = readFileSync(join(FIXTURES, "endorsement.json"), "utf8");
    const edited = join(dir, "endorsement.json");
    // Same characters, one fewer: the digest changes, so the signature fails.
    const changed = raw.replace(String.raw`run\b\f`, String.raw`run\b`);
    assert.notEqual(changed, raw, "fixture shape changed");
    writeFileSync(edited, changed);
    await assert.rejects(
      async () => verifyRotationEndorsement(await loadRotationEndorsementFile(edited)),
      /signature verification failed/u,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the chain-link encoder writes every ASCII character and U+2028/U+2029 as Go does", () => {
  const table = JSON.parse(readFileSync(join(FIXTURES, "table.json"), "utf8")) as Table;
  for (const entry of table.entries) {
    const ch = String.fromCodePoint(Number.parseInt(entry.codepoint, 16));
    const got = Buffer.from(goJSONString(ch), "utf8").toString("hex");
    assert.equal(got, entry.go_json_hex, `U+${entry.codepoint}`);
  }
});

test("a Go-signed chain link whose sessions need every escape verifies", async () => {
  const raw = readFileSync(join(FIXTURES, "chain-link.json"), "utf8");
  await verifyChainLink(decodeChainLink(raw));
  const changed = raw.replace(String.raw`proxy.run.b\b\f`, String.raw`proxy.run.b\b`);
  assert.notEqual(changed, raw, "fixture shape changed");
  await assert.rejects(async () => verifyChainLink(decodeChainLink(changed)));
});

// The v1 receipt canonicalizer and the v2 receipt JCS encoder also rebuild
// strings Go wrote with encoding/json (contract.Canonicalize marshals each
// NFC-normalized string, and NFC leaves every code point here unchanged).
test("the receipt canonicalizers write every ASCII character and U+2028/U+2029 as Go does", () => {
  const table = JSON.parse(readFileSync(join(FIXTURES, "table.json"), "utf8")) as Table;
  for (const entry of table.entries) {
    const ch = String.fromCodePoint(Number.parseInt(entry.codepoint, 16));
    for (const [name, encoded] of [
      ["canonicalJSONString", canonicalJSONString(ch)],
      ["aarp canonicalize", canonicalize(ch)],
    ] as [string, string][]) {
      const got = Buffer.from(encoded, "utf8").toString("hex");
      assert.equal(got, entry.go_json_hex, `${name} U+${entry.codepoint}`);
    }
  }
});

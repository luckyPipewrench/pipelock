// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { findPackageRoot } from "./paths.js";

const packageRoot = findPackageRoot(import.meta.url);
const root = resolve(packageRoot, "../../conformance/testdata/end-proof");
const fixture = JSON.parse(readFileSync(resolve(root, "expect.json"), "utf8")) as {
  key: string;
  cases: {
    name: string;
    file: string;
    flags: string[];
    exit: number;
    status: string;
    proven: boolean;
  }[];
};
for (const cell of fixture.cases) {
  test(`chain endpoint: ${cell.name}`, () => {
    for (const json of [false, true]) {
      const result = spawnSync(
        process.execPath,
        [
          resolve(packageRoot, "dist/src/cli.js"),
          "chain",
          resolve(root, cell.file),
          "--key",
          fixture.key,
          ...cell.flags,
          ...(json ? ["--json"] : []),
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, cell.exit, result.stdout + result.stderr);
      if (json) {
        const report = JSON.parse(result.stdout);
        assert.equal(report.status, cell.status);
        assert.equal(report.end_proof.proven, cell.proven);
        assert.equal(report.scope, "receipt_chain");
        assert.equal(report.integrity, cell.exit === 1 ? "invalid" : "valid");
      } else
        assert.ok(
          (result.stdout + result.stderr).includes(cell.status),
          result.stdout + result.stderr,
        );
    }
  });
}

test("closed unpinned chain keeps the same JSON and text label", () => {
  for (const json of [false, true]) {
    const result = spawnSync(
      process.execPath,
      [
        resolve(packageRoot, "dist/src/cli.js"),
        "chain",
        resolve(root, "closed.jsonl"),
        "--allow-unpinned",
        ...(json ? ["--json"] : []),
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
    if (json) assert.equal(JSON.parse(result.stdout).status, "CHAIN UNPINNED");
    else assert.ok(result.stdout.includes("CHAIN UNPINNED"));
  }
});

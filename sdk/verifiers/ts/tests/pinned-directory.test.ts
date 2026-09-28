// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { withPinnedEvidenceDirectory } from "../src/chain-set.js";
import { readVerifierBytes } from "../src/util.js";

test("directory reads stay on the entered directory after its name is replaced", async (t) => {
  if (process.platform === "win32") {
    t.skip("Windows prevents renaming a process working directory");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-pinned-dir-"));
  const root = join(base, "root");
  const moved = join(base, "moved");
  const outside = join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  writeFileSync(join(root, "evidence.jsonl"), "inside");
  writeFileSync(join(outside, "evidence.jsonl"), "outside");
  try {
    await withPinnedEvidenceDirectory(root, async () => {
      assert.equal(readFileSync("evidence.jsonl", "utf8"), "inside");
      renameSync(root, moved);
      symlinkSync(outside, root, "dir");
      try {
        assert.equal(readFileSync(join(root, "evidence.jsonl"), "utf8"), "outside");
        assert.equal(readVerifierBytes("evidence.jsonl", true).toString(), "inside");
      } finally {
        rmSync(root);
        renameSync(moved, root);
      }
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("directory child read refuses a symlink", async () => {
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-pinned-link-"));
  const root = join(base, "root");
  mkdirSync(root);
  writeFileSync(join(base, "outside"), "outside");
  try {
    symlinkSync(join(base, "outside"), join(root, "evidence.jsonl"));
  } catch {
    rmSync(base, { recursive: true, force: true });
    return;
  }
  try {
    await withPinnedEvidenceDirectory(root, async () => {
      assert.throws(() => readVerifierBytes("evidence.jsonl", true), /refuse symlink/u);
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

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
import { join, sep } from "node:path";
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

test("relative parent and repeated parent steps retain the selected directory", async () => {
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-pinned-relative-"));
  const child = join(base, "child");
  mkdirSync(child);
  writeFileSync(join(base, "evidence.jsonl"), "inside");
  const original = process.cwd();
  try {
    process.chdir(child);
    for (const requested of ["..", `..${sep}child${sep}..`]) {
      const result = await withPinnedEvidenceDirectory(requested, async () =>
        readVerifierBytes("evidence.jsonl", true).toString(),
      );
      assert.equal(result, "inside");
    }
  } finally {
    process.chdir(original);
    rmSync(base, { recursive: true, force: true });
  }
});

test("parent step refuses a child relocated to another parent", async (t) => {
  if (process.platform === "win32") {
    t.skip("Windows prevents renaming a process working directory");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-pinned-parent-"));
  const selected = join(base, "selected");
  const alternate = join(base, "alternate");
  const child = join(selected, "child");
  const moved = join(alternate, "child");
  mkdirSync(selected);
  mkdirSync(alternate);
  mkdirSync(child);
  mkdirSync(join(selected, "evidence"));
  mkdirSync(join(alternate, "evidence"));
  writeFileSync(join(selected, "evidence", "evidence.jsonl"), "inside");
  writeFileSync(join(alternate, "evidence", "evidence.jsonl"), "outside");
  const requested = `${child}${sep}..${sep}evidence`;
  const originalChdir = process.chdir;
  try {
    const ordinary = await withPinnedEvidenceDirectory(requested, async () =>
      readVerifierBytes("evidence.jsonl", true).toString(),
    );
    assert.equal(ordinary, "inside");
    let relocated = false;
    process.chdir = (directory: string) => {
      if (directory === ".." && !relocated) {
        renameSync(child, moved);
        relocated = true;
      }
      originalChdir(directory);
    };
    await assert.rejects(
      withPinnedEvidenceDirectory(requested, async () =>
        readVerifierBytes("evidence.jsonl", true).toString(),
      ),
      /parent changed while entering/u,
    );
    assert.equal(relocated, true);
  } finally {
    process.chdir = originalChdir;
    rmSync(base, { recursive: true, force: true });
  }
});

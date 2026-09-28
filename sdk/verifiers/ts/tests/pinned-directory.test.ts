// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import test from "node:test";
import { withPinnedEvidenceDirectory, withPinnedEvidenceDirectorySync } from "../src/chain-set.js";
import { extractReceiptsFromSessionDir } from "../src/recorder.js";
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

test("directory entry refuses a component moved after it was entered", async (t) => {
  if (process.platform === "win32") {
    t.skip("Windows prevents renaming a process working directory");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-entry-rename-"));
  const root = join(base, "root");
  const moved = join(base, "moved");
  const outside = join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  writeFileSync(join(root, "evidence.jsonl"), "inside");
  writeFileSync(join(outside, "evidence.jsonl"), "outside");
  const originalChdir = process.chdir;
  let swapped = false;
  try {
    process.chdir = ((directory: string) => {
      originalChdir(directory);
      if (directory === "root") {
        renameSync(root, moved);
        symlinkSync(outside, root, "dir");
        swapped = true;
      }
    }) as typeof process.chdir;
    await assert.rejects(
      withPinnedEvidenceDirectory(root, async () => readVerifierBytes("evidence.jsonl", true)),
      /component changed while entering/u,
    );
    assert.equal(swapped, true, "the root replacement must occur during entry");
  } finally {
    process.chdir = originalChdir;
    if (existsSync(moved)) {
      rmSync(root, { force: true });
      renameSync(moved, root);
    }
    rmSync(base, { recursive: true, force: true });
  }
});

test("directory child read refuses a symlink", async (t) => {
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-pinned-link-"));
  const root = join(base, "root");
  mkdirSync(root);
  writeFileSync(join(base, "outside"), "outside");
  try {
    symlinkSync(join(base, "outside"), join(root, "evidence.jsonl"), "file");
  } catch (err) {
    rmSync(base, { recursive: true, force: true });
    const code = (err as NodeJS.ErrnoException).code;
    if (process.platform === "win32" && (code === "EPERM" || code === "EACCES")) {
      t.skip("file symlinks unavailable");
      return;
    }
    throw err;
  }
  try {
    await withPinnedEvidenceDirectory(root, async () => {
      assert.throws(() => readVerifierBytes("evidence.jsonl", true), /refuse symlink/u);
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("directory reads through a search-only ancestor", async (t) => {
  if (process.platform === "win32" || process.getuid?.() === 0) {
    t.skip("requires Unix directory permissions for a non-root user");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-search-only-"));
  const ancestor = join(base, "search-only");
  const root = join(ancestor, "evidence");
  mkdirSync(ancestor);
  mkdirSync(root);
  writeFileSync(join(root, "evidence.jsonl"), "inside");
  chmodSync(ancestor, 0o111);
  try {
    const result = await withPinnedEvidenceDirectory(root, async () =>
      readVerifierBytes("evidence.jsonl", true).toString(),
    );
    assert.equal(result, "inside");
  } finally {
    chmodSync(ancestor, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
});

test("directory entry accepts the filesystem's case-insensitive spelling", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("case-insensitive macOS volume required");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-case-alias-"));
  const canonical = join(base, "Evidence");
  const alias = join(base, "evidence");
  mkdirSync(canonical);
  writeFileSync(join(canonical, "evidence.jsonl"), "inside");
  try {
    const canonicalID = statSync(canonical, { bigint: true });
    const aliasID = existsSync(alias) ? statSync(alias, { bigint: true }) : undefined;
    if (!aliasID || aliasID.dev !== canonicalID.dev || aliasID.ino !== canonicalID.ino) {
      assert.notEqual(
        process.env.PIPELOCK_REQUIRE_CASE_ALIAS,
        "1",
        "macOS CI must exercise a case-insensitive directory alias",
      );
      t.skip("temporary volume is case-sensitive");
      return;
    }
    assert.equal(
      await withPinnedEvidenceDirectory(alias, async () =>
        readVerifierBytes("evidence.jsonl", true).toString(),
      ),
      "inside",
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("directory entry keeps distinct names distinct on a case-sensitive volume", async (t) => {
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-case-distinct-"));
  const upper = join(base, "Evidence");
  const lower = join(base, "evidence");
  mkdirSync(upper);
  try {
    mkdirSync(lower);
  } catch {
    rmSync(base, { recursive: true, force: true });
    t.skip("temporary volume is case-insensitive");
    return;
  }
  writeFileSync(join(upper, "evidence.jsonl"), "upper");
  writeFileSync(join(lower, "evidence.jsonl"), "lower");
  try {
    assert.equal(
      await withPinnedEvidenceDirectory(lower, async () =>
        readVerifierBytes("evidence.jsonl", true).toString(),
      ),
      "lower",
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("synchronous receipt extraction refuses a root moved during entry", (t) => {
  if (process.platform === "win32") {
    t.skip("Windows prevents renaming a process working directory");
    return;
  }
  const base = mkdtempSync(join(realpathSync(tmpdir()), "verifier-sync-pinned-"));
  const selected = join(base, "selected");
  const moved = join(base, "moved");
  const outside = join(base, "outside");
  mkdirSync(selected);
  mkdirSync(outside);
  writeFileSync(join(selected, "evidence-proxy-0.jsonl"), "");
  writeFileSync(join(outside, "evidence-proxy-0.jsonl"), "not-json\n");
  const originalChdir = process.chdir;
  let swapped = false;
  try {
    process.chdir = ((directory: string) => {
      originalChdir(directory);
      if (directory === "selected") {
        renameSync(selected, moved);
        symlinkSync(outside, selected, "dir");
        swapped = true;
      }
    }) as typeof process.chdir;
    assert.throws(
      () => extractReceiptsFromSessionDir(selected, "proxy"),
      /component changed while entering/u,
    );
    assert.equal(swapped, true, "the root replacement must occur during the read");
    assert.equal(readFileSync(join(selected, "evidence-proxy-0.jsonl"), "utf8"), "not-json\n");
  } finally {
    process.chdir = originalChdir;
    if (existsSync(moved)) {
      rmSync(selected, { force: true });
      renameSync(moved, selected);
    }
    rmSync(base, { recursive: true, force: true });
  }
});

test("failed cwd lookup does not leave directory pinning active", (t) => {
  if (process.platform === "win32") {
    t.skip("Windows prevents removing a process working directory");
    return;
  }
  const original = process.cwd();
  const removed = mkdtempSync(join(realpathSync(tmpdir()), "verifier-deleted-cwd-"));
  try {
    process.chdir(removed);
    rmdirSync(removed);
    for (let attempt = 0; attempt < 2; attempt++) {
      assert.throws(
        () => withPinnedEvidenceDirectorySync(original, () => undefined),
        (err: unknown) =>
          (err as NodeJS.ErrnoException).code === "ENOENT" &&
          !String(err).includes("concurrent evidence directory reads"),
      );
    }
  } finally {
    process.chdir(original);
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

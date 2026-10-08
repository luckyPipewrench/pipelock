// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { gunzipSync, inflateRawSync } from "node:zlib";
import test from "node:test";
import assert from "node:assert/strict";
import {
  checkGroupAELMembership,
  duplicateSignedAELRunError,
  readBoundedArtifactBytes,
  verifyReceiptGroup,
} from "../src/group.js";
import { parseEvidenceFilename } from "../src/chain-set.js";
import { findPackageRoot } from "./paths.js";

const root = findPackageRoot(import.meta.url);
const fixtureRoot = mkdtempSync(join(tmpdir(), "ts-receipt-group-fixtures-"));
const fixtures = join(fixtureRoot, "groups");
const attackFixtures = join(fixtureRoot, "attacks");
const matrixFixtures = join(fixtureRoot, "matrix");
const v2Fixtures = join(fixtureRoot, "v2");
const filenameVectors = JSON.parse(
  readFileSync(resolve(root, "../filename-vectors.json"), "utf8"),
) as {
  parse: Array<{ name: string; session: string | null; seq: number | null }>;
  duplicate: string[];
};
test("shared filename vectors", () => {
  for (const item of filenameVectors.parse) {
    const parsed = parseEvidenceFilename(item.name);
    assert.equal(parsed?.session ?? null, item.session, item.name);
    assert.equal(parsed?.seqStart ?? null, item.seq === null ? null : BigInt(item.seq), item.name);
  }
  const first = parseEvidenceFilename(filenameVectors.duplicate[0] as string);
  const second = parseEvidenceFilename(filenameVectors.duplicate[1] as string);
  assert.ok(
    first && second && first.session === second.session && first.seqStart === second.seqStart,
  );
});
test("shared signed shard AEL membership vectors", () => {
  const cases = JSON.parse(
    readFileSync(resolve(root, "../receipt-group-membership-vectors.json"), "utf8"),
  ) as Array<{
    name: string;
    signed_sessions: string[];
    claimed_sessions: string[];
    incomplete: boolean;
    error: string;
  }>;
  assert.equal(cases.length, 5);
  for (const item of cases) {
    if (item.error) {
      assert.throws(
        () => checkGroupAELMembership(item.signed_sessions, item.claimed_sessions, item.incomplete),
        (error: unknown) => error instanceof Error && error.message.includes(item.error),
        item.name,
      );
    } else {
      assert.doesNotThrow(
        () => checkGroupAELMembership(item.signed_sessions, item.claimed_sessions, item.incomplete),
        item.name,
      );
    }
  }
});
test("shared AEL stream and duplicate-run vectors", () => {
  const vectors = JSON.parse(
    readFileSync(resolve(root, "../receipt-group-stream-vectors.json"), "utf8"),
  ) as {
    bounded_stream: Array<{
      name: string;
      initial_size: number;
      limit: number;
      data: string;
      error: string;
    }>;
    duplicate_run: { run: string; error: string };
  };
  for (const item of vectors.bounded_stream) {
    const source = Buffer.from(item.data);
    const readAt = (buffer: Buffer, offset: number, length: number, position: number): number => {
      const copied = source.copy(buffer, offset, position, position + length);
      return copied;
    };
    if (item.error) {
      assert.throws(
        () => readBoundedArtifactBytes(item.name, item.initial_size, item.limit, readAt),
        (error: unknown) => error instanceof Error && error.message.includes(item.error),
        item.name,
      );
    } else {
      assert.deepEqual(
        readBoundedArtifactBytes(item.name, item.initial_size, item.limit, readAt),
        source,
        item.name,
      );
    }
  }
  assert.match(
    duplicateSignedAELRunError(vectors.duplicate_run.run).message,
    /duplicate signed native AEL run/u,
  );
  assert.ok(
    duplicateSignedAELRunError(vectors.duplicate_run.run).message.includes(
      vectors.duplicate_run.error,
    ),
  );
});
extractFixtureArchive(readFileSync(resolve(root, "tests/fixtures/receipt-groups.zip")), fixtures);
extractFixtureArchive(
  Buffer.concat(
    Array.from({ length: 7 }, (_, index) =>
      readFileSync(
        resolve(
          root,
          `../fixtures/receipt-groups-attacks.zip.part${String(index).padStart(2, "0")}`,
        ),
      ),
    ),
  ),
  attackFixtures,
);
extractFixtureArchive(
  gunzipSync(readFileSync(resolve(root, "tests/fixtures/receipt-groups-matrix.zip.gz"))),
  matrixFixtures,
);
extractFixtureArchive(
  readFileSync(resolve(root, "tests/fixtures/receipt-groups-v2.zip")),
  v2Fixtures,
);
test.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

test("shared native AEL matrix", async () => {
  const cases = JSON.parse(readFileSync(join(matrixFixtures, "matrix.json"), "utf8")) as Array<{
    name: string;
    group_id: string;
    trusted_keys: string[];
    expected: string;
  }>;
  assert.equal(cases.length, 119);
  const controls = JSON.parse(
    readFileSync(join(matrixFixtures, "controls.json"), "utf8"),
  ) as typeof cases;
  assert.equal(controls.length, 1);
  for (const [prefix, entries] of [
    ["cases", cases],
    ["controls", controls],
  ] as const) {
    for (const item of entries) {
      const result = await verifyReceiptGroup(
        join(matrixFixtures, prefix, item.name),
        item.group_id,
        item.trusted_keys,
      );
      assert.equal(result.verdict, item.expected, `${item.name}: ${JSON.stringify(result)}`);
      if (item.name === "predecessor__signed-close-head-disagrees")
        assert.match(result.error ?? "", /signed close/u);
      if (item.name === "predecessor__intact__present")
        assert.match(result.error ?? "", /GROUP_INCOMPLETE/u);
    }
  }
});

test("torn gated shard without opening cannot fall back to legacy directory verification", () => {
  const dir = join(matrixFixtures, "cases", "shard__torn-gate-missing-open");
  const result = runCLI(["chain", dir, "--dir", "--json"]);
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout) as { error?: string };
  assert.match(report.error ?? "", /GROUP_INVALID/u);
});

function extractFixtureArchive(archive: Buffer, destination: string): void {
  const eocd = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.notEqual(eocd, -1, "fixture ZIP has an end record");
  const count = archive.readUInt16LE(eocd + 10),
    directoryOffset = archive.readUInt32LE(eocd + 16);
  let offset = directoryOffset;
  for (let i = 0; i < count; i++) {
    assert.equal(archive.readUInt32LE(offset), 0x02014b50, "fixture ZIP central directory entry");
    const method = archive.readUInt16LE(offset + 10),
      compressedSize = archive.readUInt32LE(offset + 20),
      uncompressedSize = archive.readUInt32LE(offset + 24),
      nameLength = archive.readUInt16LE(offset + 28),
      extraLength = archive.readUInt16LE(offset + 30),
      commentLength = archive.readUInt16LE(offset + 32),
      localOffset = archive.readUInt32LE(offset + 42),
      name = archive.toString("utf8", offset + 46, offset + 46 + nameLength);
    offset += 46 + nameLength + extraLength + commentLength;
    assert.ok(name && !name.startsWith("/") && !name.split("/").includes(".."));
    const target = resolve(destination, name);
    assert.ok(target.startsWith(`${resolve(destination)}/`));
    if (name.endsWith("/")) {
      mkdirSync(target, { recursive: true });
      continue;
    }
    const localNameLength = archive.readUInt16LE(localOffset + 26),
      localExtraLength = archive.readUInt16LE(localOffset + 28),
      dataOffset = localOffset + 30 + localNameLength + localExtraLength,
      compressed = archive.subarray(dataOffset, dataOffset + compressedSize),
      data = method === 0 ? compressed : method === 8 ? inflateRawSync(compressed) : undefined;
    assert.ok(data, `unsupported ZIP compression method ${method}`);
    assert.equal(data.length, uncompressedSize, `fixture size differs for ${name}`);
    mkdirSync(resolve(target, ".."), { recursive: true });
    writeFileSync(target, data);
  }
}
function groupID(dir: string): string {
  const names = readdirSync(dir).filter((n) => /^receipt-group-[0-9a-f]{32}-open\.json$/u.test(n));
  const successor = names.find((n) => {
    const id = n.slice("receipt-group-".length, -"-open.json".length);
    return existsSync(join(dir, `receipt-group-${id}-transition.json`));
  });
  const name =
    successor ??
    names.find((n) => existsSync(join(dir, n.replace("-open.json", "-close.json")))) ??
    names[0];
  assert.ok(name);
  return name.slice("receipt-group-".length, -"-open.json".length);
}
function keys(dir: string): string[] {
  return (JSON.parse(readFileSync(join(dir, "trust.json"), "utf8")) as { trusted_keys: string[] })
    .trusted_keys;
}
function runCLI(args: string[]): {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
} {
  const result = spawnSync(process.execPath, [resolve(root, "dist/src/cli.js"), ...args], {
    encoding: "utf8",
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    error: result.error,
  };
}

test("Go-produced initial, successor, and recovery-successor groups verify", async () => {
  const cases = ["group-valid", "group-successor", "group-recovery-successor"];
  for (const name of cases) {
    const dir = join(fixtures, name),
      id = groupID(dir),
      report = await verifyReceiptGroup(dir, id, keys(dir));
    assert.equal(report.verdict, "GROUP_VALID", `${name}: ${JSON.stringify(report)}`);
  }
});

test("shared attack vectors reject both ends of a forged transition", async () => {
  for (const name of ["forged-untrusted", "flipped-signature", "lying-chain-head"]) {
    const dir = join(attackFixtures, name),
      successor = groupID(dir),
      predecessor = readdirSync(dir)
        .filter((file) => /^receipt-group-[0-9a-f]{32}-open\.json$/u.test(file))
        .map((file) => file.slice("receipt-group-".length, -"-open.json".length))
        .find((id) => id !== successor);
    assert.ok(predecessor);
    for (const id of [predecessor, successor]) {
      const report = await verifyReceiptGroup(dir, id, keys(dir));
      assert.equal(report.verdict, "GROUP_INVALID", `${name} ${id}: ${JSON.stringify(report)}`);
    }
  }
  for (const name of ["extra-unowned-ael", "empty-unowned-ael"]) {
    const dir = join(attackFixtures, name),
      report = await verifyReceiptGroup(dir, groupID(dir), keys(dir));
    assert.equal(report.verdict, "GROUP_INVALID");
    assert.match(report.error ?? "", /no signed session owner/u);
  }
  for (const name of [
    "self-signed-owner",
    "damaged-recorder-owner",
    "damaged-recorder-trusted-owner",
    "damaged-legacy-ael",
    "damaged-neighbor-ael",
    "missing-legacy-ael",
    "missing-neighbor-ael",
    "damaged-legacy-incomplete",
  ]) {
    const dir = join(attackFixtures, name),
      report = await verifyReceiptGroup(dir, groupID(dir), keys(dir));
    assert.equal(report.verdict, "GROUP_INVALID", `${name}: ${JSON.stringify(report)}`);
  }
  for (const scenario of ["damaged-neighbor-ael", "missing-neighbor-ael"]) {
    const neighbor = join(attackFixtures, scenario);
    for (const id of readdirSync(neighbor)
      .filter((name) => /^receipt-group-[0-9a-f]{32}-open\.json$/u.test(name))
      .map((name) => name.slice("receipt-group-".length, -"-open.json".length))) {
      const report = await verifyReceiptGroup(neighbor, id, keys(neighbor));
      assert.equal(report.verdict, "GROUP_INVALID", `${scenario}/${id}: ${JSON.stringify(report)}`);
    }
  }
  const legacy = join(attackFixtures, "trusted-legacy-owner");
  assert.equal(
    (await verifyReceiptGroup(legacy, groupID(legacy), keys(legacy))).verdict,
    "GROUP_VALID",
  );
  const large = join(attackFixtures, "large-legacy-ael");
  assert.equal(
    (await verifyReceiptGroup(large, groupID(large), keys(large))).verdict,
    "GROUP_VALID",
  );
});

test("recovery seal survives a successor shard count change", async () => {
  const dir = join(attackFixtures, "recovery-count-change"),
    report = await verifyReceiptGroup(dir, groupID(dir), keys(dir));
  assert.equal(report.verdict, "GROUP_VALID", JSON.stringify(report));
  assert.equal(report.shard_count, 3);
});

test("shared duplicate successors invalidate every linked group", async () => {
  const dir = join(attackFixtures, "duplicate-successor"),
    ids = readdirSync(dir)
      .filter((name) => /^receipt-group-[0-9a-f]{32}-open\.json$/u.test(name))
      .map((name) => name.slice("receipt-group-".length, -"-open.json".length));
  assert.equal(ids.length, 3);
  for (const id of ids) {
    const report = await verifyReceiptGroup(dir, id, keys(dir));
    assert.equal(report.verdict, "GROUP_INVALID", `${id}: ${JSON.stringify(report)}`);
  }
});

test("group verification fails closed for missing close, deleted shard, tampered AEL, and unpinned signer", async () => {
  const base = join(fixtures, "group-valid"),
    id = groupID(base),
    trusted = keys(base);
  const temp = mkdtempSync(join(tmpdir(), "ts-receipt-group-"));
  try {
    const incomplete = join(temp, "incomplete");
    cpSync(base, incomplete, { recursive: true });
    rmSync(join(incomplete, `receipt-group-${id}-close.json`));
    assert.equal((await verifyReceiptGroup(incomplete, id, trusted)).verdict, "GROUP_INCOMPLETE");

    const missing = join(temp, "missing");
    cpSync(base, missing, { recursive: true });
    const shard = readdirSync(missing).find(
      (n) => n.startsWith("evidence-") && n.endsWith(".jsonl"),
    );
    assert.ok(shard);
    rmSync(join(missing, shard));
    assert.equal((await verifyReceiptGroup(missing, id, trusted)).verdict, "GROUP_INVALID");

    const ael = join(temp, "ael");
    cpSync(base, ael, { recursive: true });
    const runDir = readdirSync(join(ael, "ael"))[0];
    assert.ok(runDir);
    const stream = join(ael, "ael", runDir, "recorders", "pipelock.jsonl");
    writeFileSync(stream, `${readFileSync(stream, "utf8")}tamper\n`);
    assert.equal((await verifyReceiptGroup(ael, id, trusted)).verdict, "GROUP_INVALID");
    assert.equal((await verifyReceiptGroup(base, id, [])).verdict, "GROUP_INVALID");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("recovery group fails closed when its seal is missing, altered, or transition is forged", async () => {
  const base = join(fixtures, "group-recovery-successor"),
    id = groupID(base),
    trusted = keys(base);
  const transition = JSON.parse(
    readFileSync(join(base, `receipt-group-${id}-transition.json`), "utf8"),
  ) as { predecessors: { session_id: string; recovery_seal_sha256: string }[] };
  const sealClaim = transition.predecessors.find((p) => p.recovery_seal_sha256 !== "");
  assert.ok(sealClaim);
  const temp = mkdtempSync(join(tmpdir(), "ts-receipt-group-recovery-"));
  try {
    const missing = join(temp, "missing");
    cpSync(base, missing, { recursive: true });
    rmSync(join(missing, `chain-link-${sealClaim.session_id}.json`));
    assert.equal((await verifyReceiptGroup(missing, id, trusted)).verdict, "GROUP_INVALID");

    const altered = join(temp, "altered");
    cpSync(base, altered, { recursive: true });
    const sealPath = join(altered, `chain-link-${sealClaim.session_id}.json`);
    writeFileSync(
      sealPath,
      readFileSync(sealPath, "utf8").replace('"damage_offset":3808', '"damage_offset":3807'),
    );
    assert.equal((await verifyReceiptGroup(altered, id, trusted)).verdict, "GROUP_INVALID");

    const damaged = join(temp, "damaged");
    cpSync(base, damaged, { recursive: true });
    const damagedShard = join(damaged, `evidence-${sealClaim.session_id}-0.jsonl`);
    writeFileSync(damagedShard, `${readFileSync(damagedShard, "utf8")}changed\n`);
    assert.equal((await verifyReceiptGroup(damaged, id, trusted)).verdict, "GROUP_INVALID");

    const forged = join(temp, "forged");
    cpSync(base, forged, { recursive: true });
    const path = join(forged, `receipt-group-${id}-transition.json`);
    const raw = readFileSync(path, "utf8").replace('"final_chain_seq":0', '"final_chain_seq":1');
    writeFileSync(path, raw);
    assert.equal((await verifyReceiptGroup(forged, id, trusted)).verdict, "GROUP_INVALID");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("CLI group mode prints the group verdict and exits nonzero when incomplete", () => {
  const dir = join(fixtures, "group-valid"),
    id = groupID(dir),
    key = keys(dir)[0];
  assert.ok(key);
  const valid = runCLI(["chain", dir, "--dir", "--group", id, "--key", key, "--json"]);
  assert.equal(valid.status, 0, `${valid.stdout}\n${valid.stderr}\n${String(valid.error)}`);
  assert.equal((JSON.parse(valid.stdout) as { verdict: string }).verdict, "GROUP_VALID");
  const temp = mkdtempSync(join(tmpdir(), "ts-receipt-group-cli-"));
  try {
    const incomplete = join(temp, "incomplete");
    cpSync(dir, incomplete, { recursive: true });
    rmSync(join(incomplete, `receipt-group-${id}-close.json`));
    const result = runCLI(["chain", incomplete, "--dir", "--group", id, "--key", key, "--json"]);
    assert.equal(result.status, 1, `${result.stdout}\n${result.stderr}\n${String(result.error)}`);
    assert.ok(result.stdout, result.stderr);
    assert.equal((JSON.parse(result.stdout) as { verdict: string }).verdict, "GROUP_INCOMPLETE");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

interface MutationOp {
  file: string;
  op: string;
  arg?: string;
}
interface MutationVector {
  name: string;
  case: string;
  note: string;
  ops: MutationOp[];
  expected: string;
  error_contains?: string;
  group_id: string;
  trusted_keys: string[];
}
function applyMutation(dir: string, op: MutationOp): void {
  const target = join(dir, op.file);
  if (op.op === "create") return writeFileSync(target, op.arg ?? "");
  if (op.op === "delete") return rmSync(target);
  const bytes = readFileSync(target);
  let next: Buffer;
  switch (op.op) {
    case "append":
      next = Buffer.concat([bytes, Buffer.from(op.arg ?? "", "hex")]);
      break;
    case "bom":
      next = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes]);
      break;
    case "empty":
      next = Buffer.alloc(0);
      break;
    case "strip_final_newline":
      assert.equal(bytes[bytes.length - 1], 0x0a);
      next = bytes.subarray(0, bytes.length - 1);
      break;
    case "truncate_half":
      next = bytes.subarray(0, Math.floor(bytes.length / 2));
      break;
    case "drop_last_line": {
      const lines = bytes.toString("utf8").replace(/\n+$/u, "").split("\n");
      next = Buffer.from(`${lines.slice(0, -1).join("\n")}\n`);
      break;
    }
    default:
      assert.fail(`unknown mutation ${op.op}`);
  }
  writeFileSync(target, next);
}

// Every verdict in the vector file was produced by the Go CLI on the same
// mutated directory, so this pins TS to Go for torn tails, BOMs, emptied
// segments, deleted transitions and unknown artifacts.
test("shared mutation vectors match the Go verdict", async () => {
  const vectors = JSON.parse(
    readFileSync(resolve(root, "../receipt-group-mutation-vectors.json"), "utf8"),
  ) as MutationVector[];
  assert.equal(vectors.length, 25);
  const temp = mkdtempSync(join(tmpdir(), "ts-receipt-group-mutation-"));
  try {
    for (const item of vectors) {
      const dir = join(temp, item.name);
      cpSync(join(matrixFixtures, "cases", item.case), dir, { recursive: true });
      for (const op of item.ops) applyMutation(dir, op);
      const result = await verifyReceiptGroup(dir, item.group_id, item.trusted_keys);
      assert.equal(result.verdict, item.expected, `${item.name}: ${JSON.stringify(result)}`);
      assert.doesNotMatch(result.error ?? "", /ENOENT/u, item.name);
      if (item.error_contains) assert.ok(result.error?.includes(item.error_contains), item.name);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("a group shard file is not a skippable receipt chain outside group mode", () => {
  const dir = join(matrixFixtures, "cases", "shard__intact__present");
  const shard = "evidence-proxy.run.1806d08396effa4a8f31e45aa8165c84-0.jsonl";
  const trusted = (
    JSON.parse(readFileSync(join(dir, "trust.json"), "utf8")) as { trusted_keys: string[] }
  ).trusted_keys[0] as string;
  const single = runCLI(["chain", join(dir, shard), "--key", trusted]);
  assert.notEqual(single.status, 0, `${single.stdout}\n${single.stderr}`);
  assert.doesNotMatch(single.stdout, /CHAIN VALID/u);
  const asDir = runCLI(["chain", dir, "--dir", "--key", trusted]);
  assert.notEqual(asDir.status, 0, `${asDir.stdout}\n${asDir.stderr}`);
});

// Legacy directory and single-file verification keep their origin/main
// behavior: an unterminated final fragment is a failure, never silently dropped.
test("legacy chain --dir and single-file verification reject a torn final fragment", () => {
  const parity = resolve(root, "../../conformance/testdata/parity/rotated");
  const keyHex = readFileSync(join(parity, "signer-key.hex"), "utf8").trim();
  const shard = "evidence-proxy.run.da660e29de374fd065cf1a12b3abde7b-0.jsonl";
  const temp = mkdtempSync(join(tmpdir(), "ts-legacy-torn-"));
  try {
    const intact = join(temp, "intact");
    cpSync(parity, intact, { recursive: true });
    const args = (target: string, dir: boolean): string[] => [
      "chain",
      target,
      ...(dir ? ["--dir"] : []),
      "--key",
      keyHex,
      "--rotation-endorsement",
      join(intact, "rotation-endorsement.json"),
    ];
    const ok = runCLI(args(intact, true));
    assert.equal(ok.status, 0, `${ok.stdout}\n${ok.stderr}`);
    const torn = join(temp, "torn");
    cpSync(parity, torn, { recursive: true });
    writeFileSync(join(torn, shard), `${readFileSync(join(torn, shard), "utf8")}{"torn":`);
    const dirResult = runCLI(args(torn, true));
    assert.equal(dirResult.status, 1, `${dirResult.stdout}\n${dirResult.stderr}`);
    assert.match(dirResult.stdout, /result:\s+INVALID/u);
    const fileResult = runCLI(args(join(torn, shard), false));
    assert.notEqual(fileResult.status, 0, `${fileResult.stdout}\n${fileResult.stderr}`);
    assert.doesNotMatch(fileResult.stdout, /CHAIN VALID/u);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("leading BOM is rejected by the strict UTF-8 decoder", async () => {
  const { decodeUTF8 } = await import("../src/util.js");
  assert.throws(
    () => JSON.parse(decodeUTF8(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), "x")),
    SyntaxError,
  );
  assert.equal(decodeUTF8(Buffer.from("{}"), "x"), "{}");
});

// A closed group whose two shards both sign a session_open for one native AEL
// run. The fixture is Go-produced; Go, TS, Rust and Python all report the
// duplicate-run error. Asserting the message (not just INVALID) makes the test
// fail if the guard is removed, because the orphaned second run would then be
// reported as "no signed session owner" instead.
test("duplicate signed native AEL run is rejected end to end", async () => {
  const dir = join(fixtureRoot, "duplicate-run");
  extractFixtureArchive(
    readFileSync(resolve(root, "../fixtures/receipt-group-duplicate-ael-run.zip")),
    dir,
  );
  const group = join(dir, "duplicate-ael-run");
  const trust = JSON.parse(readFileSync(join(group, "trust.json"), "utf8")) as {
    group_id: string;
    trusted_keys: string[];
  };
  const result = await verifyReceiptGroup(group, trust.group_id, trust.trusted_keys);
  assert.equal(result.verdict, "GROUP_INVALID", JSON.stringify(result));
  assert.match(result.error ?? "", /duplicate signed native AEL run "[0-9a-f]{32}"/u);
});

// The production shape: groups written by the real server emitter path, with a
// v2 evidence receipt on every shard, a transition from a closed, crashed or
// torn-and-sealed predecessor, and tamper cases whose recorder hash chain (and
// checkpoint, seal and transition signatures) were recomputed, so only the
// signed content is wrong. Every verdict is the Go verifier's own.
test("shared v2 group corpus matches the Go verdict", async () => {
  const cases = JSON.parse(readFileSync(join(v2Fixtures, "cases.json"), "utf8")) as Array<{
    name: string;
    group_id: string;
    trusted_keys: string[];
    expected: string;
  }>;
  assert.equal(cases.length, 35);
  for (const item of cases) {
    const result = await verifyReceiptGroup(
      join(v2Fixtures, "cases", item.name),
      item.group_id,
      item.trusted_keys,
    );
    assert.equal(result.verdict, item.expected, `${item.name}: ${JSON.stringify(result)}`);
  }
});

// A live writer holds a shared flock on its run's lifetime lock. Linking a
// crashed predecessor (unsealed or sealed) needs that lock gone: a held lock is
// a still-growing chain, so verification must refuse it until the writer exits.
// Node cannot take an flock itself, so a child process plays the writer.
test(
  "a predecessor whose writer lock is held is invalid until the writer exits",
  { skip: process.platform !== "linux" || spawnSync("python3", ["--version"]).status !== 0 },
  async () => {
    const cases = JSON.parse(readFileSync(join(v2Fixtures, "cases.json"), "utf8")) as Array<{
      name: string;
      group_id: string;
      trusted_keys: string[];
    }>;
    for (const name of ["v2-successor-unsealed-predecessor", "v2-successor-sealed-predecessor"]) {
      const item = cases.find((c) => c.name === name);
      assert.ok(item, name);
      const dir = join(v2Fixtures, "cases", name);
      const locks = readdirSync(dir)
        .filter((f) => f.startsWith("writer-") && f.endsWith(".lock"))
        .map((f) => join(dir, f));
      assert.ok(locks.length > 0, name);
      const free = await verifyReceiptGroup(dir, item.group_id, item.trusted_keys);
      assert.equal(free.verdict, "GROUP_VALID", `${name}: ${JSON.stringify(free)}`);
      const writer = spawn(
        "python3",
        [
          "-c",
          "import fcntl,sys\nfs=[open(p) for p in sys.argv[1:]]\n[fcntl.flock(f,fcntl.LOCK_SH) for f in fs]\nprint('held',flush=True)\nsys.stdin.read()",
          ...locks,
        ],
        { stdio: ["pipe", "pipe", "inherit"] },
      );
      try {
        await new Promise<void>((resolveHeld, reject) => {
          writer.once("error", reject);
          writer.stdout.once("data", () => resolveHeld());
        });
        const blocked = await verifyReceiptGroup(dir, item.group_id, item.trusted_keys);
        assert.equal(blocked.verdict, "GROUP_INVALID", `${name}: ${JSON.stringify(blocked)}`);
        assert.match(blocked.error ?? "", /writer still present/u);
      } finally {
        const exited = new Promise((resolveExit) => writer.once("exit", resolveExit));
        writer.stdin.end();
        await exited;
      }
      const released = await verifyReceiptGroup(dir, item.group_id, item.trusted_keys);
      assert.equal(released.verdict, "GROUP_VALID", `${name}: ${JSON.stringify(released)}`);
    }
  },
);

// Go reads only the python copy of the shared fixtures, so a drifted copy in
// another language directory would silently test different bytes.
test("shared group fixtures are byte-identical across language directories", () => {
  const sha = (file: string): string =>
    createHash("sha256")
      .update(readFileSync(resolve(root, file)))
      .digest("hex");
  for (const name of [
    "receipt-groups-matrix.zip.gz",
    "receipt-groups.zip",
    "receipt-groups-v2.zip",
  ]) {
    const reference = sha(`../python/tests/fixtures/${name}`);
    for (const language of ["ts", "rust", "python"]) {
      assert.equal(sha(`../${language}/tests/fixtures/${name}`), reference, `${language}/${name}`);
    }
  }
});

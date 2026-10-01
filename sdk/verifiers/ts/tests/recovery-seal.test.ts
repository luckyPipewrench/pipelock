// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as ed25519 from "@noble/ed25519";
import { receiptHash } from "../src/chain.js";
import { canonicalizeActionRecord } from "../src/canonical.js";
import type { Receipt } from "../src/types.js";
import { RawNumber, parseJSONStrict } from "../src/aarp/strictjson.js";
import {
  baseHealthy,
  baseUnlinked,
  decodeChainLink,
  decodeRecoverySeal,
  recoverySealSigningBytes,
  verifyBase,
  verifyRecoveryOuterSequence,
  type RecoverySeal,
} from "../src/chain-set.js";
import { extractTypedFromEntries, parseEntryLinesText } from "../src/recorder.js";
import { recorderEntryHash } from "../src/recorder-chain.js";
import { decodeUTF8, sha256Hex } from "../src/util.js";
import { findPackageRoot } from "./paths.js";

const zeroKey = "00".repeat(32);
const sealObject = {
  kind: "recovery_seal",
  version: 1,
  predecessor_session: "proxy.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  shard: "evidence-proxy.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0.jsonl",
  shard_size: 3,
  shard_sha256: "11".repeat(32),
  damage_offset: 1,
  last_good_seq: 0,
  last_good_hash: "genesis",
  predecessor_tail_seq: 0,
  predecessor_tail_hash: "genesis",
  predecessor_signer_key: zeroKey,
  successor_session: "proxy.run.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  successor_signer_key: zeroKey,
  successor_open_hash: "22".repeat(32),
  observed_at: "2026-10-01T12:00:00Z",
  signature: `ed25519:${"00".repeat(64)}`,
};
const sealJSON = JSON.stringify(sealObject);

test("recovery seal v1 decoder accepts the exact schema", () => {
  const decoded = decodeRecoverySeal(sealJSON);
  assert.equal(decoded.kind, "recovery_seal");
  assert.equal(decoded.version, 1);
  assert.equal(decoded.shard_size, 3);
  assert.equal(decoded.damage_offset, 1);
});

test("recovery seal decoder rejects aliases, unknown fields, duplicates, and trailing data", () => {
  const cases: [string, RegExp][] = [
    [sealJSON.replace('"version":1', '"Version":1'), /alias/u],
    [JSON.stringify({ ...sealObject, extra: true }), /unknown field/u],
    [sealJSON.replace("{", '{"kind":"recovery_seal",'), /duplicate/u],
    [`${sealJSON} {}`, /trailing/u],
  ];
  for (const [body, error] of cases) assert.throws(() => decodeRecoverySeal(body), error);
  assert.throws(() => decodeChainLink(sealJSON), /unknown field "kind"/u);
});

test("recovery seal v1 numbers reject non-integers and unsafe values before conversion", () => {
  for (const value of ["1.0", "1e0", "-1", "9007199254740992"]) {
    const body = sealJSON.replace('"shard_size":3', `"shard_size":${value}`);
    assert.throws(() => decodeRecoverySeal(body), /unsigned integer|safe integer/u, value);
  }
});

const packageRoot = findPackageRoot(import.meta.url);
const CLI = resolve(packageRoot, "dist/src/cli.js");
const fixtureDir = resolve(packageRoot, "../../conformance/testdata/recovery-seals/valid");
const fixtureEvidenceDir = existsSync(join(fixtureDir, "evidence"))
  ? join(fixtureDir, "evidence")
  : fixtureDir;
const fixtureSealFile = (): string => {
  const name = readdirSync(fixtureEvidenceDir).find((entry) => entry.startsWith("chain-link-"));
  return join(fixtureEvidenceDir, name ?? "chain-link-missing.json");
};

test("recovery prefix enforces zero-based contiguous outer sequence", () => {
  const seal = decodeRecoverySeal(readFileSync(fixtureSealFile(), "utf8"));
  const shard = readFileSync(join(fixtureEvidenceDir, seal.shard));
  const prefix = parseEntryLinesText(
    decodeUTF8(shard.subarray(0, seal.damage_offset), "recovery-seal fixture prefix"),
  );
  assert.equal(verifyRecoveryOuterSequence(prefix), undefined);
  assert.equal(prefix.length, 3);
  assert.match(prefix[0]?.line ?? "", /"seq":0/u);
  const resequenced = [...prefix];
  const first = resequenced[0];
  assert.ok(first);
  first.line = first.line.replace(/"seq":0/u, '"seq":1');
  assert.match(
    verifyRecoveryOuterSequence(resequenced) ?? "",
    /expected zero-based contiguous sequence 0, got 1/u,
  );
  assert.equal(verifyRecoveryOuterSequence([]), undefined);
});

test("Go recovery-seal fixture verifies as an unhealthy attested discontinuity and fails closed on replay edits", async () => {
  const originalText = readFileSync(fixtureSealFile(), "utf8");
  const original = decodeRecoverySeal(originalText);
  const originalShardBytes = readFileSync(join(fixtureEvidenceDir, original.shard));
  const trustedKey = readFileSync(join(fixtureDir, "signer.pub"), "utf8").trim();
  const report = await verifyBase(
    fixtureEvidenceDir,
    original.predecessor_session.split(".run.")[0] as string,
    {
      trustedKeys: [trustedKey],
      endorsements: [],
    },
  );
  const successor = report.chains.find((chain) => chain.session === original.successor_session);
  assert.ok(successor?.recovery_seal, "verified seal attaches to the bound successor");
  assert.ok(report.findings.some((finding) => finding.kind === "attested_discontinuity"));
  assert.equal(baseHealthy(report), false, "an attested discontinuity remains unhealthy");
  assert.equal(baseUnlinked(report).includes(original.successor_session), false);
  const linksOnly = await verifyBase(
    fixtureEvidenceDir,
    original.predecessor_session.split(".run.")[0] as string,
    { trustedKeys: [], endorsements: [] },
  );
  assert.ok(linksOnly.chains.some((chain) => chain.recovery_seal !== undefined));
  assert.equal(
    baseHealthy(linksOnly),
    false,
    "links-only trust mode still reports unhealthy discontinuity",
  );
  const cli = spawnSync(
    "node",
    [CLI, "chain", fixtureEvidenceDir, "--dir", "--key", trustedKey, "--json"],
    { encoding: "utf8" },
  );
  assert.equal(cli.status, 1, cli.stderr);
  const cliReport = JSON.parse(cli.stdout) as {
    continuity: {
      discontinuities: {
        session: string;
        predecessor_session: string;
        shard: string;
        damage_offset: number;
      }[];
    };
  };
  assert.deepEqual(cliReport.continuity.discontinuities, [
    {
      session: original.successor_session,
      predecessor_session: original.predecessor_session,
      shard: original.shard,
      damage_offset: original.damage_offset,
    },
  ]);

  const dir = mkdtempSync(join(tmpdir(), "pipelock-recovery-seal-"));
  try {
    for (const entry of readdirSync(fixtureEvidenceDir)) {
      cpSync(join(fixtureEvidenceDir, entry), join(dir, entry), { recursive: true });
    }
    const file = fixtureSealFile();
    const name = file.slice(fixtureEvidenceDir.length + 1);
    const seed = createHash("sha256").update("pipelock-recovery-seal-conformance-v1").digest();
    const pub = Buffer.from(await ed25519.getPublicKeyAsync(seed)).toString("hex");
    assert.equal(
      pub,
      original.successor_signer_key,
      "fixture signer matches the known conformance key",
    );

    for (const [field, changed] of [
      ["shard_size", { ...original, shard_size: original.shard_size + 1 }],
      ["successor_open_hash", { ...original, successor_open_hash: "33".repeat(32) }],
      [
        "successor_session",
        {
          ...original,
          successor_session: `${original.successor_session.slice(0, -32)}${"c".repeat(32)}`,
        },
      ],
    ] as [string, RecoverySeal][]) {
      const unsigned = { ...changed, signature: "" as const };
      const sig = Buffer.from(
        await ed25519.signAsync(recoverySealSigningBytes(unsigned), seed),
      ).toString("hex");
      writeFileSync(join(dir, name), JSON.stringify({ ...changed, signature: `ed25519:${sig}` }));
      const rejected = await verifyBase(
        dir,
        original.predecessor_session.split(".run.")[0] as string,
        {
          trustedKeys: [trustedKey],
          endorsements: [],
        },
      );
      assert.ok(
        rejected.findings.some((finding) => finding.kind === "invalid_recovery_seal"),
        field,
      );
      assert.equal(
        rejected.chains.some((chain) => chain.recovery_seal !== undefined),
        false,
        field,
      );
    }

    // Replaying the otherwise valid seal against changed raw shard bytes
    // must fail even though the signature itself remains valid.
    const damagedName = original.shard;
    writeFileSync(join(dir, name), originalText);
    writeFileSync(
      join(dir, damagedName),
      Buffer.concat([readFileSync(join(dir, damagedName)), Buffer.from([0])]),
    );
    const replayed = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      {
        trustedKeys: [trustedKey],
        endorsements: [],
      },
    );
    assert.ok(replayed.findings.some((finding) => finding.kind === "invalid_recovery_seal"));
    assert.equal(
      replayed.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );

    writeFileSync(join(dir, damagedName), originalShardBytes);
    unlinkSync(join(dir, name));
    const missing = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(missing.findings.some((finding) => finding.kind === "corrupt_chain"));
    assert.equal(baseUnlinked(missing).includes(original.successor_session), true);
    assert.equal(
      missing.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );

    // A complete signed final receipt without its newline is observed but
    // excluded from the bound prefix. Its outer hash and receipt signature
    // still have to verify before the discontinuity can attach.
    const completeText = decodeUTF8(
      originalShardBytes.subarray(0, originalShardBytes.lastIndexOf(0x0a) + 1),
      "fixture shard",
    );
    const receiptLines = completeText.split("\n").filter((line) => line !== "");
    const openLine = receiptLines[0] as string;
    const finalLine = receiptLines[1] as string;
    const prefixBytes = Buffer.from(`${openLine}\n`, "utf8");
    const noNewlineBytes = Buffer.concat([prefixBytes, Buffer.from(finalLine, "utf8")]);
    const prefixLines = parseEntryLinesText(prefixBytes.toString("utf8"));
    const prefixEntry = parseJSONStrict(prefixLines[0]?.line ?? "") as Record<string, unknown>;
    const prefixSeq = prefixEntry["seq"];
    assert.ok(prefixSeq instanceof RawNumber);
    const prefixReceipts = extractTypedFromEntries(prefixLines.map((line) => line.entry)).action;
    const prefixReceipt = prefixReceipts.at(-1);
    assert.ok(prefixReceipt);
    const noNewlineSeal = {
      ...original,
      shard_size: noNewlineBytes.length,
      shard_sha256: sha256Hex(noNewlineBytes),
      damage_offset: prefixBytes.length,
      last_good_seq: Number(prefixSeq.literal),
      last_good_hash: prefixEntry["hash"] as string,
      predecessor_tail_seq: prefixReceipt.action_record?.chain_seq ?? 0,
      predecessor_tail_hash: receiptHash(prefixReceipt),
      predecessor_signer_key: prefixReceipt.signer_key as string,
      signature: "" as const,
    } satisfies RecoverySeal;
    const noNewlineSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(noNewlineSeal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), noNewlineBytes);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...noNewlineSeal, signature: `ed25519:${noNewlineSignature}` }),
    );
    const noNewlineReport = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(noNewlineReport.chains.some((chain) => chain.recovery_seal !== undefined));

    // A closed writer may tear the final checkpoint's LF. Known recorder
    // entries qualify even when the final entry is not itself a receipt.
    const checkpointPrefix = Buffer.from(`${openLine}\n${finalLine}\n`, "utf8");
    const checkpointBytes = Buffer.concat([
      checkpointPrefix,
      Buffer.from(receiptLines[2] as string, "utf8"),
    ]);
    const lastComplete = parseJSONStrict(finalLine) as Record<string, unknown>;
    const completeReceipts = extractTypedFromEntries(
      parseEntryLinesText(checkpointPrefix.toString("utf8")).map((line) => line.entry),
    ).action;
    const lastCompleteReceipt = completeReceipts.at(-1);
    assert.ok(lastCompleteReceipt);
    const checkpointSeal = {
      ...original,
      shard_size: checkpointBytes.length,
      shard_sha256: sha256Hex(checkpointBytes),
      damage_offset: checkpointPrefix.length,
      last_good_seq: Number((lastComplete["seq"] as RawNumber).literal),
      last_good_hash: lastComplete["hash"] as string,
      predecessor_tail_seq: lastCompleteReceipt.action_record?.chain_seq ?? 0,
      predecessor_tail_hash: receiptHash(lastCompleteReceipt),
      signature: "" as const,
    } satisfies RecoverySeal;
    const checkpointSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(checkpointSeal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), checkpointBytes);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...checkpointSeal, signature: `ed25519:${checkpointSignature}` }),
    );
    const checkpointReport = await verifyBase(dir, "proxy", {
      trustedKeys: [trustedKey],
      endorsements: [],
    });
    assert.ok(checkpointReport.chains.some((chain) => chain.recovery_seal !== undefined));

    const completeInvalidUTF8 = Buffer.concat([
      prefixBytes,
      Buffer.from('{"summary":"', "utf8"),
      Buffer.from([0xff]),
      Buffer.from('"}', "utf8"),
    ]);
    const invalidUTF8Seal = {
      ...noNewlineSeal,
      shard_size: completeInvalidUTF8.length,
      shard_sha256: sha256Hex(completeInvalidUTF8),
      signature: "" as const,
    } satisfies RecoverySeal;
    const invalidUTF8Signature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(invalidUTF8Seal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), completeInvalidUTF8);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...invalidUTF8Seal, signature: `ed25519:${invalidUTF8Signature}` }),
    );
    const invalidUTF8Report = await verifyBase(dir, "proxy", {
      trustedKeys: [trustedKey],
      endorsements: [],
    });
    assert.equal(
      invalidUTF8Report.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );

    // Go classifies a nonempty unterminated byte fragment as torn even when
    // the final fragment is incomplete UTF-8; it has no complete JSON record
    // to validate. The seal still binds its exact bytes.
    const malformedTailBytes = Buffer.concat([
      prefixBytes,
      Buffer.from([0x7b, 0x22, 0x76, 0x22, 0x3a, 0x22, 0xe2, 0x82]),
    ]);
    const malformedTailSeal = {
      ...noNewlineSeal,
      shard_size: malformedTailBytes.length,
      shard_sha256: sha256Hex(malformedTailBytes),
      signature: "" as const,
    } satisfies RecoverySeal;
    const malformedTailSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(malformedTailSeal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), malformedTailBytes);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...malformedTailSeal, signature: `ed25519:${malformedTailSignature}` }),
    );
    const malformedTail = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(malformedTail.chains.some((chain) => chain.recovery_seal !== undefined));

    const completeInvalidBytes = Buffer.concat([prefixBytes, Buffer.from("{}", "utf8")]);
    const completeInvalidSeal = {
      ...noNewlineSeal,
      shard_size: completeInvalidBytes.length,
      shard_sha256: sha256Hex(completeInvalidBytes),
      signature: "" as const,
    } satisfies RecoverySeal;
    const completeInvalidSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(completeInvalidSeal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), completeInvalidBytes);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...completeInvalidSeal, signature: `ed25519:${completeInvalidSignature}` }),
    );
    const completeInvalid = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(completeInvalid.findings.some((finding) => finding.kind === "invalid_recovery_seal"));
    assert.equal(
      completeInvalid.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );

    const wrongSuccessorSeal = {
      ...noNewlineSeal,
      successor_open_hash: "44".repeat(32),
      signature: "" as const,
    } satisfies RecoverySeal;
    const wrongSuccessorSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(wrongSuccessorSeal), seed),
    ).toString("hex");
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...wrongSuccessorSeal, signature: `ed25519:${wrongSuccessorSignature}` }),
    );
    const wrongSuccessor = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(wrongSuccessor.findings.some((finding) => finding.kind === "invalid_recovery_seal"));
    assert.equal(
      wrongSuccessor.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );

    const tamperedFinal = JSON.parse(finalLine) as Record<string, unknown>;
    const tamperedDetail = tamperedFinal["detail"] as Record<string, unknown>;
    const receiptSignature = String(tamperedDetail["signature"]);
    tamperedDetail["signature"] =
      `${receiptSignature.slice(0, -1)}${receiptSignature.endsWith("0") ? "1" : "0"}`;
    tamperedFinal["hash"] = "";
    const unsignedFinal = JSON.stringify(tamperedFinal);
    tamperedFinal["hash"] = recorderEntryHash(unsignedFinal);
    const tamperedFinalLine = JSON.stringify(tamperedFinal);
    const tamperedBytes = Buffer.concat([prefixBytes, Buffer.from(tamperedFinalLine, "utf8")]);
    const tamperedSeal = {
      ...noNewlineSeal,
      shard_size: tamperedBytes.length,
      shard_sha256: sha256Hex(tamperedBytes),
      signature: "" as const,
    } satisfies RecoverySeal;
    const tamperedSealSignature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(tamperedSeal), seed),
    ).toString("hex");
    writeFileSync(join(dir, damagedName), tamperedBytes);
    writeFileSync(
      join(dir, name),
      JSON.stringify({ ...tamperedSeal, signature: `ed25519:${tamperedSealSignature}` }),
    );
    const invalidFinal = await verifyBase(
      dir,
      original.predecessor_session.split(".run.")[0] as string,
      { trustedKeys: [trustedKey], endorsements: [] },
    );
    assert.ok(invalidFinal.findings.some((finding) => finding.kind === "invalid_recovery_seal"));
    assert.equal(
      invalidFinal.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Go rotated recovery fixture needs every predecessor key pinned", async () => {
  const fixture = resolve(packageRoot, "../../conformance/testdata/recovery-seals/rotated");
  const keys = readFileSync(join(fixture, "signer.pub"), "utf8").trim().split(/\s+/u);
  const seal = decodeRecoverySeal(readFileSync(join(fixture, "seal.json"), "utf8"));
  for (const [name, pins, expected] of [
    ["both", keys, true],
    ["TOFU", [], false],
    ["missing predecessor key", keys.slice(1), false],
    ["missing rotated key", keys.slice(0, 1), false],
  ] as [string, string[], boolean][]) {
    const report = await verifyBase(join(fixture, "evidence"), "proxy", {
      trustedKeys: pins,
      endorsements: [],
    });
    const attached = report.chains.some(
      (chain) => chain.session === seal.successor_session && chain.recovery_seal !== undefined,
    );
    assert.equal(attached, expected, name);
    assert.equal(baseHealthy(report), false, name);
  }
});

test("a recovery signed by a different successor key needs explicit trust", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-recovery-key-"));
  try {
    cpSync(fixtureEvidenceDir, dir, { recursive: true });
    const seal = decodeRecoverySeal(readFileSync(fixtureSealFile(), "utf8"));
    const seed = createHash("sha256").update("pipelock-recovery-seal-key-change-test").digest();
    const successorKey = Buffer.from(await ed25519.getPublicKeyAsync(seed)).toString("hex");
    const successorFile = join(dir, `evidence-${seal.successor_session}-0.jsonl`);
    const entries = readFileSync(successorFile, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((entry) => entry["type"] === "action_receipt");
    let priorReceiptHash = "";
    let priorOuterHash = "genesis";
    for (const entry of entries) {
      const receipt = entry["detail"] as Receipt;
      assert.ok(receipt.action_record);
      if (priorReceiptHash !== "") receipt.action_record.chain_prev_hash = priorReceiptHash;
      receipt.signer_key = successorKey;
      const digest = createHash("sha256")
        .update(canonicalizeActionRecord(receipt.action_record))
        .digest();
      receipt.signature = `ed25519:${Buffer.from(await ed25519.signAsync(digest, seed)).toString("hex")}`;
      priorReceiptHash = receiptHash(receipt);
      entry["prev_hash"] = priorOuterHash;
      entry["hash"] = recorderEntryHash(JSON.stringify(entry));
      priorOuterHash = entry["hash"] as string;
    }
    const opening = entries[0]?.["detail"] as Receipt;
    const changed = {
      ...seal,
      successor_signer_key: successorKey,
      successor_open_hash: receiptHash(opening),
      signature: "" as const,
    } satisfies RecoverySeal;
    const signature = Buffer.from(
      await ed25519.signAsync(recoverySealSigningBytes(changed), seed),
    ).toString("hex");
    writeFileSync(successorFile, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);
    writeFileSync(
      join(dir, `chain-link-${seal.predecessor_session}.json`),
      JSON.stringify({ ...changed, signature: `ed25519:${signature}` }),
    );
    for (const [pins, expected] of [
      [[seal.predecessor_signer_key, successorKey], true],
      [[], false],
      [[seal.predecessor_signer_key], false],
    ] as [string[], boolean][]) {
      const report = await verifyBase(dir, "proxy", { trustedKeys: pins, endorsements: [] });
      assert.equal(
        report.chains.some((chain) => chain.recovery_seal !== undefined),
        expected,
      );
      assert.equal(baseHealthy(report), false);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a valid seal placed in another predecessor's slot is rejected and never attaches", async () => {
  const dir = mkdtempSync(join(tmpdir(), "recovery-seal-slot-"));
  try {
    cpSync(fixtureEvidenceDir, dir, { recursive: true });
    const sealName = readdirSync(dir).find((name) => name.startsWith("chain-link-"));
    assert.ok(sealName, "fixture carries a seal claim");
    const seal = decodeRecoverySeal(readFileSync(join(dir, sealName), "utf8"));
    const base = seal.predecessor_session.split(".run.")[0] as string;
    const wrongSlot = `chain-link-${base}.run.${"3".repeat(32)}.json`;
    writeFileSync(join(dir, wrongSlot), readFileSync(join(dir, sealName)));
    unlinkSync(join(dir, sealName));
    const trustedKey = readFileSync(join(fixtureDir, "signer.pub"), "utf8").trim();
    const report = await verifyBase(dir, base, { trustedKeys: [trustedKey], endorsements: [] });
    assert.ok(report.findings.some((finding) => finding.kind === "invalid_recovery_seal"));
    assert.equal(
      report.findings.some((finding) => finding.kind === "attested_discontinuity"),
      false,
      "a seal rejected for its placement must not become an attested discontinuity",
    );
    assert.equal(
      report.chains.some((chain) => chain.recovery_seal !== undefined),
      false,
    );
    assert.equal(baseUnlinked(report).includes(seal.successor_session), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

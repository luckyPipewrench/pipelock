// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { verifyAuditPacket } from "../src/audit-packet.js";
import { computeTotals, verifyChain } from "../src/chain.js";
import { extractReceipts } from "../src/recorder.js";
import type { AuditPacket } from "../src/types.js";
import { resolveSignerKey, sha256Hex } from "../src/util.js";

const publicKey = "4655a7e605c12ebb00a46037881c33c5bca5eb74b45a02e8e7261a7ff5a21678";
const versionedPublicKey =
  "pipelock-ed25519-public-v1\nRlWn5gXBLrsApGA3iBwzxbyl63S0WgLo5yYaf/WiFng=";
const rootHash = "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a";

function basePacket(): AuditPacket {
  return {
    schema_version: "pipelock.audit_packet.v0",
    generated_at: "2026-05-10T00:00:00Z",
    run: {
      provider: "local",
      agent_identity: "test-agent",
      started_at: "2026-05-10T00:00:00Z",
    },
    policy: {
      policy_hashes: ["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    },
    summary: {
      receipt_count: 5,
      totals: {
        allow: 5,
        block: 0,
        warn: 0,
        ask: 0,
        strip: 0,
        forward: 0,
        redirect: 0,
        other: 0,
      },
    },
    verifier: {
      verdict: "valid",
      trusted: true,
      receipt_count: 5,
      root_hash: rootHash,
      final_seq: 4,
      signer_key: publicKey,
    },
    posture: {
      enforcement_mode: "local",
      runner_os: "Linux",
      raw_socket_status: "unknown",
      docker_socket_status: "unknown",
      dns_udp_status: "unknown",
      browser_proxy_status: "unknown",
      websocket_frame_scanning: "explicit_ws_proxy_path_required",
      unsupported_paths: [],
    },
    artifacts: {
      packet: "packet.json",
      evidence: "evidence.jsonl",
      verifier: "verifier.txt",
    },
  };
}

function writePacket(mutator?: (packet: AuditPacket) => void): string {
  const dir = mkdtempSync(path.join(tmpdir(), "pipelock-ts-verifier-"));
  const packet = basePacket();
  mutator?.(packet);
  writeFileSync(path.join(dir, "packet.json"), `${JSON.stringify(packet, null, 2)}\n`, {
    mode: 0o600,
  });
  writeFileSync(
    path.join(dir, "evidence.jsonl"),
    readFileSync("../../conformance/testdata/valid-chain.jsonl"),
    { mode: 0o600 },
  );
  writeFileSync(path.join(dir, "verifier.txt"), "ok\n", { mode: 0o600 });
  return dir;
}

async function writePacketWithEvidence(source: string, lines?: number): Promise<string> {
  const dir = mkdtempSync(path.join(tmpdir(), "pipelock-ts-verifier-lifecycle-"));
  const rawEvidence = readFileSync(source, "utf8");
  const evidence =
    lines === undefined
      ? rawEvidence
      : `${rawEvidence.trimEnd().split("\n").slice(0, lines).join("\n")}\n`;
  writeFileSync(path.join(dir, "evidence.jsonl"), evidence, { mode: 0o600 });
  const receipts = extractReceipts(path.join(dir, "evidence.jsonl"));
  const chain = await verifyChain(receipts, publicKey);
  assert.equal(chain.valid, true, chain.error);
  const packet = basePacket();
  packet.summary!.receipt_count = chain.receipt_count;
  packet.summary!.totals = computeTotals(receipts);
  packet.verifier!.receipt_count = chain.receipt_count;
  packet.verifier!.root_hash = chain.root_hash;
  packet.verifier!.final_seq = chain.final_seq;
  writeFileSync(path.join(dir, "packet.json"), `${JSON.stringify(packet, null, 2)}\n`, {
    mode: 0o600,
  });
  writeFileSync(path.join(dir, "verifier.txt"), "ok\n", { mode: 0o600 });
  return dir;
}

const defaultOptions = {
  signerKey: publicKey,
  offline: false,
  allowSelfConsistentOnly: false,
  noTrustRequired: false,
  expectSha256: "",
};

test("audit packet verifies end to end", async () => {
  const report = await verifyAuditPacket(writePacket(), defaultOptions);
  assert.equal(report.valid, true);
  assert.equal(report.schema_check, "pass");
  assert.equal(report.chain_check, "pass");
  assert.equal(report.cross_check, "pass");
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "UNVERIFIED");
  assert.equal(report.lifecycle_reason, "no_lifecycle");
});

test("audit packet rejects an orphan outcome in an otherwise valid chain", async () => {
  const report = await verifyAuditPacket(
    await writePacketWithEvidence("../../conformance/testdata/g1-valid-chain.jsonl"),
    defaultOptions,
  );
  assert.equal(report.valid, false);
  assert.equal(report.chain_check, "pass");
  assert.equal(report.cross_check, "pass");
  assert.ok(report.errors?.some((error) => error.includes("lifecycle: chain_broken")));
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "BROKEN");
  assert.equal(report.lifecycle_reason, "chain_broken");
});

test("audit packet keeps an in-progress lifecycle valid but names it", async () => {
  const report = await verifyAuditPacket(
    await writePacketWithEvidence("../../conformance/testdata/g1-restart-chain.jsonl"),
    defaultOptions,
  );
  assert.equal(report.valid, true, JSON.stringify(report.errors));
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "LIMITED");
  assert.equal(report.lifecycle_reason, "open_action");
});

test("audit packet keeps an open session valid but marks its missing close", async () => {
  const report = await verifyAuditPacket(
    await writePacketWithEvidence("../../conformance/testdata/g1-valid-chain.jsonl", 1),
    defaultOptions,
  );
  assert.equal(report.valid, true, JSON.stringify(report.errors));
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "LIMITED");
  assert.equal(report.lifecycle_reason, "abnormal_end");
});

test("audit packet reports a malformed lifecycle chain as assessed and broken", async () => {
  const dir = writePacket();
  writeFileSync(
    path.join(dir, "evidence.jsonl"),
    readFileSync("../../conformance/testdata/g1-inconsistent-close.jsonl"),
    { mode: 0o600 },
  );
  const report = await verifyAuditPacket(dir, defaultOptions);
  assert.equal(report.valid, false);
  assert.equal(report.chain_check, "fail");
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "BROKEN");
  assert.equal(report.lifecycle_reason, "chain_broken");
});

test("audit packet requires external trust for valid verdict", async () => {
  const report = await verifyAuditPacket(writePacket(), { ...defaultOptions, signerKey: "" });
  assert.equal(report.valid, false);
  assert.equal(report.chain_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("requires --key or --expect-sha256")));
});

test("packet hash can anchor the embedded signer key", async () => {
  const dir = writePacket();
  const packetBytes = readFileSync(path.join(dir, "packet.json"));
  const report = await verifyAuditPacket(dir, {
    ...defaultOptions,
    signerKey: "",
    expectSha256: sha256Hex(packetBytes),
  });
  assert.equal(report.valid, true, JSON.stringify(report.errors));
});

test("wrong packet hash cannot anchor the embedded signer key", async () => {
  const report = await verifyAuditPacket(writePacket(), {
    ...defaultOptions,
    signerKey: "",
    expectSha256: "a".repeat(64),
  });
  assert.equal(report.valid, false);
  assert.ok(report.errors?.some((err) => err.includes("packet sha256 mismatch")));
});

test("explicit self-consistent mode uses the unpinned chain", async () => {
  const dir = writePacket((packet) => {
    packet.verifier!.verdict = "self_consistent_only";
    packet.verifier!.trusted = false;
    delete packet.verifier!.signer_key;
  });
  const report = await verifyAuditPacket(dir, {
    ...defaultOptions,
    signerKey: "",
    allowSelfConsistentOnly: true,
  });
  assert.equal(report.valid, true, JSON.stringify(report.errors));
});

test("explicit no-trust mode can use the packet key", async () => {
  const dir = writePacket((packet) => {
    packet.verifier!.verdict = "error";
    packet.verifier!.trusted = false;
  });
  const report = await verifyAuditPacket(dir, {
    ...defaultOptions,
    signerKey: "",
    noTrustRequired: true,
  });
  assert.equal(report.valid, true, JSON.stringify(report.errors));
});

test("audit packet rejects an empty chain", async () => {
  const dir = writePacket((packet) => {
    packet.summary!.receipt_count = 0;
    packet.summary!.totals!.allow = 0;
    packet.verifier!.receipt_count = 0;
    packet.verifier!.root_hash = "";
    packet.verifier!.final_seq = 0;
  });
  writeFileSync(path.join(dir, "evidence.jsonl"), "\n", { mode: 0o600 });

  const report = await verifyAuditPacket(dir, defaultOptions);
  assert.equal(report.valid, false);
  assert.equal(report.chain_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("empty chain")));
  assert.equal(report.lifecycle_assessment, "assessed");
  assert.equal(report.lifecycle_status, "UNVERIFIED");
  assert.equal(report.lifecycle_reason, "no_receipts");
});

test("literal signer key wins over a same-named cwd file", () => {
  const dir = writePacket();
  writeFileSync(path.join(dir, publicKey), "0".repeat(64), { mode: 0o600 });
  const result = spawnSync(
    process.execPath,
    [path.resolve("dist/src/cli.js"), "audit-packet", ".", "--key", publicKey],
    {
      cwd: dir,
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("versioned literal signer key wins over a same-named cwd file", () => {
  const dir = writePacket();
  const shadow = path.join(dir, versionedPublicKey);
  mkdirSync(path.dirname(shadow), { recursive: true, mode: 0o700 });
  writeFileSync(shadow, "0".repeat(64), { mode: 0o600 });
  const result = spawnSync(
    process.execPath,
    [path.resolve("dist/src/cli.js"), "audit-packet", ".", "--key", versionedPublicKey],
    {
      cwd: dir,
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("versioned signer keys reject malformed base64", () => {
  const malformed = versionedPublicKey.replace("RlWn", "Rl!Wn");
  assert.throws(() => resolveSignerKey(malformed), /malformed base64/u);
});

test("audit packet detects totals mismatch", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.summary!.totals!.allow = 4;
      packet.summary!.totals!.block = 1;
    }),
    defaultOptions,
  );
  assert.equal(report.valid, false);
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("totals[allow]")));
});

test("audit packet detects receipt_count mismatch", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.summary!.receipt_count = 6;
      packet.summary!.totals!.other = 1;
    }),
    defaultOptions,
  );
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("receipt_count")));
});

test("audit packet detects root_hash mismatch", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.verifier!.root_hash = "0".repeat(64);
    }),
    defaultOptions,
  );
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("root_hash")));
});

test("audit packet detects final_seq mismatch", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.verifier!.final_seq = 3;
    }),
    defaultOptions,
  );
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("final_seq")));
});

test("audit packet detects present final_seq zero mismatch", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.verifier!.final_seq = 0;
    }),
    defaultOptions,
  );
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("final_seq")));
});

test("audit packet detects verdict-vs-chain disagreement", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.verifier!.verdict = "invalid";
      packet.verifier!.trusted = false;
    }),
    defaultOptions,
  );
  assert.equal(report.cross_check, "fail");
  assert.ok(report.errors?.some((err) => err.includes("verdict=invalid")));
});

test("--offline skips chain verification", async () => {
  const report = await verifyAuditPacket(
    writePacket((packet) => {
      packet.verifier!.root_hash = "0".repeat(64);
    }),
    { ...defaultOptions, offline: true },
  );
  assert.equal(report.valid, true);
  assert.equal(report.chain_check, "skipped");
  assert.equal(report.cross_check, "skipped");
  assert.equal(report.lifecycle_assessment, "not_assessed");
  assert.equal(report.lifecycle_assessment_reason, "offline mode skips chain re-verification");
});

test("CLI missing argument exits 64", () => {
  const result = spawnSync(process.execPath, ["dist/src/cli.js", "audit-packet"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 64);
  assert.match(result.stderr, /Usage: pipelock-verifier-ts audit-packet/u);
});

// A duplicated object member must be rejected, not resolved last-wins. The Go
// verifier rejects it; if this verifier accepted it, the same packet.json would
// be VALID here and REJECTED there — a cross-language parser differential on the
// artifact users are told to verify independently.
test("audit packet rejects duplicate object members", async () => {
  const dir = writePacket();
  const packetPath = path.join(dir, "packet.json");
  const text = readFileSync(packetPath, "utf8");
  // Duplicate schema_version: the first is honest, the second is the attacker's.
  const poisoned = text.replace(
    /"schema_version": "([^"]+)",/,
    '"schema_version": "$1",\n  "schema_version": "pipelock.audit_packet.vX-attacker",',
  );
  assert.notEqual(poisoned, text, "fixture must actually contain a duplicate member");
  writeFileSync(packetPath, poisoned, { mode: 0o600 });

  const report = await verifyAuditPacket(dir, defaultOptions);
  assert.equal(report.valid, false);
  assert.ok(
    report.errors?.some((e) => e.includes("duplicate object key")),
    `want a duplicate-key rejection, got ${JSON.stringify(report.errors)}`,
  );
});

test("audit packet rejects integers outside the cross-language exact range", async () => {
  const dir = writePacket();
  const packetPath = path.join(dir, "packet.json");
  let text = readFileSync(packetPath, "utf8");
  text = text.replace('"receipt_count": 5', '"receipt_count": 9007199254740993');
  text = text.replace('"allow": 5', '"allow": 9007199254740992');
  writeFileSync(packetPath, text, { mode: 0o600 });

  const report = await verifyAuditPacket(dir, { ...defaultOptions, offline: true });
  assert.equal(report.valid, false);
  assert.ok(
    report.errors?.some((error) => error.includes("cross-language exact range")),
    `want exact-range rejection, got ${JSON.stringify(report.errors)}`,
  );
});

test("audit packet rejects a non-finite magnitude Go and Rust reject", async () => {
  // 1e999 overflows to Infinity, which is not finite. A guard gated on
  // Number.isFinite skips it, so TypeScript would accept a packet Go and Rust
  // reject as out of range - the cross-language differential this guard closes.
  const dir = writePacket();
  const packetPath = path.join(dir, "packet.json");
  const text = readFileSync(packetPath, "utf8").replace(
    '"receipt_count": 5',
    '"receipt_count": 1e999',
  );
  assert.ok(text.includes("1e999"), "fixture must contain the overflowing literal");
  writeFileSync(packetPath, text, { mode: 0o600 });

  const report = await verifyAuditPacket(dir, { ...defaultOptions, offline: true });
  assert.equal(report.valid, false);
  assert.ok(
    report.errors?.some((error) => error.includes("cross-language exact range")),
    `want exact-range rejection, got ${JSON.stringify(report.errors)}`,
  );
});

test("audit packet rejects invalid UTF-8 instead of replacing bytes", async () => {
  const dir = writePacket();
  const packetPath = path.join(dir, "packet.json");
  const raw = readFileSync(packetPath);
  const marker = Buffer.from("test-agent");
  const offset = raw.indexOf(marker);
  assert.notEqual(offset, -1, "fixture must contain agent identity marker");
  raw[offset] = 0xff;
  writeFileSync(packetPath, raw, { mode: 0o600 });

  const report = await verifyAuditPacket(dir, { ...defaultOptions, offline: true });
  assert.equal(report.valid, false);
  assert.ok(
    report.errors?.some((error) => error.includes("invalid UTF-8")),
    `want UTF-8 rejection, got ${JSON.stringify(report.errors)}`,
  );
});

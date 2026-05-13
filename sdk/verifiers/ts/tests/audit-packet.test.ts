import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { verifyAuditPacket } from "../src/audit-packet.js";
import type { AuditPacket } from "../src/types.js";

const publicKey = "4655a7e605c12ebb00a46037881c33c5bca5eb74b45a02e8e7261a7ff5a21678";
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

const defaultOptions = {
  signerKey: "",
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
});

test("CLI missing argument exits 64", () => {
  const result = spawnSync(process.execPath, ["dist/src/cli.js", "audit-packet"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 64);
  assert.match(result.stderr, /Usage: pipelock-verifier-ts audit-packet/u);
});

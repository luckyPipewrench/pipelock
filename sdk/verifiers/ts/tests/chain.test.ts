// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import * as ed25519 from "@noble/ed25519";
import { canonicalizeBytes } from "../src/aarp/canonical.js";
import { canonicalizeActionRecord } from "../src/canonical.js";
import { extractReceipts, readEntries } from "../src/recorder.js";
import { computeSessionOpenGenesis, receiptHash, verifyChain } from "../src/chain.js";
import {
  loadRotationEndorsementFile,
  verifyChainWithEndorsements,
  verifyRotationEndorsement,
} from "../src/rotation.js";
import type { JSONObject, Receipt } from "../src/types.js";
import { InvalidError } from "../src/util.js";

const validChain = "../../conformance/testdata/valid-chain.jsonl";
const brokenChain = "../../conformance/testdata/broken-chain.jsonl";
const g1ValidChain = "../../conformance/testdata/g1-valid-chain.jsonl";
const g1RestartChain = "../../conformance/testdata/g1-restart-chain.jsonl";
const g1BrokenGenesis = "../../conformance/testdata/g1-broken-genesis.jsonl";
const g1LegacyOpenGenesis = "../../conformance/testdata/g1-legacy-open-genesis.jsonl";
const g1InconsistentHeartbeat = "../../conformance/testdata/g1-inconsistent-heartbeat.jsonl";
const g1InconsistentClose = "../../conformance/testdata/g1-inconsistent-close.jsonl";
const g1AmbiguousSessionControl = "../../conformance/testdata/g1-ambiguous-session-control.jsonl";
const g1AmbiguousOpenClose = "../../conformance/testdata/g1-ambiguous-open-close.jsonl";
const g1AmbiguousHeartbeatClose = "../../conformance/testdata/g1-ambiguous-heartbeat-close.jsonl";
const g1RotatedCloseCountValid = "../../conformance/testdata/g1-rotated-close-count-valid.jsonl";
const g1RotatedTwice = "../../conformance/testdata/g1-rotated-twice-valid.jsonl";
const g1RotatedCloseCountInvalid =
  "../../conformance/testdata/g1-rotated-close-count-invalid.jsonl";
const g1RotationEndorsement = "../../conformance/testdata/g1-rotation-endorsement.json";
const g1RotationEndorsementSecond = "../../conformance/testdata/g1-rotation-endorsement-2.json";
const g1PlainAfterClose = "../../conformance/testdata/g1-plain-after-close.jsonl";
const g1EmptyRunNonceAfterClose = "../../conformance/testdata/g1-empty-run-nonce-after-close.jsonl";
const g1HeartbeatAfterClose = "../../conformance/testdata/g1-heartbeat-after-close.jsonl";
const g1CloseWithoutOpen = "../../conformance/testdata/g1-close-without-open.jsonl";
const g1NewSessionAfterClose = "../../conformance/testdata/g1-new-session-after-close.jsonl";
const g1ReopenClosedRun = "../../conformance/testdata/g1-reopen-closed-run.jsonl";
const g1GenesisVectors = "../../conformance/testdata/g1-genesis-vectors.json";
const testKey = "../../conformance/testdata/test-key.json";
const validPlainV2 =
  "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json";
const v2GoldenPublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const v2PrivateSeedHex =
  "9d61b19d" +
  "effd5a60" +
  "ba844af4" +
  "92ec2cc4" +
  "4449c569" +
  "7b326919" +
  "703bac03" +
  "1cae7f60";

test("valid Go-generated chain verifies", async () => {
  const result = await verifyChain(extractReceipts(validChain));
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /UNPINNED/u);
});

test("valid Go-generated chain allows explicit unpinned structural verification", async () => {
  const result = await verifyChain(extractReceipts(validChain), "", { allowUnpinned: true });
  assert.equal(result.valid, true);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
  assert.equal(
    result.root_hash,
    "be904bd5ca82adc26c2969872c23925f22ff24e33faf44a1185b9ffc0e2c2b5a",
  );
});

test("legacy Go-generated chain verifies with pinned key", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(validChain), key);
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
});

test("g1 Go-generated chain verifies with pinned key", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1ValidChain), key);
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
});

test("g1 restart chain verifies with prior tail fields", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const receipts = extractReceipts(g1RestartChain);
  const result = await verifyChain(receipts, key);
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 5);
  assert.equal(result.final_seq, 4);
  const restartOpen = receipts[2]!.action_record!.session_control as Record<string, unknown>;
  const open = restartOpen["open"] as Record<string, unknown>;
  assert.equal(open["prior_chain_seq"], 1);
  assert.equal(typeof open["prior_chain_head"], "string");
  assert.notEqual(open["prior_chain_head"], "");
});

test("g1 restart close receipt_count mismatch is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const receipts = extractReceipts(g1RestartChain);
  (
    (receipts[4]!.action_record!.session_control as Record<string, unknown>)["close"] as Record<
      string,
      unknown
    >
  )["receipt_count"] = 3;
  await signActionReceiptWithTestKey(receipts[4]!);

  const result = await verifyChain(receipts, key);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /session_close receipt_count mismatch/u);
});

test("g1 genesis vectors match Go", () => {
  const vectors = JSON.parse(readFileSync(g1GenesisVectors, "utf8")) as Array<{
    open: Record<string, unknown>;
    expected: string;
  }>;
  assert.ok(vectors.length >= 5);
  for (const vector of vectors) {
    assert.equal(computeSessionOpenGenesis(vector.open), vector.expected);
  }
});

test("g1 broken genesis is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1BrokenGenesis), key);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 0);
  assert.match(result.error ?? "", /session_open genesis hash mismatch/u);
});

test("g1 legacy session_open on genesis is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1LegacyOpenGenesis), key);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 0);
  assert.match(result.error ?? "", /session_open on legacy genesis/u);
});

test("g1 inconsistent heartbeat fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1InconsistentHeartbeat), key);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 3);
  assert.match(result.error ?? "", /heartbeat chain_head mismatch/u);
});

test("g1 inconsistent close fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1InconsistentClose), key);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 4);
  assert.match(result.error ?? "", /session_close root_hash mismatch/u);
});

test("g1 ambiguous session_control fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  for (const path of [g1AmbiguousSessionControl, g1AmbiguousOpenClose, g1AmbiguousHeartbeatClose]) {
    const result = await verifyChain(extractReceipts(path), key);
    assert.equal(result.valid, false, path);
    assert.match(result.error ?? "", /session_control must carry exactly one payload/u);
  }
});

test("g1 rotated close receipt_count valid fixture verifies", async () => {
  const result = await verifyChain(extractReceipts(g1RotatedCloseCountValid), trustedKeys());
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 6);
  assert.equal(result.final_seq, 2);
});

test("g1 rotated chain verifies from one root plus the signed endorsement", async () => {
  const rootKey = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const endorsement = await loadRotationEndorsementFile(g1RotationEndorsement);
  const result = await verifyChainWithEndorsements(
    extractReceipts(g1RotatedCloseCountValid),
    rootKey,
    {
      sessionID: "conformance-session",
      endorsements: [endorsement],
    },
  );
  assert.equal(result.valid, true, result.error);
});

test("g1 twice-rotated chain verifies from one root plus both endorsements", async () => {
  const rootKey = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const endorsements = await Promise.all([
    loadRotationEndorsementFile(g1RotationEndorsement),
    loadRotationEndorsementFile(g1RotationEndorsementSecond),
  ]);
  const result = await verifyChainWithEndorsements(extractReceipts(g1RotatedTwice), rootKey, {
    sessionID: "conformance-session",
    endorsements,
  });
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 9);
});

test("rotation endorsement trust fails closed when absent, altered, or duplicated", async () => {
  const rootKey = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const receipts = extractReceipts(g1RotatedCloseCountValid);
  const endorsement = await loadRotationEndorsementFile(g1RotationEndorsement);

  const missing = await verifyChainWithEndorsements(receipts, rootKey, {
    sessionID: "conformance-session",
    endorsements: [],
  });
  assert.equal(missing.valid, false);
  assert.match(missing.error ?? "", /does not match receipt boundary/u);

  const unpinned = await verifyChainWithEndorsements(receipts, "", {
    sessionID: "conformance-session",
    endorsements: [endorsement],
  });
  assert.equal(unpinned.valid, false);
  assert.match(unpinned.error ?? "", /requires at least one trusted root key/u);

  const successorKey = receipts.find(
    (receipt) => receipt.action_record?.key_transition !== undefined,
  )?.signer_key;
  assert.ok(successorKey);
  const prePinnedSuccessor = await verifyChainWithEndorsements(
    receipts,
    `${rootKey},${successorKey}`,
    {
      sessionID: "conformance-session",
      endorsements: [],
    },
  );
  assert.equal(prePinnedSuccessor.valid, false);
  assert.match(prePinnedSuccessor.error ?? "", /does not match receipt boundary/u);

  const keyInfo = JSON.parse(readFileSync(testKey, "utf8")) as {
    rotated_public_key_hex: string;
    rotated_seed_hex: string;
  };
  const unmarkedSwitch = extractReceipts(g1ValidChain);
  await signActionReceiptWithKey(
    unmarkedSwitch[1]!,
    keyInfo.rotated_seed_hex,
    keyInfo.rotated_public_key_hex,
  );
  const forged = await verifyChainWithEndorsements(unmarkedSwitch, rootKey, {
    sessionID: "conformance-session",
    endorsements: [],
  });
  assert.equal(forged.valid, false);
  assert.match(forged.error ?? "", /without a key_transition boundary/u);

  const altered = { ...endorsement, prior_tail_hash: "0".repeat(64) };
  await assert.rejects(verifyRotationEndorsement(altered), /signature verification failed/u);
  await assert.rejects(
    verifyRotationEndorsement({ ...endorsement, rotated_at: "2026-02-30T12:00:00Z" }),
    /canonical UTC RFC3339Nano/u,
  );

  const duplicate = await verifyChainWithEndorsements(receipts, rootKey, {
    sessionID: "conformance-session",
    endorsements: [endorsement, endorsement],
  });
  assert.equal(duplicate.valid, false);
  assert.match(duplicate.error ?? "", /multiple rotation endorsements/u);

  const second = await loadRotationEndorsementFile(g1RotationEndorsementSecond);
  const replayed = await verifyChainWithEndorsements(receipts, rootKey, {
    sessionID: "conformance-session",
    endorsements: [endorsement, second],
  });
  assert.equal(replayed.valid, false);
  assert.match(replayed.error ?? "", /unused rotation endorsement/u);

  const crossSession = await verifyChainWithEndorsements(receipts, rootKey, {
    sessionID: "other-session",
    endorsements: [endorsement],
  });
  assert.equal(crossSession.valid, false);
  assert.match(crossSession.error ?? "", /signed recorder session/u);
});

test("rotation endorsement file rejects duplicate, unknown, and trailing fields", async () => {
  const source = readFileSync(g1RotationEndorsement, "utf8").trim();
  const dir = mkdtempSync(join(tmpdir(), "pipelock-rotation-json-"));
  try {
    const duplicate = join(dir, "duplicate.json");
    writeFileSync(duplicate, source.replace('"version": 1,', '"version": 1, "version": 1,'));
    await assert.rejects(loadRotationEndorsementFile(duplicate), InvalidError);
    await assert.rejects(loadRotationEndorsementFile(duplicate), /duplicate object key/u);

    const unknown = join(dir, "unknown.json");
    writeFileSync(unknown, source.replace(/\n\}$/u, ',\n  "trusted": true\n}'));
    await assert.rejects(loadRotationEndorsementFile(unknown), /unknown field trusted/u);

    const trailing = join(dir, "trailing.json");
    writeFileSync(trailing, `${source}\n{}`);
    await assert.rejects(loadRotationEndorsementFile(trailing), /trailing tokens/u);

    const oversized = join(dir, "oversized.json");
    writeFileSync(oversized, Buffer.alloc(64 * 1024 + 1));
    await assert.rejects(loadRotationEndorsementFile(oversized), /exceeds 65536 bytes/u);

    const malformedUtf8 = join(dir, "malformed-utf8.json");
    writeFileSync(malformedUtf8, Buffer.from([0xff]));
    await assert.rejects(loadRotationEndorsementFile(malformedUtf8), /not valid UTF-8/u);

    if (process.platform !== "win32") {
      const fifo = join(dir, "fifo.json");
      const created = spawnSync("mkfifo", [fifo], { encoding: "utf8", timeout: 2_000 });
      assert.equal(created.status, 0, created.stderr);
      const child = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          [
            'import { loadRotationEndorsementFile } from "./dist/src/rotation.js";',
            "try {",
            "  await loadRotationEndorsementFile(process.argv[1]);",
            "  process.exit(1);",
            "} catch (error) {",
            "  process.exit(/must be a regular file/u.test(error.message) ? 0 : 1);",
            "}",
          ].join("\n"),
          fifo,
        ],
        { encoding: "utf8", timeout: 2_000 },
      );
      assert.notEqual((child.error as NodeJS.ErrnoException | undefined)?.code, "ETIMEDOUT");
      assert.equal(child.status, 0, child.stderr);
    }

    await assert.rejects(loadRotationEndorsementFile(dir), /must be a regular file/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rotation endorsements cannot be combined with allow-unpinned", () => {
  const result = spawnSync(
    process.execPath,
    [
      "dist/src/cli.js",
      "chain",
      g1RotatedCloseCountValid,
      "--rotation-endorsement",
      g1RotationEndorsement,
      "--allow-unpinned",
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 64);
  assert.match(result.stderr, /cannot be combined with --allow-unpinned/u);
});

test("g1 rotated close receipt_count invalid fixture is rejected", async () => {
  const result = await verifyChain(extractReceipts(g1RotatedCloseCountInvalid), trustedKeys());
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /session_close receipt_count mismatch/u);
});

test("chain CLI rejects a lifecycle-broken but signature-valid chain", () => {
  const result = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "chain", g1ValidChain, "--key", trustedKeys().split(",")[0]!, "--json"],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout) as { valid: boolean; error?: string };
  assert.equal(report.valid, false);
  assert.match(report.error ?? "", /lifecycle: chain_broken/u);
});

test("chain CLI preserves a chain trust failure over lifecycle assessment", () => {
  const result = spawnSync(
    process.execPath,
    ["dist/src/cli.js", "chain", g1ValidChain, "--key", "00".repeat(32), "--json"],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout) as { valid: boolean; error?: string };
  assert.equal(report.valid, false);
  assert.match(report.error ?? "", /not in the trusted set/u);
  assert.doesNotMatch(report.error ?? "", /lifecycle:/u);
});

test("g1 plain action after close fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1PlainAfterClose), key);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /record observed after session_close/u);
});

test("g1 empty run_nonce action after close fixture verifies", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1EmptyRunNonceAfterClose), key);
  assert.equal(result.valid, true, result.error);
});

test("g1 heartbeat after close fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1HeartbeatAfterClose), key);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /record observed after session_close/u);
});

test("g1 close without open fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1CloseWithoutOpen), key);
  assert.equal(result.valid, false);
  assert.equal(result.integrity_verified, true);
  assert.equal(result.failure_kind, "lifecycle_missing_open");
  assert.match(result.error ?? "", /first receipt is not a matching session_open/u);
});

test("endorsement verification does not skip root trust after lifecycle-only failure", async () => {
  const result = await verifyChainWithEndorsements(
    extractReceipts(g1CloseWithoutOpen),
    "0".repeat(64),
    { sessionID: "conformance-session", endorsements: [] },
  );

  assert.equal(result.valid, false);
  assert.notEqual(result.failure_kind, "lifecycle_missing_open");
  assert.match(result.error ?? "", /genesis signer key is not in the trusted root set/u);
});

test("g1 new session after close fixture verifies", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1NewSessionAfterClose), key);
  assert.equal(result.valid, true, result.error);
});

test("g1 re-open closed run fixture is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const result = await verifyChain(extractReceipts(g1ReopenClosedRun), key);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /duplicate session_open for run_nonce/u);
});

test("g1 session_control missing record run_nonce is rejected with valid signature", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const receipts = JSON.parse(JSON.stringify(extractReceipts(g1ValidChain))) as Receipt[];
  delete (receipts[3]!.action_record as Record<string, unknown>)["run_nonce"];
  await signActionReceiptWithTestKey(receipts[3]!);

  const result = await verifyChain(receipts, key);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_seq, 3);
  assert.match(result.error ?? "", /session_control receipt missing run_nonce/u);
});

test("signed malformed lifecycle controls fail closed through the chain CLI", async () => {
  type ControlCase = {
    name: string;
    mutate: (receipts: Receipt[]) => void;
    directError?: RegExp;
    cliError: RegExp;
  };
  const cases: ControlCase[] = [
    {
      name: "missing heartbeat payload",
      mutate: (receipts) => {
        delete (receipts[3]!.action_record!.session_control as Record<string, unknown>)[
          "heartbeat"
        ];
      },
      directError: /session_control must carry exactly one payload/u,
      cliError: /session_control must carry exactly one payload/u,
    },
    {
      name: "null heartbeat payload",
      mutate: (receipts) => {
        (receipts[3]!.action_record!.session_control as Record<string, unknown>)["heartbeat"] =
          null;
      },
      directError: /session_control must carry exactly one payload/u,
      cliError: /session_control must carry exactly one payload/u,
    },
    {
      name: "missing close payload",
      mutate: (receipts) => {
        delete (receipts[4]!.action_record!.session_control as Record<string, unknown>)["close"];
      },
      directError: /session_control must carry exactly one payload/u,
      cliError: /session_control must carry exactly one payload/u,
    },
    {
      name: "null close payload",
      mutate: (receipts) => {
        (receipts[4]!.action_record!.session_control as Record<string, unknown>)["close"] = null;
      },
      directError: /session_control must carry exactly one payload/u,
      cliError: /session_control must carry exactly one payload/u,
    },
    {
      name: "heartbeat run_nonce mismatch",
      mutate: (receipts) => {
        const heartbeat = (receipts[3]!.action_record!.session_control as Record<string, unknown>)[
          "heartbeat"
        ] as Record<string, unknown>;
        heartbeat["run_nonce"] = "other-run";
      },
      directError: /session_control run_nonce mismatch/u,
      cliError: /session_control run_nonce mismatch/u,
    },
    {
      name: "close run_nonce mismatch",
      mutate: (receipts) => {
        const close = (receipts[4]!.action_record!.session_control as Record<string, unknown>)[
          "close"
        ] as Record<string, unknown>;
        close["run_nonce"] = "other-run";
      },
      directError: /session_control run_nonce mismatch/u,
      cliError: /session_control run_nonce mismatch/u,
    },
    {
      name: "missing beat with malformed durability counter",
      mutate: (receipts) => {
        const heartbeat = (receipts[3]!.action_record!.session_control as Record<string, unknown>)[
          "heartbeat"
        ] as Record<string, unknown>;
        delete heartbeat["beat"];
        heartbeat["fsync_errors_gated"] = "malformed-counter";
      },
      cliError: /lifecycle: chain_broken/u,
    },
  ];

  for (const testCase of cases) {
    const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-signed-control-"));
    try {
      const entries = readEntries(g1ValidChain);
      const receipts = entries.map((entry) => entry.detail as Receipt);
      testCase.mutate(receipts);
      await resignG1Tail(receipts, 3);
      const file = join(dir, "evidence.jsonl");
      writeFileSync(file, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
        mode: 0o600,
      });

      const direct = await verifyChain(extractReceipts(file), trustedKeys().split(",")[0]!);
      if (testCase.directError === undefined) {
        assert.equal(direct.valid, true, `${testCase.name}: ${direct.error}`);
      } else {
        assert.equal(direct.valid, false, `${testCase.name} unexpectedly verified`);
        assert.match(direct.error ?? "", testCase.directError, testCase.name);
        assert.doesNotMatch(direct.error ?? "", /signature/u, testCase.name);
      }

      const cli = spawnSync(
        process.execPath,
        ["dist/src/cli.js", "chain", file, "--key", trustedKeys().split(",")[0]!, "--json"],
        { encoding: "utf8", timeout: 10_000 },
      );
      assert.equal(cli.status, 1, `${testCase.name}: ${cli.stderr}`);
      const report = JSON.parse(cli.stdout) as { valid: boolean; error?: string };
      assert.equal(report.valid, false, testCase.name);
      assert.match(report.error ?? "", testCase.cliError, testCase.name);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("g1 signed field tampering is rejected", async () => {
  const key = (JSON.parse(readFileSync(testKey, "utf8")) as { public_key_hex: string })
    .public_key_hex;
  const cases: Array<[string, (receipts: Receipt[]) => void]> = [
    [
      "session_open_posture_signer_key_id",
      (receipts) => {
        const open = (receipts[0]!.action_record!.session_control as Record<string, unknown>)[
          "open"
        ] as Record<string, unknown>;
        open["posture_signer_key_id"] = "posture-key-tampered";
      },
    ],
    [
      "decision_phase",
      (receipts) => {
        receipts[1]!.action_record!.decision_phase = "outcome";
      },
    ],
    [
      "heartbeat_beat",
      (receipts) => {
        const heartbeat = (receipts[3]!.action_record!.session_control as Record<string, unknown>)[
          "heartbeat"
        ] as Record<string, unknown>;
        heartbeat["beat"] = 2;
      },
    ],
    [
      "heartbeat_fsync_errors_gated",
      (receipts) => {
        const heartbeat = (receipts[3]!.action_record!.session_control as Record<string, unknown>)[
          "heartbeat"
        ] as Record<string, unknown>;
        heartbeat["fsync_errors_gated"] = 99;
      },
    ],
    [
      "close_root_hash",
      (receipts) => {
        const close = (receipts[4]!.action_record!.session_control as Record<string, unknown>)[
          "close"
        ] as Record<string, unknown>;
        close["root_hash"] = "tampered-root";
      },
    ],
    [
      "close_durability_blocks",
      (receipts) => {
        const close = (receipts[4]!.action_record!.session_control as Record<string, unknown>)[
          "close"
        ] as Record<string, unknown>;
        close["durability_blocks"] = 99;
      },
    ],
  ];
  for (const [name, mutate] of cases) {
    const receipts = JSON.parse(JSON.stringify(extractReceipts(g1ValidChain))) as Receipt[];
    mutate(receipts);
    const result = await verifyChain(receipts, key);
    assert.equal(result.valid, false, `${name} unexpectedly verified`);
    assert.match(result.error ?? "", /signature/u, name);
  }
});

test("broken chain_prev_hash is rejected", async () => {
  const result = await verifyChain(extractReceipts(brokenChain), "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /chain_prev_hash mismatch/u);
});

test("chain_seq gap is rejected", async () => {
  const receipts = extractReceipts(validChain);
  receipts.splice(2, 1);
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /seq gap/u);
});

test("first receipt must link to genesis", async () => {
  const receipts = extractReceipts(validChain);
  receipts[0]!.action_record!.chain_prev_hash = "not-genesis";
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /signature|chain_prev_hash/u);
});

test("mixed signer keys are rejected without pinned key", async () => {
  const receipts = extractReceipts(validChain);
  receipts[1]!.signer_key = "0".repeat(64);
  const result = await verifyChain(receipts, "", { allowUnpinned: true });
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /does not match expected key/u);
});

test("EvidenceReceipt v2 multi-receipt chain verifies with pinned key", async () => {
  const receipts = await buildEvidenceChain(2);
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, true, result.error);
  assert.equal(result.receipt_count, 2);
  assert.equal(result.final_seq, 1);
});

test("EvidenceReceipt v2 valid 1-receipt chain after pop", async () => {
  const receipts = await buildEvidenceChain(2);
  receipts.pop();
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, true, result.error);
});

test("EvidenceReceipt v2 tampered chain fails closed", async () => {
  const tampered = await buildEvidenceChain(2);
  tampered[1]!.chain_prev_hash = "sha256:0";
  const broken = await verifyChain(tampered, v2GoldenPublicKey);
  assert.equal(broken.valid, false);
  assert.match(broken.error ?? "", /signature|chain_prev_hash/u);
});

test("EvidenceReceipt v2 truncated middle receipt fails closed", async () => {
  const receipts = await buildEvidenceChain(3);
  receipts.splice(1, 1);
  const result = await verifyChain(receipts, v2GoldenPublicKey);
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /signature|seq gap/u);
});

test("malformed JSONL raises an error", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "malformed.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"noop","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n{"bad":\n',
      { mode: 0o600 },
    );
    assert.throws(() => extractReceipts(file), /line 2/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader accepts namespaced v3 entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "v3.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":3,"seq":0,"ts":"2026-08-07T00:00:00Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"writer-a","type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n',
      { mode: 0o600 },
    );
    assert.equal(extractReceipts(file).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects v3 entries without a complete namespace", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const [name, namespace] of [
      ["missing-kind", '"writer_instance_id":"writer-a",'],
      ["missing-writer", '"chain_kind":"recorder",'],
    ]) {
      const file = join(dir, `${name}.jsonl`);
      writeFileSync(
        file,
        `{"v":3,"seq":0,"ts":"2026-08-07T00:00:00Z","session_id":"s",${namespace}"type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n`,
        { mode: 0o600 },
      );
      assert.throws(() => extractReceipts(file), /v3 (chain_kind|writer_instance_id) required/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects namespace fields on legacy entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "v2-namespace.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":2,"seq":0,"ts":"2026-08-07T00:00:00Z","session_id":"s","chain_kind":"recorder","type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n',
      { mode: 0o600 },
    );
    assert.throws(() => extractReceipts(file), /legacy entry cannot carry/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects NUL in legacy projected strings", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const version of [1, 2]) {
      const file = join(dir, `v${version}-nul.jsonl`);
      writeFileSync(
        file,
        `${JSON.stringify({ v: version, seq: 0, ts: "2026-08-07T00:00:00Z", session_id: "x\0y", type: "checkpoint", transport: "x", summary: "", detail: {}, prev_hash: "genesis", hash: "h" })}\n`,
        { mode: 0o600 },
      );
      assert.throws(() => extractReceipts(file), /cannot contain NUL/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader preserves legacy null compatibility", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const version of [1, 2]) {
      const file = join(dir, `v${version}-null.jsonl`);
      writeFileSync(
        file,
        `${JSON.stringify({ v: version, seq: 0, ts: "2026-08-07T00:00:00Z", session_id: "s", trace_id: null, type: "checkpoint", transport: "x", summary: "", detail: {}, prev_hash: "genesis", hash: "h" })}\n`,
        { mode: 0o600 },
      );
      assert.doesNotThrow(() => extractReceipts(file));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects malformed legacy namespace field types", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const [name, value] of [
      ["object", "{}"],
      ["array", "[]"],
      ["number", "1"],
      ["boolean", "true"],
    ]) {
      const file = join(dir, `${name}.jsonl`);
      writeFileSync(
        file,
        `{"v":2,"seq":0,"ts":"2026-08-07T00:00:00Z","session_id":"s","chain_kind":${value},"type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}\n`,
        { mode: 0o600 },
      );
      assert.throws(() => extractReceipts(file), /legacy entry cannot carry/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects NUL in every v3 projected string", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const field of [
      "ts",
      "session_id",
      "chain_kind",
      "writer_instance_id",
      "trace_id",
      "type",
      "event_kind",
      "transport",
      "summary",
      "raw_ref",
      "prev_hash",
    ]) {
      const file = join(dir, `v3-nul-${field}.jsonl`);
      const entry: Record<string, unknown> = {
        v: 3,
        seq: 0,
        ts: "2026-08-07T00:00:00Z",
        session_id: "s",
        chain_kind: "recorder",
        writer_instance_id: "writer-a",
        type: "checkpoint",
        transport: "x",
        summary: "",
        detail: {},
        prev_hash: "genesis",
        hash: "h",
      };
      entry[field] = "a\0b";
      writeFileSync(file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      assert.throws(() => extractReceipts(file), new RegExp(`${field} cannot contain NUL`, "u"));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects v3 delimiter-collision pair", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "v3-collision.jsonl");
  try {
    const base = {
      v: 3,
      seq: 0,
      ts: "2026-08-07T00:00:00Z",
      session_id: "s",
      chain_kind: "recorder",
      writer_instance_id: "writer-a",
      type: "z",
      transport: "x",
      summary: "",
      detail: {},
      prev_hash: "genesis",
      hash: "h",
    };
    const colliding = [
      { ...base, trace_id: "x\0y", type: "z" },
      { ...base, trace_id: "x", type: "y\0z" },
    ];
    writeFileSync(file, `${colliding.map((entry) => JSON.stringify(entry)).join("\n")}\n`, {
      mode: 0o600,
    });
    assert.throws(() => extractReceipts(file), /trace_id cannot contain NUL/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects non-string v3 projected fields", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const field of ["ts", "session_id", "trace_id", "type", "prev_hash"]) {
      const file = join(dir, `v3-type-${field}.jsonl`);
      const entry: Record<string, unknown> = {
        v: 3,
        seq: 0,
        ts: "2026-08-07T00:00:00Z",
        session_id: "s",
        chain_kind: "recorder",
        writer_instance_id: "writer-a",
        type: "checkpoint",
        transport: "x",
        summary: "",
        prev_hash: "genesis",
      };
      entry[field] = 1;
      writeFileSync(file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
      assert.throws(() => extractReceipts(file), new RegExp(`${field} must be a string`, "u"));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects null and malformed v3 timestamps", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const [name, ts] of [
      ["omitted", undefined],
      ["null", null],
      ["malformed", "not-a-time"],
    ]) {
      const file = join(dir, `v3-ts-${name}.jsonl`);
      writeFileSync(
        file,
        `${JSON.stringify({ v: 3, seq: 0, ts, session_id: "s", chain_kind: "recorder", writer_instance_id: "writer-a", type: "checkpoint", transport: "x", summary: "", prev_hash: "genesis" })}\n`,
        { mode: 0o600 },
      );
      assert.throws(() => extractReceipts(file), /ts required|recorder ts|ts must be a string/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader rejects invalid v3 sequences", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  try {
    for (const [name, seqField] of [
      ["missing", ""],
      ["null", '"seq":null,'],
      ["negative", '"seq":-1,'],
      ["fractional", '"seq":1.5,'],
      ["overflow", '"seq":18446744073709551616,'],
    ]) {
      const file = join(dir, `v3-seq-${name}.jsonl`);
      writeFileSync(
        file,
        `{"v":3,${seqField}"ts":"2026-08-07T00:00:00Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"writer-a","type":"checkpoint","transport":"x","summary":"","prev_hash":"genesis"}\n`,
        { mode: 0o600 },
      );
      assert.throws(() => extractReceipts(file), /v3 seq|exceeds cross-language exact range/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder reader preserves maximum uint64 v3 sequence", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "v3-seq-max.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":3,"seq":18446744073709551615,"ts":"2026-08-07T00:00:00Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"writer-a","type":"checkpoint","transport":"x","summary":"","prev_hash":"genesis"}\n',
      { mode: 0o600 },
    );
    const entries = readEntries(file);
    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.seq, "18446744073709551615");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder extraction rejects duplicate keys inside receipt detail", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "duplicate-key.jsonl");
  try {
    writeFileSync(
      file,
      '{"v":1,"seq":0,"ts":"2026-05-10T00:00:00Z","session_id":"s","type":"action_receipt","transport":"https","summary":"","detail":{"version":1,"action_record":{"version":1,"action_id":"x","action_type":"write","timestamp":"2026-04-15T12:00:00Z","target":"https://e.example","verdict":"allow","verdict":"block","transport":"https","chain_prev_hash":"genesis","chain_seq":0},"signature":"ed25519:00","signer_key":"00"},"prev_hash":"genesis","hash":"h"}\n',
      { mode: 0o600 },
    );
    assert.throws(() => extractReceipts(file), /duplicate object key/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("JSONL recorder extraction rejects invalid UTF-8", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-verifier-"));
  const file = join(dir, "invalid-utf8.jsonl");
  try {
    writeFileSync(file, Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]));
    assert.throws(() => extractReceipts(file), /invalid UTF-8/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

async function buildEvidenceChain(count: number): Promise<Receipt[]> {
  const base = JSON.parse(readFileSync(validPlainV2, "utf8")) as Receipt;
  const receipts: Receipt[] = [];
  let prevHash = "genesis";
  for (let i = 0; i < count; i++) {
    const receipt = JSON.parse(JSON.stringify(base)) as Receipt;
    receipt.event_id = `01F8MECHZX3TBDSZ7XRADM79V${i}`;
    receipt.chain_seq = i;
    receipt.chain_prev_hash = prevHash;
    await signEvidenceReceipt(receipt);
    receipts.push(receipt);
    prevHash = receiptHash(receipt);
  }
  return receipts;
}

async function signEvidenceReceipt(receipt: Receipt): Promise<void> {
  const signature = receipt.signature as JSONObject;
  receipt.signature = {
    signer_key_id: "",
    key_purpose: "",
    algorithm: "",
    signature: "",
  };
  const sig = await ed25519.signAsync(
    canonicalizeBytes(receipt),
    Buffer.from(v2PrivateSeedHex, "hex"),
  );
  receipt.signature = {
    signer_key_id: signature["signer_key_id"] ?? "receipt-signing-test",
    key_purpose: "receipt-signing",
    algorithm: "ed25519",
    signature: `ed25519:${Buffer.from(sig).toString("hex")}`,
  };
}

async function signActionReceiptWithTestKey(receipt: Receipt): Promise<void> {
  const keyInfo = JSON.parse(readFileSync(testKey, "utf8")) as {
    public_key_hex: string;
    seed_hex: string;
  };
  await signActionReceiptWithKey(receipt, keyInfo.seed_hex, keyInfo.public_key_hex);
}

async function resignG1Tail(receipts: Receipt[], start: number): Promise<void> {
  let previousHash = receiptHash(receipts[start - 1]!);
  for (let i = start; i < receipts.length; i++) {
    const receipt = receipts[i]!;
    const record = receipt.action_record!;
    record.chain_prev_hash = previousHash;
    const control = record.session_control as Record<string, unknown> | undefined;
    if (control?.["kind"] === "session_close") {
      const close = control["close"];
      if (typeof close === "object" && close !== null && !Array.isArray(close)) {
        (close as Record<string, unknown>)["root_hash"] = previousHash;
      }
    }
    await signActionReceiptWithTestKey(receipt);
    previousHash = receiptHash(receipt);
  }
}

async function signActionReceiptWithKey(
  receipt: Receipt,
  seedHex: string,
  publicKeyHex: string,
): Promise<void> {
  const digest = createHash("sha256")
    .update(canonicalizeActionRecord(receipt.action_record!))
    .digest();
  const sig = await ed25519.signAsync(digest, Buffer.from(seedHex, "hex"));
  receipt.signature = `ed25519:${Buffer.from(sig).toString("hex")}`;
  receipt.signer_key = publicKeyHex;
}

function trustedKeys(): string {
  const keyInfo = JSON.parse(readFileSync(testKey, "utf8")) as {
    public_key_hex: string;
    rotated_public_key_hex: string;
  };
  return `${keyInfo.public_key_hex},${keyInfo.rotated_public_key_hex}`;
}

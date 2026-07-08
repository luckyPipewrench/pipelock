import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import * as ed25519 from "@noble/ed25519";
import { canonicalizeBytes } from "../src/aarp/canonical.js";
import { canonicalizeActionRecord } from "../src/canonical.js";
import { extractReceipts } from "../src/recorder.js";
import { computeSessionOpenGenesis, receiptHash, verifyChain } from "../src/chain.js";
import type { JSONObject, Receipt } from "../src/types.js";

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
const g1RotatedCloseCountInvalid =
  "../../conformance/testdata/g1-rotated-close-count-invalid.jsonl";
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

test("g1 rotated close receipt_count invalid fixture is rejected", async () => {
  const result = await verifyChain(extractReceipts(g1RotatedCloseCountInvalid), trustedKeys());
  assert.equal(result.valid, false);
  assert.match(result.error ?? "", /session_close receipt_count mismatch/u);
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
  assert.match(result.error ?? "", /first receipt is not a matching session_open/u);
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
  const digest = createHash("sha256")
    .update(canonicalizeActionRecord(receipt.action_record!))
    .digest();
  const sig = await ed25519.signAsync(digest, Buffer.from(keyInfo.seed_hex, "hex"));
  receipt.signature = `ed25519:${Buffer.from(sig).toString("hex")}`;
  receipt.signer_key = keyInfo.public_key_hex;
}

function trustedKeys(): string {
  const keyInfo = JSON.parse(readFileSync(testKey, "utf8")) as {
    public_key_hex: string;
    rotated_public_key_hex: string;
  };
  return `${keyInfo.public_key_hex},${keyInfo.rotated_public_key_hex}`;
}

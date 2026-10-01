// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as ed25519 from "@noble/ed25519";
import { canonicalizeBytes } from "../src/aarp/canonical.js";
import { runReceipt } from "../src/receipt.js";
import { extractTypedReceipts, readEntries } from "../src/recorder.js";
import { normalizeEvidenceReceipt, verifyReceipt } from "../src/signing.js";
import {
  secretEgressDecisionKind,
  validateSecretEgressDecision,
  validateSecretEgressEnvelope,
  validateSecretEgressPayload,
} from "../src/secret-egress.js";
import type { Receipt } from "../src/types.js";
import { rejectDuplicateKeys } from "../src/util.js";

const decisions = "../../../internal/egressevidence/testdata/decision-v1";
const corpus = "../../conformance/testdata/secret-egress-v1";
const publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const privateSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const registryHash = "sha256:" + "a".repeat(64);
function decision(): Record<string, unknown> {
  return JSON.parse(readFileSync(`${decisions}/intent-block.json`, "utf8")) as Record<
    string,
    unknown
  >;
}
function receipt(d = decision()): Receipt {
  const r = JSON.parse(
    readFileSync(
      "../../../internal/contract/testdata/golden/valid_evidence_receipt_proxy_decision.json",
      "utf8",
    ),
  ) as Receipt;
  r.payload_kind = secretEgressDecisionKind;
  r.crit = ["canonicalization", secretEgressDecisionKind];
  r.payload = { registry_hash: registryHash, decision: d };
  return r;
}
async function sign(r: Receipt): Promise<Receipt> {
  r.signature = { signer_key_id: "", key_purpose: "", algorithm: "", signature: "" };
  const sig = await ed25519.signAsync(canonicalizeBytes(r), Buffer.from(privateSeed, "hex"));
  r.signature = {
    signer_key_id: publicKey,
    key_purpose: "receipt-signing",
    algorithm: "ed25519",
    signature: `ed25519:${Buffer.from(sig).toString("hex")}`,
  };
  return r;
}

test("secret-egress: frozen unsigned model fixtures agree", () => {
  const manifest = JSON.parse(readFileSync(`${decisions}/manifest.json`, "utf8")) as {
    fixtures: { id: string; file: string; valid: boolean }[];
  };
  for (const entry of manifest.fixtures) {
    const raw = readFileSync(`${decisions}/${entry.file}`, "utf8");
    const validate = (): void => {
      rejectDuplicateKeys(raw);
      validateSecretEgressDecision(JSON.parse(raw) as unknown);
    };
    if (entry.valid) assert.doesNotThrow(validate, entry.id);
    else assert.throws(validate, entry.id);
  }
});

test("secret-egress: every shared signed corpus row agrees", async () => {
  const manifest = JSON.parse(readFileSync(`${corpus}/manifest.json`, "utf8")) as {
    version: number;
    public_key_hex: string;
    cases: { name: string; file: string; valid: boolean }[];
  };
  assert.equal(manifest.version, 1);
  assert.ok(manifest.cases.length > 0);
  for (const entry of manifest.cases) {
    const report = await runReceipt(`${corpus}/${entry.file}`, manifest.public_key_hex);
    assert.equal(report.valid, entry.valid, `${entry.name}: ${report.error ?? "accepted"}`);
  }
});

test("secret-egress: retained decision fields are required, exact, typed, and non-null", () => {
  const base = decision();
  for (const key of Object.keys(base)) {
    const missing = { ...base };
    delete missing[key];
    assert.throws(() => validateSecretEgressDecision(missing), `missing ${key}`);
    assert.throws(() => validateSecretEgressDecision({ ...base, [key]: null }), `null ${key}`);
    assert.throws(
      () => validateSecretEgressDecision({ ...missing, [key.toUpperCase()]: base[key] }),
      `case ${key}`,
    );
    assert.throws(() => validateSecretEgressDecision({ ...base, [key]: [] }), `array ${key}`);
  }
  for (const bad of [
    null,
    [],
    false,
    "",
    { ...base, unknown: 1 },
    { ...base, action_id: base["decision_id"] },
    { ...base, action_id: String(base["action_id"]) + "\n" },
  ])
    assert.throws(() => validateSecretEgressDecision(bad));
  for (const key of ["registry_hash", "decision"]) {
    const payload: Record<string, unknown> = { registry_hash: registryHash, decision: base };
    delete payload[key];
    assert.throws(() => validateSecretEgressPayload(payload));
  }
  for (const hash of [registryHash.toUpperCase(), registryHash + "\n", "a".repeat(64), null])
    assert.throws(() => validateSecretEgressPayload({ registry_hash: hash, decision: base }));
  assert.throws(() =>
    validateSecretEgressPayload({ registry_hash: registryHash, decision: base, extra: false }),
  );
});

test("secret-egress: nested authority, rewrite, and outcome objects are strict", () => {
  const d = decision();
  for (const authorization of [
    null,
    [],
    {},
    { kind: "none", ref: "" },
    { kind: "none", origin: "" },
    { Kind: "none" },
    { kind: "none", extra: 1 },
  ])
    assert.throws(() => validateSecretEgressDecision({ ...d, authorization }));
  for (const disposition of ["authorize", "exempt"]) {
    const kind = disposition === "authorize" ? "authorization" : "exemption";
    for (const origin of ["builtin", "operator"])
      assert.doesNotThrow(() =>
        validateSecretEgressDecision({
          ...d,
          finding_disposition: disposition,
          planned_byte_form: "original",
          authorization: { kind, ref: "fixture.authority", origin },
        }),
      );
    for (const authorization of [
      { kind },
      { kind, ref: "fixture.authority" },
      { kind, ref: "", origin: "builtin" },
      { kind, ref: "fixture.authority", origin: "unknown" },
    ])
      assert.throws(() =>
        validateSecretEgressDecision({ ...d, finding_disposition: disposition, authorization }),
      );
  }
  const fallback = {
    reason: "no_safe_raw_span",
    policy_ref: "fixture.fallback",
    policy_origin: "operator",
  };
  const outcome = { release: "complete", byte_form: "original" };
  for (const [field, base] of [
    ["rewrite_fallback", fallback],
    ["outcome", outcome],
  ] as const) {
    const parent = field === "outcome" ? { ...d, phase: "outcome" } : d;
    for (const bad of [null, [], {}, { ...base, extra: 1 }])
      assert.throws(() => validateSecretEgressDecision({ ...parent, [field]: bad }));
    for (const key of Object.keys(base)) {
      const changed: Record<string, unknown> = { ...base };
      delete changed[key];
      assert.throws(() => validateSecretEgressDecision({ ...parent, [field]: changed }));
      assert.throws(() =>
        validateSecretEgressDecision({ ...parent, [field]: { ...base, [key]: null } }),
      );
      assert.throws(() =>
        validateSecretEgressDecision({
          ...parent,
          [field]: { ...changed, [key.toUpperCase()]: "x" },
        }),
      );
    }
  }
});

test("secret-egress: all typed transport and boundary pairs match frozen Go model", () => {
  const allowed: Record<string, string[]> = {
    fetch: ["upstream_request"],
    forward: ["upstream_request"],
    intercept: ["upstream_request"],
    reverse: ["upstream_request"],
    connect: ["tunnel_admission"],
    websocket: ["upstream_request", "upstream_frame"],
    mcp_stdio: ["upstream_request", "tool_dispatch"],
    mcp_http_upstream: ["upstream_request", "tool_dispatch"],
    mcp_ws: ["upstream_request", "tool_dispatch"],
    mcp_http_listener: ["upstream_request", "tool_dispatch"],
  };
  for (const [transport, boundaries] of Object.entries(allowed)) {
    for (const boundary of [
      "upstream_request",
      "upstream_frame",
      "tunnel_admission",
      "tool_dispatch",
      "hook_decision",
    ]) {
      const validate = (): void =>
        validateSecretEgressDecision({
          ...decision(),
          transport,
          boundary,
          ...(transport === "mcp_stdio"
            ? { destination_kind: "local_process", destination_ref: "configured.server" }
            : {}),
        });
      if (boundaries.includes(boundary)) assert.doesNotThrow(validate, `${transport}/${boundary}`);
      else assert.throws(validate, `${transport}/${boundary}`);
    }
    const local = (): void =>
      validateSecretEgressDecision({
        ...decision(),
        transport,
        boundary: boundaries[0],
        destination_kind: "local_process",
        destination_ref: "configured.server",
      });
    if (transport === "mcp_stdio") assert.doesNotThrow(local);
    else assert.throws(local);
  }
  for (const transport of ["mcp_stdio", "mcp_http", "mcp_websocket"]) {
    assert.throws(() => validateSecretEgressDecision({ ...decision(), transport }));
  }
  assert.throws(() =>
    validateSecretEgressDecision({
      ...decision(),
      plane: "hook",
      transport: "agent_hook",
      boundary: "hook_decision",
    }),
  );
});

test("secret-egress: planned/observed mismatches and core nonblock evidence remain representable", () => {
  for (const finding_disposition of ["block", "redact", "observe"]) {
    for (const release of ["none", "partial", "complete", "unknown"]) {
      for (const byte_form of ["none", "original", "transformed", "unknown"]) {
        const d = {
          ...decision(),
          phase: "outcome",
          finding_disposition,
          outcome: { release, byte_form },
        };
        if ((release === "none") === (byte_form === "none"))
          assert.doesNotThrow(() => validateSecretEgressDecision(d));
        else assert.throws(() => validateSecretEgressDecision(d));
      }
    }
  }
  assert.throws(() => validateSecretEgressDecision({ ...decision(), phase: "outcome" }));
  assert.throws(() =>
    validateSecretEgressDecision({
      ...decision(),
      outcome: { release: "none", byte_form: "none" },
    }),
  );
  assert.throws(() =>
    validateSecretEgressDecision({ ...decision(), planned_byte_form: "original" }),
  );
  assert.throws(() =>
    validateSecretEgressDecision({
      ...decision(),
      finding_disposition: "redact",
      planned_byte_form: "original",
    }),
  );
  assert.doesNotThrow(() =>
    validateSecretEgressDecision({
      ...decision(),
      finding_disposition: "redact",
      planned_byte_form: "transformed",
    }),
  );
});

test("secret-egress: canonical hostname and IP identities mirror destination parser", () => {
  const valid = [
    "api.vendor.example",
    "xn--fixture.example",
    "192.0.2.1",
    "2001:db8::1",
    "::",
    "::1",
    "2001:db8::1:0:0:1",
    "2001:db8:0:1:1:1:1:1",
    "::c000:201",
    "123.api.vendor.example",
    "0x.api.vendor.example",
    "api.vendor.0xnothex",
  ];
  const invalid = [
    "4294967296",
    "999.1.1.1",
    "09",
    "0x",
    "0x100000000",
    "api.vendor.123",
    "api.vendor.0x",
    "api.vendor.0xff",
    "192.0.2.1.1",
    "",
    "API.vendor.example",
    "api.vendor.example.",
    "https://api.vendor.example",
    "api.vendor.example:443",
    "api..example",
    "-api.example",
    "api-.example",
    "a".repeat(64) + ".example",
    "bad_host.example",
    "192.0.2.1\n",
    "192.000.002.001",
    "0300.0.2.1",
    "0xc0000201",
    "3221225985",
    "192.513",
    "192.0.513",
    "::ffff:192.0.2.1",
    "::ffff:c000:201",
    "[2001:db8::1]",
    "2001:0db8::1",
    "2001:DB8::1",
    "2001:db8:0:0:0:0:0:1",
    "2001:db8:0:1::1:1:1",
    "2001:db8::1%fixture",
    "::192.0.2.1",
  ];
  for (const destination_ref of valid)
    assert.doesNotThrow(
      () => validateSecretEgressDecision({ ...decision(), destination_ref }),
      destination_ref,
    );
  for (const destination_ref of invalid)
    assert.throws(
      () => validateSecretEgressDecision({ ...decision(), destination_ref }),
      destination_ref,
    );
});

test("secret-egress: envelope dispatch requires feature, policy, key purpose, and distinct event ID", () => {
  assert.doesNotThrow(() => normalizeEvidenceReceipt(receipt()));
  for (const crit of [
    [],
    ["canonicalization"],
    [secretEgressDecisionKind],
    ["canonicalization", secretEgressDecisionKind, secretEgressDecisionKind],
    ["canonicalization", secretEgressDecisionKind, "source_spans"],
  ])
    assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), crit }));
  for (const event_id of [String(decision()["action_id"]), String(decision()["decision_id"])])
    assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), event_id }));
  const missingPolicy = receipt();
  delete missingPolicy.policy_hash;
  assert.throws(() => normalizeEvidenceReceipt(missingPolicy));
  const wrongPurpose = receipt();
  wrongPurpose.signature = {
    ...(wrongPurpose.signature as Record<string, string>),
    key_purpose: "contract-signing",
  };
  assert.throws(() => normalizeEvidenceReceipt(wrongPurpose));
  const legacy = receipt();
  legacy.payload_kind = "proxy_decision";
  assert.throws(() => normalizeEvidenceReceipt(legacy));
});

test("secret-egress: signatures bind facts without authenticating registry membership", async () => {
  const r = await sign(receipt());
  await assert.doesNotReject(verifyReceipt(r, publicKey));
  (r.payload as Record<string, unknown>)["registry_hash"] = "sha256:" + "b".repeat(64);
  await assert.rejects(verifyReceipt(r, publicKey), /signature/u);
  await sign(r);
  await assert.doesNotReject(verifyReceipt(r, publicKey));
});

test("secret-egress: raw version spelling, duplicates, and size checked in file and recorder", async () => {
  const r = await sign(receipt());
  const source = JSON.stringify(r);
  const rawDecision = JSON.stringify((r.payload as Record<string, unknown>)["decision"]);
  const padded = rawDecision.slice(0, 1) + " ".repeat(16 * 1024) + rawDecision.slice(1);
  const variants = [
    source.replace('"version":1', '"version":1.0'),
    source.replace('"version":1', '"version":1e0'),
    source.replace(rawDecision, padded),
    source.replace('"kind":"none"', '"kind":"none","kind":"none"'),
  ];
  const dir = mkdtempSync(join(tmpdir(), "secret-egress-"));
  try {
    for (const [i, raw] of variants.entries()) {
      assert.notEqual(raw, source);
      const file = join(dir, `${i}.json`);
      writeFileSync(file, raw);
      const report = await runReceipt(file, publicKey);
      assert.equal(report.valid, false, `${i}: ${report.error ?? "accepted"}`);
      const recorder = join(dir, `${i}.jsonl`);
      writeFileSync(recorder, '{"v":1,"type":"evidence_receipt","detail":' + raw + "}\n");
      assert.throws(() => readEntries(recorder));
    }
    for (const size of [16 * 1024, 16 * 1024 + 1]) {
      const paddedDecision =
        rawDecision.slice(0, 1) +
        " ".repeat(size - Buffer.byteLength(rawDecision)) +
        rawDecision.slice(1);
      const boundedFile = join(dir, `bounded-${size}.json`);
      writeFileSync(boundedFile, source.replace(rawDecision, paddedDecision));
      const boundedReport = await runReceipt(boundedFile, publicKey);
      assert.equal(boundedReport.valid, size === 16 * 1024, boundedReport.error);
    }
    const reordered = Object.fromEntries(Object.entries(r).reverse());
    const file = join(dir, "reformatted.json");
    writeFileSync(file, JSON.stringify(reordered, null, 2) + "\n");
    const report = await runReceipt(file, publicKey);
    assert.equal(report.valid, true, report.error);
    assert.equal(report.transport, "forward");
    const actionID = (r.payload as { decision: { action_id: string } }).decision.action_id;
    assert.notEqual(actionID, r.event_id);
    assert.equal(report.action_id, actionID);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secret-egress: envelope required, optional, and nested keys follow dedicated profile", () => {
  const required = [
    "record_type",
    "receipt_version",
    "payload_kind",
    "canonicalization",
    "crit",
    "event_id",
    "timestamp",
    "signature",
    "chain_seq",
    "chain_prev_hash",
    "policy_hash",
    "payload",
  ];
  for (const field of required) {
    for (const mutation of ["missing", "null", "case"]) {
      const r = receipt();
      if (mutation === "null") r[field] = null;
      else {
        const value = r[field];
        delete r[field];
        if (mutation === "case") r[field.toUpperCase()] = value;
      }
      assert.throws(() => validateSecretEgressEnvelope(r), `${field}/${mutation}`);
    }
  }
  for (const field of [
    "principal",
    "actor",
    "active_manifest_hash",
    "contract_hash",
    "selector_id",
  ]) {
    for (const value of [null, "", [], {}, 1, false])
      assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), [field]: value }));
  }
  for (const delegation_chain of [null, [], [""], [null], [1], [false], {}, "actor"])
    assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), delegation_chain }));
  for (const [field, minimum] of [
    ["chain_seq", 0],
    ["contract_generation", 1],
  ] as const) {
    for (const value of [null, true, false, -1, -0, 1.5, "1", 9007199254740992])
      assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), [field]: value }));
    for (const value of [minimum, Number.MAX_SAFE_INTEGER])
      assert.doesNotThrow(() => normalizeEvidenceReceipt({ ...receipt(), [field]: value }));
  }
  for (const field of ["canonicalization", "signature"] as const) {
    for (const key of Object.keys(receipt()[field] as Record<string, unknown>)) {
      for (const value of [null, "", [], false, 1]) {
        const r = receipt();
        (r[field] as Record<string, unknown>)[key] = value;
        assert.throws(() => normalizeEvidenceReceipt(r));
      }
    }
  }
});

test("secret-egress: envelope integer source spelling survives standalone and recorder reads", async () => {
  const r = receipt();
  r.contract_generation = 1;
  r.chain_seq = 0;
  await sign(r);
  const source = JSON.stringify(r);
  const dir = mkdtempSync(join(tmpdir(), "egress-envelope-"));
  try {
    for (const [field, literal] of [
      ["receipt_version", "2.0"],
      ["receipt_version", "2e0"],
      ["chain_seq", "-0"],
      ["chain_seq", "0.0"],
      ["chain_seq", "0e0"],
      ["contract_generation", "1.0"],
      ["contract_generation", "1e0"],
    ]) {
      const raw = source.replace(`"${field}":${r[field]}`, `"${field}":${literal}`);
      assert.notEqual(raw, source);
      const file = join(dir, "receipt.json");
      writeFileSync(file, raw);
      const report = await runReceipt(file, publicKey);
      assert.equal(report.valid, false, `${field}: ${report.error}`);
      const recorder = join(dir, "recorder.jsonl");
      writeFileSync(recorder, '{"v":1,"type":"evidence_receipt","detail":' + raw + "}\n");
      assert.throws(() => readEntries(recorder));
    }
    Object.assign(r, {
      principal: "fixture.principal",
      actor: "fixture.actor",
      delegation_chain: ["fixture.delegation"],
      active_manifest_hash: "fixture.manifest",
      contract_hash: "fixture.contract",
      selector_id: "fixture.selector",
    });
    await sign(r);
    const file = join(dir, "valid.json");
    writeFileSync(file, JSON.stringify(r));
    const report = await runReceipt(file, publicKey);
    assert.equal(report.valid, true, report.error);
    assert.equal(report.transport, "forward");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secret-egress: canonical UTC timestamp profile has calendar and lexical parity", () => {
  const valid = [
    "2026-09-30T12:34:56Z",
    "2026-09-30T12:34:56.123456789Z",
    "2026-09-30T12:34:56.000000001Z",
    "0000-02-29T00:00:00Z",
    "0001-01-01T00:00:00.1Z",
    "9999-12-31T23:59:59Z",
  ];
  const invalid = [
    "0001-01-01T00:00:00Z",
    "2026-02-29T12:34:56Z",
    "2026-09-30T24:00:00Z",
    "2026-09-30T12:60:00Z",
    "2026-09-30T12:34:60Z",
    "2026-09-30T12:34:56.0Z",
    "2026-09-30T12:34:56.10Z",
    "2026-09-30T12:34:56.1234567891Z",
    "2026-09-30T12:34:56+00:00",
    "2026-09-30T12:34:56-00:00",
    "2026-09-30T12:34:56+01:00",
    "2026-09-30T1:34:56Z",
    "2026-09-30T12:34:56,1Z",
    "2026-09-30T12:34:56Z\n",
    "2026-00-30T12:34:56Z",
    "2026-09-00T12:34:56Z",
  ];
  for (const timestamp of valid)
    assert.doesNotThrow(() => normalizeEvidenceReceipt({ ...receipt(), timestamp }), timestamp);
  for (const timestamp of invalid)
    assert.throws(() => normalizeEvidenceReceipt({ ...receipt(), timestamp }), timestamp);
});

test("secret-egress: timestamp wire token is unescaped ASCII in file and recorder", async () => {
  const r = await sign(receipt());
  const raw = JSON.stringify(r);
  const escaped = raw.replace(
    JSON.stringify(r.timestamp),
    '"\\u0032' + (r.timestamp as string).slice(1) + '"',
  );
  assert.notEqual(escaped, raw);
  assert.equal((JSON.parse(escaped) as Receipt).timestamp, r.timestamp);
  const dir = mkdtempSync(join(tmpdir(), "egress-timestamp-"));
  try {
    const file = join(dir, "timestamp.json");
    writeFileSync(file, raw);
    assert.equal((await runReceipt(file, publicKey)).valid, true);
    writeFileSync(file, escaped);
    const report = await runReceipt(file, publicKey);
    assert.equal(report.valid, false);
    assert.match(report.error ?? "", /raw timestamp spelling/u);
    const recorder = join(dir, "timestamp.jsonl");
    writeFileSync(recorder, '{"v":1,"type":"evidence_receipt","detail":' + raw + "}\n");
    assert.equal(readEntries(recorder).length, 1);
    writeFileSync(recorder, '{"v":1,"type":"evidence_receipt","detail":' + escaped + "}\n");
    assert.throws(() => readEntries(recorder), /raw timestamp spelling/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secret-egress: signature encoding is exact lowercase ASCII without whitespace", async () => {
  const r = await sign(receipt());
  const proof = (r.signature as Record<string, string>)["signature"];
  const variants = [
    "ed25519:" + proof.slice(8).toUpperCase(),
    "ED25519:" + proof.slice(8),
    " " + proof,
    proof + " ",
    proof.slice(0, 10) + " " + proof.slice(10),
    proof + "\n",
    proof + "\t",
    "ed25519:ａ" + proof.slice(9),
    proof.slice(0, -1),
    proof + "a",
  ];
  const dir = mkdtempSync(join(tmpdir(), "egress-signature-"));
  try {
    for (const signature of variants) {
      const changed = {
        ...r,
        signature: { ...(r.signature as Record<string, string>), signature },
      };
      assert.throws(() => normalizeEvidenceReceipt(changed), /lowercase signature encoding/u);
      const raw = JSON.stringify(changed);
      const file = join(dir, "receipt.json");
      writeFileSync(file, raw);
      const report = await runReceipt(file, publicKey);
      assert.equal(report.valid, false);
      assert.match(report.error ?? "", /lowercase signature encoding/u);
      const recorder = join(dir, "signature.jsonl");
      writeFileSync(recorder, '{"v":1,"type":"evidence_receipt","detail":' + raw + "}\n");
      assert.throws(() => readEntries(recorder), /lowercase signature encoding/u);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function redactedDecision(): Record<string, unknown> {
  const d = decision();
  delete d["destination_ref"];
  d["destination_redaction"] = { reason: "classified_sensitive" };
  return d;
}

test("secret-egress: redacted destination preserves the carrier/kind matrix", () => {
  for (const [transport, boundary] of [
    ["fetch", "upstream_request"],
    ["forward", "upstream_request"],
    ["connect", "tunnel_admission"],
    ["intercept", "upstream_request"],
    ["reverse", "upstream_request"],
    ["websocket", "upstream_frame"],
    ["mcp_stdio", "tool_dispatch"],
    ["mcp_http_upstream", "tool_dispatch"],
    ["mcp_http_listener", "tool_dispatch"],
    ["mcp_ws", "tool_dispatch"],
  ]) {
    const d = {
      ...redactedDecision(),
      transport,
      boundary,
      destination_kind: transport === "mcp_stdio" ? "local_process" : "network",
    };
    assert.doesNotThrow(() => validateSecretEgressDecision(d));
    assert.equal(Object.hasOwn(d, "destination_ref"), false);
    d.destination_kind = transport === "mcp_stdio" ? "network" : "local_process";
    assert.throws(() => validateSecretEgressDecision(d));
  }
});

test("secret-egress: destination reference/redaction is a strict exclusive sum", () => {
  const invalid = [
    null,
    {},
    [],
    "classified_sensitive",
    1,
    false,
    { reason: null },
    { reason: "" },
    { reason: "unknown" },
    { reason: [] },
    { reason: "Classified_sensitive" },
    { Reason: "classified_sensitive" },
    { reason: "classified_sensitive", extra: "fixture" },
  ];
  for (const destination_redaction of invalid)
    assert.throws(() =>
      validateSecretEgressDecision({ ...redactedDecision(), destination_redaction }),
    );
  for (const destination_ref of [null, "", "api.vendor.example"])
    assert.throws(() => validateSecretEgressDecision({ ...redactedDecision(), destination_ref }));
  const absent = redactedDecision();
  delete absent["destination_redaction"];
  assert.throws(() => validateSecretEgressDecision(absent));
  assert.throws(() =>
    validateSecretEgressDecision({
      ...absent,
      Destination_redaction: { reason: "classified_sensitive" },
    }),
  );
  assert.throws(() => validateSecretEgressDecision({ ...decision(), destination_ref: "" }));
});

test("secret-egress: signed redacted destinations need no identity placeholder", async () => {
  for (const [destination_kind, transport] of [
    ["network", "forward"],
    ["local_process", "mcp_stdio"],
  ]) {
    const d = { ...redactedDecision(), destination_kind, transport };
    const r = await sign(receipt(d));
    await assert.doesNotReject(verifyReceipt(r, publicKey));
    assert.equal(Object.hasOwn(d, "destination_ref"), false);
  }
});

test("secret-egress: typed version value is separate from raw number spelling", async () => {
  const signed = await sign(receipt());
  const raw = JSON.stringify(signed);
  const dir = mkdtempSync(join(tmpdir(), "secret-egress-version-boundary-"));
  try {
    for (const token of ["1", "1.0", "1e0"]) {
      const source = raw.replace('"version":1,', `"version":${token},`);
      assert.equal(source === raw, token === "1");
      const typed = JSON.parse(source) as Receipt;
      assert.deepEqual(typed, signed);
      assert.equal(JSON.stringify(typed), raw);
      const d = (typed.payload as { decision: { version: number } }).decision;
      assert.equal(d.version, 1);
      assert.equal(Number.isInteger(d.version), true);
      assert.doesNotThrow(() => normalizeEvidenceReceipt(typed));
      await verifyReceipt(typed, publicKey);

      const path = join(dir, `${token}.json`);
      writeFileSync(path, source);
      const report = await runReceipt(path, publicKey);
      assert.equal(report.valid, token === "1", report.error);
      const recorderPath = join(dir, `${token}.jsonl`);
      writeFileSync(recorderPath, '{"v":1,"type":"evidence_receipt","detail":' + source + "}\n");
      if (token === "1") assert.doesNotThrow(() => readEntries(recorderPath));
      else assert.throws(() => readEntries(recorderPath));
    }
    const unsupported = JSON.parse(raw.replace('"version":1,', '"version":1.5,')) as Receipt;
    assert.throws(() => normalizeEvidenceReceipt(unsupported));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secret-egress: raw profile is scoped to evidence recorder entries", async () => {
  const signed = await sign(receipt());
  const dir = mkdtempSync(join(tmpdir(), "secret-egress-entry-scope-"));
  const path = join(dir, "entries.jsonl");
  const receiptLine = JSON.stringify({ v: 1, type: "evidence_receipt", detail: signed });
  const marker = { payload_kind: secretEgressDecisionKind };
  try {
    writeFileSync(path, receiptLine + "\n");
    const baseline = extractTypedReceipts(path);
    assert.equal(baseline.evidence.length, 1);
    await verifyReceipt(baseline.evidence[0]!, publicKey);

    for (const type of ["checkpoint", "transcript_root", "decision", "capture", "capture_drop"]) {
      for (const detail of [marker, { crit: [secretEgressDecisionKind] }]) {
        writeFileSync(path, JSON.stringify({ v: 1, type, detail }) + "\n" + receiptLine + "\n");
        assert.equal(readEntries(path).length, 2, type);
        const extracted = extractTypedReceipts(path);
        assert.equal(extracted.action.length, 0, type);
        assert.deepEqual(extracted.evidence, baseline.evidence, type);
      }
    }

    writeFileSync(path, JSON.stringify({ v: 1, type: "evidence_receipt", detail: marker }) + "\n");
    assert.throws(() => readEntries(path), /missing secret-egress field record_type/u);

    writeFileSync(path, JSON.stringify({ v: 1, type: "action_receipt", detail: signed }) + "\n");
    assert.throws(() => extractTypedReceipts(path), /unknown field .* signed v1/u);

    writeFileSync(path, JSON.stringify({ v: 1, type: "unrecognized", detail: marker }) + "\n");
    assert.throws(() => extractTypedReceipts(path), /unexpected recorder entry type/u);

    writeFileSync(path, JSON.stringify({ v: 4, type: "capture", detail: marker }) + "\n");
    assert.throws(() => readEntries(path), /unsupported entry version/u);
    writeFileSync(path, '{"v":1,"v":1,"type":"capture","detail":{}}\n');
    assert.throws(() => readEntries(path), /duplicate/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

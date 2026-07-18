// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { validateAuditPacket } from "../src/schema.js";
import type { AuditPacket } from "../src/types.js";

function example(): AuditPacket {
  return JSON.parse(readFileSync("../../audit-packet/example.json", "utf8")) as AuditPacket;
}

test("sdk audit-packet example passes schema and structural checks", () => {
  assert.deepEqual(validateAuditPacket(example()), []);
});

for (const field of [
  "schema_version",
  "generated_at",
  "run",
  "policy",
  "summary",
  "verifier",
  "posture",
  "artifacts",
]) {
  test(`missing ${field} fails clearly`, () => {
    const packet = example();
    delete packet[field];
    const errors = validateAuditPacket(packet);
    assert.ok(
      errors.some((err) => err.includes(field)),
      errors.join("\n"),
    );
  });
}

test("wrong schema_version fails", () => {
  const packet = example();
  packet.schema_version = "pipelock.audit_packet.v1";
  assert.ok(validateAuditPacket(packet).some((err) => err.includes("schema_version")));
});

test("unknown verifier verdict fails", () => {
  const packet = example();
  packet.verifier!.verdict = "maybe";
  assert.ok(validateAuditPacket(packet).some((err) => err.includes("verdict")));
});

test("trusted=true requires verifier verdict valid", () => {
  const packet = example();
  packet.verifier!.trusted = true;
  packet.verifier!.verdict = "invalid";
  assert.ok(validateAuditPacket(packet).some((err) => err.includes("trusted=true")));
});

test("trusted=true requires signer_key", () => {
  const packet = example();
  packet.verifier!.trusted = true;
  packet.verifier!.verdict = "valid";
  delete packet.verifier!.signer_key;
  assert.ok(validateAuditPacket(packet).some((err) => err.includes("signer_key")));
});

test("summary totals must sum to receipt_count", () => {
  const packet = example();
  packet.summary!.totals!.allow += 1;
  assert.ok(validateAuditPacket(packet).some((err) => err.includes("totals sum")));
});

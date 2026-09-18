// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { Ajv2020 } from "ajv/dist/2020.js";
import { createRequire } from "node:module";
import { validateAuditPacket } from "../src/schema.js";
import type { AuditPacket } from "../src/types.js";

const require = createRequire(import.meta.url);
const addFormats = require("ajv-formats") as (ajv: Ajv2020) => void;
const anchorBundleSchemaURL = new URL("../../../../anchor-bundle/v1.json", import.meta.url);
const anchorBundleExampleURL = new URL("../../../../anchor-bundle/example.json", import.meta.url);

function example(): AuditPacket {
  return JSON.parse(readFileSync("../../audit-packet/example.json", "utf8")) as AuditPacket;
}

test("sdk audit-packet example passes schema and structural checks", () => {
  assert.deepEqual(validateAuditPacket(example()), []);
});

function anchorBundleValidator() {
  const schema = JSON.parse(readFileSync(anchorBundleSchemaURL, "utf8")) as object;
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

test("anchor bundle v1 schema compiles with AJV strict mode", () => {
  assert.doesNotThrow(() => anchorBundleValidator());
});

// Compiling is not validating. Declaring the conditionally-required property so
// AJV strict can resolve it must not change which bundles the schema accepts,
// so the committed rekor-backed example has to stay valid and a rekor bundle
// missing its rekor block has to stay invalid. Without the second case this
// test would pass for a schema that had stopped enforcing the conditional.
test("anchor bundle v1 schema still enforces the rekor conditional", () => {
  const validate = anchorBundleValidator();
  const rekorExample = JSON.parse(readFileSync(anchorBundleExampleURL, "utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(rekorExample.backend, "rekor", "example must exercise the rekor branch");
  assert.equal(validate(rekorExample), true, JSON.stringify(validate.errors));

  const withoutRekor = JSON.parse(JSON.stringify(rekorExample)) as {
    proof: Record<string, unknown>;
  };
  delete withoutRekor.proof.rekor;
  assert.equal(
    validate(withoutRekor),
    false,
    "a rekor bundle without proof.rekor must be rejected",
  );
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

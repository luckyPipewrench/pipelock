// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  applyEvidenceProvenanceRecipe,
  EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
} from "../src/provenance.js";

type Vector = {
  id: string;
  input_b64: string;
  output_b64?: string;
  want_error?: string;
  recipe?: unknown[];
  transform_profile_digest?: string;
};
const corpus = JSON.parse(
  readFileSync("../../conformance/testdata/transform-profile/evidence-provenance-v1.json", "utf8"),
) as { profile_digest: string; operation_coverage: string[]; vectors: Vector[] };

test("evidence provenance: pinned corpus profile and every operation are exercised", () => {
  assert.equal(corpus.profile_digest, EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST);
  const expected = new Set(corpus.operation_coverage);
  const seen = new Set(
    corpus.vectors
      .flatMap((v) => (v.recipe ?? []).map((op) => (op as { kind: string }).kind))
      .filter((kind) => expected.has(kind)),
  );
  assert.deepEqual([...seen].sort(), [...corpus.operation_coverage].sort());
});

for (const vector of corpus.vectors)
  test(`evidence provenance: ${vector.id}`, () => {
    const recipe = {
      transform_profile_digest: vector.transform_profile_digest ?? corpus.profile_digest,
      operations: vector.recipe ?? [],
    };
    if (vector.want_error) {
      assert.throws(
        () => applyEvidenceProvenanceRecipe(Buffer.from(vector.input_b64, "base64"), recipe),
        new RegExp(vector.want_error, "u"),
      );
      return;
    }
    assert.equal(
      Buffer.from(
        applyEvidenceProvenanceRecipe(Buffer.from(vector.input_b64, "base64"), recipe),
      ).toString("base64"),
      vector.output_b64,
    );
  });

test("evidence provenance: HTML5 named entities decode repeatedly", () => {
  const recipe = {
    transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
    operations: [{ kind: "html_entity_decode" }],
  };
  const result = applyEvidenceProvenanceRecipe(
    Buffer.from("&amp;CounterClockwiseContourIntegral;", "utf8"),
    recipe,
  );
  assert.equal(Buffer.from(result).toString("utf8"), "∳");
});

test("evidence provenance: Unicode 15 tables pin newer code points as opaque", () => {
  const unicodeData = JSON.parse(
    readFileSync("node_modules/@unicode/unicode-15.0.0/package.json", "utf8"),
  ) as { version: string };
  assert.equal(unicodeData.version, "1.6.17");

  // U+1C89 was assigned in Unicode 16. Native Node 24 (Unicode 17) maps it
  // to U+1C8A; profile v1 must leave it untouched under Unicode 15.
  const result = applyEvidenceProvenanceRecipe(Buffer.from("\u{1C89}", "utf8"), {
    transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
    operations: [{ kind: "lowercase" }],
  });
  assert.equal(Buffer.from(result).toString("utf8"), "\u{1C89}");
});

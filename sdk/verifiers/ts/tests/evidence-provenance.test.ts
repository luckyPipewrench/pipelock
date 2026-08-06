// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import {
  applyEvidenceProvenanceRecipe,
  EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
  supportedOperationKinds,
} from "../src/provenance.js";
import { findPackageRoot } from "./paths.js";

type Vector = {
  id: string;
  input_b64: string;
  output_b64?: string;
  want_error?: string;
  recipe?: unknown[];
  transform_profile_digest?: string;
};
const packageRoot = findPackageRoot(import.meta.url);
const corpusPath = resolve(
  packageRoot,
  "../../conformance/testdata/transform-profile/evidence-provenance-v1.json",
);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as {
  profile_digest: string;
  operation_coverage: string[];
  vectors: Vector[];
};

test("evidence provenance: pinned corpus profile and every operation are exercised", () => {
  assert.equal(corpus.profile_digest, EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST);
  const seen = new Set(
    corpus.vectors
      .filter((v) => !v.want_error)
      .flatMap((v) => (v.recipe ?? []).map((op) => (op as { kind: string }).kind)),
  );
  assert.deepEqual([...seen].sort(), [...corpus.operation_coverage].sort());
  assert.deepEqual([...supportedOperationKinds()].sort(), [...corpus.operation_coverage].sort());
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
        (error: unknown) => error instanceof Error && error.message.includes(vector.want_error!),
        vector.id,
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
    readFileSync(resolve(packageRoot, "node_modules/@unicode/unicode-15.0.0/package.json"), "utf8"),
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

test("evidence provenance: execution limits reject unbounded verifier work", () => {
  assert.throws(
    () =>
      applyEvidenceProvenanceRecipe(Buffer.from("value"), {
        transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
        operations: Array.from({ length: 33 }, () => ({ kind: "identity" })),
      }),
    /exceeds 32 operations/u,
  );

  const token = `%${"25".repeat(500)}`;
  assert.throws(
    () =>
      applyEvidenceProvenanceRecipe(Buffer.from(token.repeat(1500)), {
        transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
        operations: [{ kind: "query_unescape" }],
      }),
    /cumulative processing budget/u,
  );
});

test("encoded token normalization rejects non-ASCII whitespace separators", () => {
  for (const separator of ["\u00a0", "\u1680", "\u3000", "\ufeff"]) {
    const output = applyEvidenceProvenanceRecipe(Buffer.from(`SG${separator}k=`), {
      transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
      operations: [{ kind: "encoded_token_normalize", alphabet: "base64_standard" }],
    });
    assert.equal(Buffer.from(output).toString(), "");
  }
});

test("URL authority delimiter must immediately follow the scheme", () => {
  assert.throws(
    () =>
      applyEvidenceProvenanceRecipe(Buffer.from("https:api.vendor.example/path://x"), {
        transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
        operations: [{ kind: "url_component", component: "hostname" }],
      }),
    /invalid absolute URL/u,
  );
});

// Unicode marks U+001C..U+001F as White_Space=Yes, but Go's unicode.IsSpace
// excludes them and this profile follows Go. A verifier that strips them
// produces a different view than the Go reference for byte-identical input, and
// therefore a different commitment. This case is pinned because the whole suite
// passed while the divergence was live: nothing exercised these four code
// points, so the bug was invisible to 310 green tests.
test("whitespace_compact keeps the information separators Go retains", () => {
  const separators = "\u001c\u001d\u001e\u001f";
  const input = "abc" + separators + "de f";
  const recipe = {
    transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
    operations: [{ kind: "whitespace_compact" }],
  };

  const out = applyEvidenceProvenanceRecipe(Buffer.from(input, "utf8"), recipe);
  const text = Buffer.from(out).toString("utf8");

  // The ASCII space is compacted away; the four separators survive, matching
  // Go codepoints [97 98 99 28 29 30 31 100 101 102].
  assert.equal(text, "abc" + separators + "def");
  for (let cp = 0x1c; cp <= 0x1f; cp += 1) {
    assert.ok(
      text.includes(String.fromCodePoint(cp)),
      `U+${cp.toString(16).toUpperCase().padStart(4, "0")} must be retained to match Go`,
    );
  }
});

// A malformed absolute URL carries a scheme but no literal "://" authority.
// indexOf then returns -1 and the slice started at index 2, so this verifier
// returned a fabricated hostname ("tps") while Go rejected the same input and
// Rust fabricated something else ("https"). A proof built on it would commit to
// a source view that never existed. Pinned so the rejection cannot regress.
test("url_component hostname rejects a malformed authority like Go", () => {
  const recipe = {
    transform_profile_digest: EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST,
    operations: [{ kind: "url_component", component: "hostname" }],
  };

  assert.throws(
    () => applyEvidenceProvenanceRecipe(Buffer.from("https:api.vendor.example", "utf8"), recipe),
    /invalid absolute URL/,
  );

  const ok = applyEvidenceProvenanceRecipe(
    Buffer.from("https://api.vendor.example/x", "utf8"),
    recipe,
  );
  assert.equal(Buffer.from(ok).toString("utf8"), "api.vendor.example");
});

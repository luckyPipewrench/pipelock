// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as ed25519 from "@noble/ed25519";
import test from "node:test";
import { RawNumber, parseJSONStrict } from "../src/aarp/strictjson.js";
import {
  executeProvenanceRecipe,
  validateProvenanceIntervals,
  verifyProvenanceFixture,
} from "../src/provenance-proof.js";
import { EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST } from "../src/provenance.js";
import { findPackageRoot } from "./paths.js";

const profileDigest = EVIDENCE_PROVENANCE_PROFILE_V1_DIGEST;
const commitment = `hmac-sha256:${"0".repeat(64)}`;
const seed = Buffer.from("1".repeat(64), "hex");

const corpusDir = resolve(
  findPackageRoot(import.meta.url),
  "../../conformance/testdata/transform-profile",
);

async function fixture(
  signed: Record<string, unknown>[],
  options: { corruptSignature?: boolean; source?: string; sources?: Record<string, string> } = {},
): Promise<string> {
  const signer = await ed25519.getPublicKeyAsync(seed);
  const entries = await Promise.all(
    signed.map(async (value, index) => {
      const bytes = Buffer.from(JSON.stringify(value));
      const signature = Buffer.from(await ed25519.signAsync(bytes, seed));
      if (options.corruptSignature === true && index === 0) signature[0] ^= 1;
      return {
        signed_b64: bytes.toString("base64"),
        signature: `ed25519:${signature.toString("hex")}`,
      };
    }),
  );
  return JSON.stringify({
    format: "pipelock-evidence-provenance-verification-fixture/v1",
    entries,
    verification: {
      signer_public_key_hex: Buffer.from(signer).toString("hex"),
      sources: Object.entries(options.sources ?? { "source-1": options.source ?? "A💩B" }).map(
        ([source_id, source]) => ({ source_id, bytes_b64: Buffer.from(source).toString("base64") }),
      ),
    },
  });
}

function signed(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    chain_seq: 0,
    chain_prev_hash: "genesis",
    critical_features: ["evidence_provenance"],
    proof: {
      version: "pipelock-evidence-provenance-proof/v1",
      transform_profile_digest: profileDigest,
      producer: {},
      sources: [
        {
          source_ordinal: 1,
          source_id: "source-1",
          recipe: { transform_profile_digest: profileDigest, operations: [{ kind: "identity" }] },
          view_commitment: commitment,
          matches: [],
        },
      ],
    },
    ...overrides,
  };
}

function signedChain(
  length: number,
  operationsByEntry?: Array<Array<Record<string, unknown>>>,
): Record<string, unknown>[] {
  const entries: Record<string, unknown>[] = [];
  let previous = "genesis";
  for (let index = 0; index < length; index++) {
    const entry = signed({ chain_seq: index, chain_prev_hash: previous });
    if (operationsByEntry !== undefined) {
      const source = (entry.proof as { sources: Array<Record<string, unknown>> }).sources[0]!;
      source.recipe = {
        transform_profile_digest: profileDigest,
        operations: operationsByEntry[index]!,
      };
    }
    entries.push(entry);
    previous = `sha256:${createHash("sha256").update(JSON.stringify(entry)).digest("hex")}`;
  }
  return entries;
}

function chainWithProofs(proofs: Array<Record<string, unknown>>): Record<string, unknown>[] {
  let previous = "genesis";
  return proofs.map((proof, index) => {
    const entry = signed({ chain_seq: index, chain_prev_hash: previous, proof });
    previous = `sha256:${createHash("sha256").update(JSON.stringify(entry)).digest("hex")}`;
    return entry;
  });
}

function proofSources(
  count: number,
  matches = 0,
  operations: Record<string, unknown>[] = [{ kind: "identity" }],
) {
  return Array.from({ length: count }, (_, index) => ({
    source_ordinal: index + 1,
    source_id: `source-${index + 1}`,
    recipe: { transform_profile_digest: profileDigest, operations },
    view_commitment: commitment,
    matches: Array.from({ length: matches }, (_, match) => ({
      match_ordinal: match + 1,
      byte_start: match * 2,
      byte_end: match * 2 + 1,
      match_class: "credential",
      match_commitment: commitment,
    })),
  }));
}

test("provenance fixture reports all available stages and remains incomplete without source commitments", async () => {
  const report = await verifyProvenanceFixture(await fixture([signed()]));
  assert.deepEqual(report, {
    trust_roots: "fixture supplied; self-attested; not authenticated",
    authenticated_provenance: false,
    signature: "verified",
    chain: "verified",
    artifacts: "not_attested",
    source_commitment: "not_checked",
    view_reproduction: "reproduced",
    location: "exact_coordinates",
    match_commitment: "not_checked",
    overall: "incomplete",
  });
});

test("provenance fixture fails closed at the critical-feature stage", async () => {
  const report = await verifyProvenanceFixture(await fixture([signed({ critical_features: [] })]));
  assert.equal(report.failure_stage, "critical_features");
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
  assert.equal(report.overall, "invalid");
});

test("provenance fixture authenticates a missing critical feature before rejecting it", async () => {
  const proof = signed();
  delete proof.critical_features;
  const report = await verifyProvenanceFixture(await fixture([proof]));
  assert.equal(report.failure_stage, "critical_features");
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
});

test("provenance fixture rejects a UTF-8 continuation-byte coordinate", async () => {
  const proof = signed();
  const source = (proof.proof as { sources: Array<Record<string, unknown>> }).sources[0]!;
  source.matches = [
    {
      match_ordinal: 1,
      byte_start: 2,
      byte_end: 5,
      match_class: "credential",
      match_commitment: commitment,
    },
  ];
  const report = await verifyProvenanceFixture(await fixture([proof]));
  assert.equal(report.failure_stage, "location");
  assert.equal(report.location, "mismatch");
});

test("provenance fixture reports signature failure before every later stage", async () => {
  const report = await verifyProvenanceFixture(
    await fixture([signed()], { corruptSignature: true }),
  );
  assert.deepEqual(report, {
    trust_roots: "fixture supplied; self-attested; not authenticated",
    authenticated_provenance: false,
    signature: "invalid",
    chain: "not_checked",
    artifacts: "attested_unchecked",
    source_commitment: "not_checked",
    view_reproduction: "not_checked",
    location: "not_checked",
    match_commitment: "not_checked",
    overall: "invalid",
    failure_stage: "signature",
  });
});

test("provenance fixture rejects duplicate keys in envelopes and signed payloads", async () => {
  const ordinary = await fixture([signed()]);
  const duplicateEnvelope = ordinary.replace('{"format":', '{"format":"duplicate","format":');
  const envelopeReport = await verifyProvenanceFixture(duplicateEnvelope);
  assert.equal(envelopeReport.failure_stage, "proof_structure");

  const signer = await ed25519.getPublicKeyAsync(seed);
  const raw = Buffer.from(
    JSON.stringify(signed()).replace('{"chain_seq":0,', '{"chain_seq":0,"chain_seq":0,'),
  );
  const signature = Buffer.from(await ed25519.signAsync(raw, seed));
  const duplicateSigned = JSON.stringify({
    format: "pipelock-evidence-provenance-verification-fixture/v1",
    entries: [
      {
        signed_b64: raw.toString("base64"),
        signature: `ed25519:${signature.toString("hex")}`,
      },
    ],
    verification: {
      signer_public_key_hex: Buffer.from(signer).toString("hex"),
      sources: [],
    },
  });
  const signedReport = await verifyProvenanceFixture(duplicateSigned);
  assert.equal(signedReport.failure_stage, "proof_structure");
  assert.equal(signedReport.signature, "not_checked");
});

test("provenance fixture verifies every entry in a signed chain", async () => {
  const first = signed();
  const prior = `sha256:${createHash("sha256")
    .update(Buffer.from(JSON.stringify(first)))
    .digest("hex")}`;
  const second = signed({ chain_seq: 1, chain_prev_hash: prior });
  const report = await verifyProvenanceFixture(await fixture([first, second]));
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
  assert.equal(report.overall, "incomplete");
});

test("provenance fixture marks a signed chain break invalid", async () => {
  const report = await verifyProvenanceFixture(
    await fixture([signed({ chain_prev_hash: "sha256:" + "0".repeat(64) })]),
  );
  assert.equal(report.failure_stage, "chain");
  assert.equal(report.chain, "invalid");
});

test("provenance fixture rejects total source references across entries", async () => {
  const sources = Object.fromEntries(
    Array.from({ length: 32 }, (_, i) => [`source-${i + 1}`, "x"]),
  );
  const proofs = Array.from({ length: 5 }, () => ({
    version: "pipelock-evidence-provenance-proof/v1",
    transform_profile_digest: profileDigest,
    producer: {},
    sources: proofSources(32),
  }));
  const report = await verifyProvenanceFixture(await fixture(chainWithProofs(proofs), { sources }));
  assert.equal(report.failure_stage, "proof_structure");
});

test("provenance fixture rejects total match checks across entries", async () => {
  const proof = signed();
  (proof.proof as { sources: Array<Record<string, unknown>> }).sources = proofSources(5, 1024);
  const sources = Object.fromEntries(
    Array.from({ length: 5 }, (_, i) => [`source-${i + 1}`, "ab".repeat(1024)]),
  );
  const report = await verifyProvenanceFixture(await fixture([proof], { sources }));
  assert.equal(report.failure_stage, "proof_structure");
});

test("provenance fixture rejects total recipe processing bytes across entries", async () => {
  const report = await verifyProvenanceFixture(
    await fixture(
      [
        signed({
          proof: {
            version: "pipelock-evidence-provenance-proof/v1",
            transform_profile_digest: profileDigest,
            producer: {},
            sources: proofSources(
              8,
              0,
              Array.from({ length: 9 }, () => ({ kind: "identity" })),
            ),
          },
        }),
      ],
      {
        sources: Object.fromEntries(
          Array.from({ length: 8 }, (_, i) => [`source-${i + 1}`, "x".repeat(1 << 20)]),
        ),
      },
    ),
  );
  assert.equal(report.failure_stage, "proof_structure");
});

test("provenance fixture gives the per-recipe budget precedence", async () => {
  const sources = proofSources(7);
  for (const [index, source] of sources.entries()) {
    source.recipe.operations = Array.from({ length: index === 6 ? 17 : 8 }, () => ({
      kind: "identity",
    }));
  }
  const proof = signed();
  (proof.proof as { sources: Array<Record<string, unknown>> }).sources = sources;
  const report = await verifyProvenanceFixture(
    await fixture([proof], {
      sources: Object.fromEntries(
        Array.from({ length: 7 }, (_, i) => [`source-${i + 1}`, "x".repeat(1 << 20)]),
      ),
    }),
  );
  assert.equal(report.failure_stage, "view_reproduction");
});

test("provenance fixture reuses a reconstructed view for identical source and recipe", async () => {
  const identities = Array.from({ length: 16 }, () => ({ kind: "identity" }));
  const report = await verifyProvenanceFixture(
    await fixture(
      chainWithProofs(
        Array.from({ length: 32 }, () => ({
          version: "pipelock-evidence-provenance-proof/v1",
          transform_profile_digest: profileDigest,
          producer: {},
          sources: proofSources(4, 0, identities),
        })),
      ),
      {
        sources: Object.fromEntries(
          Array.from({ length: 4 }, (_, i) => [`source-${i + 1}`, "x".repeat(1 << 20)]),
        ),
      },
    ),
  );
  assert.equal(report.overall, "incomplete");
  assert.equal(report.view_reproduction, "reproduced");
});

test("provenance fixture rejects outer envelope size, counts, decoded payloads, and depth", async () => {
  const oversized = " ".repeat((16 << 20) + 1);
  assert.equal((await verifyProvenanceFixture(oversized)).failure_stage, "proof_structure");
  const tooManyEntries = await fixture(signedChain(33));
  assert.equal((await verifyProvenanceFixture(tooManyEntries)).failure_stage, "proof_structure");
  const tooManySources = await fixture([signed()], {
    sources: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`source-${i}`, "x"])),
  });
  assert.equal((await verifyProvenanceFixture(tooManySources)).failure_stage, "proof_structure");
  const tooManyProofSources = signed();
  (tooManyProofSources.proof as { sources: Array<Record<string, unknown>> }).sources =
    proofSources(33);
  assert.equal(
    (await verifyProvenanceFixture(await fixture([tooManyProofSources], { sources: {} })))
      .failure_stage,
    "proof_structure",
  );
  const tooLargeSource = await fixture([signed()], { source: "x".repeat((2 << 20) + 1) });
  assert.equal((await verifyProvenanceFixture(tooLargeSource)).failure_stage, "proof_structure");
  const deep = "[".repeat(65) + "0" + "]".repeat(65);
  assert.equal((await verifyProvenanceFixture(deep)).failure_stage, "proof_structure");
  const value = JSON.parse(await fixture([signed()])) as { entries: Array<Record<string, string>> };
  value.entries[0]!.signed_b64 = Buffer.alloc((1 << 20) + 1).toString("base64");
  assert.equal(
    (await verifyProvenanceFixture(JSON.stringify(value))).failure_stage,
    "proof_structure",
  );
});

test("provenance fixture reports an absent source as incomplete", async () => {
  const value = JSON.parse(await fixture([signed()])) as { verification: Record<string, unknown> };
  delete value.verification.sources;
  const report = await verifyProvenanceFixture(JSON.stringify(value));
  assert.deepEqual(
    {
      signature: report.signature,
      chain: report.chain,
      artifacts: report.artifacts,
      view_reproduction: report.view_reproduction,
      location: report.location,
      match_commitment: report.match_commitment,
      overall: report.overall,
    },
    {
      signature: "verified",
      chain: "verified",
      artifacts: "not_attested",
      view_reproduction: "not_checked",
      location: "not_checked",
      match_commitment: "not_checked",
      overall: "incomplete",
    },
  );
});

test("artifact mismatch outranks a distinct unavailable artifact", async () => {
  const proof = signed();
  const producer = (proof.proof as { producer: Record<string, string> }).producer;
  const binary = Buffer.from("matching binary");
  producer.binary_digest = `sha256:${createHash("sha256").update(binary).digest("hex")}`;
  producer.ruleset_digest = `sha256:${"a".repeat(64)}`;
  const value = JSON.parse(await fixture([proof])) as { verification: Record<string, unknown> };
  value.verification.binary_b64 = binary.toString("base64");
  value.verification.ruleset_b64 = Buffer.from("wrong ruleset").toString("base64");
  const report = await verifyProvenanceFixture(JSON.stringify(value));
  assert.equal(report.failure_stage, "artifacts");
  assert.equal(report.artifacts, "mismatch");
});

test("a missing source cannot hide an available sibling reconstruction mismatch", async () => {
  const proof = signed();
  const sources = (proof.proof as { sources: Array<Record<string, unknown>> }).sources;
  sources[0]!.recipe = {
    transform_profile_digest: profileDigest,
    operations: [{ kind: "percent_decode", passes: 1 }],
  };
  sources.push({
    source_ordinal: 2,
    source_id: "source-2",
    recipe: { transform_profile_digest: profileDigest, operations: [{ kind: "identity" }] },
    view_commitment: commitment,
    matches: [],
  });
  const report = await verifyProvenanceFixture(await fixture([proof], { source: "%ff" }));
  assert.equal(report.failure_stage, "view_reproduction");
  assert.equal(report.view_reproduction, "mismatch");
  assert.equal(report.overall, "invalid");
});

type RawObject = Record<string, unknown>;

function rawObject(value: unknown, label: string): RawObject {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must not be null`);
  assert.equal(Array.isArray(value), false, `${label} must not be an array`);
  return value as RawObject;
}

function rawString(value: unknown, label: string): string {
  assert.equal(typeof value, "string", `${label} must be a string`);
  return value as string;
}

function rawUint(value: unknown, label: string): bigint {
  assert.ok(value instanceof RawNumber, `${label} must preserve its JSON number literal`);
  return BigInt(value.literal);
}

test("PR3 transform corpus executes every recipe vector byte-exactly", () => {
  const corpusPath = resolve(corpusDir, "evidence-provenance-v1.json");
  const corpus = rawObject(parseJSONStrict(readFileSync(corpusPath, "utf8")), "corpus");
  const profile = rawString(corpus.profile_digest, "profile_digest");
  const vectors = corpus.vectors as unknown[];
  assert.equal(vectors.length, 63, "the pinned PR3 transform corpus must not shrink");
  for (const value of vectors) {
    const vector = rawObject(value, "vector");
    const id = rawString(vector.id, "vector.id");
    const recipe = {
      transform_profile_digest:
        vector.transform_profile_digest === undefined
          ? profile
          : rawString(vector.transform_profile_digest, `${id}.transform_profile_digest`),
      operations: vector.recipe ?? [],
    };
    const input = Buffer.from(rawString(vector.input_b64, `${id}.input_b64`), "base64");
    const wantError =
      vector.want_error === undefined ? "" : rawString(vector.want_error, `${id}.want_error`);
    if (wantError !== "") {
      assert.throws(
        () => executeProvenanceRecipe(recipe, input),
        (error: unknown) => error instanceof Error && error.message.includes(wantError),
        id,
      );
      continue;
    }
    const got = executeProvenanceRecipe(recipe, input);
    assert.deepEqual(
      got,
      Buffer.from(rawString(vector.output_b64, `${id}.output_b64`), "base64"),
      id,
    );
  }
});

test("PR3 interval vectors reject malformed UTF-8 boundaries without replacement", () => {
  const corpusPath = resolve(corpusDir, "evidence-provenance-v1.json");
  const corpus = rawObject(parseJSONStrict(readFileSync(corpusPath, "utf8")), "corpus");
  const vectors = corpus.interval_vectors as unknown[];
  assert.equal(vectors.length, 8, "the pinned PR3 interval corpus must not shrink");
  for (const value of vectors) {
    const vector = rawObject(value, "interval vector");
    const id = rawString(vector.id, "interval id");
    const intervals = (vector.matches as unknown[]).map((pair) => {
      assert.ok(Array.isArray(pair) && pair.length === 2, `${id}: interval pair`);
      return [rawUint(pair[0], `${id}.start`), rawUint(pair[1], `${id}.end`)] as const;
    });
    const view = Buffer.from(rawString(vector.view_b64, `${id}.view_b64`), "base64");
    const wantError = rawString(vector.want_error, `${id}.want_error`);
    if (wantError === "") {
      assert.doesNotThrow(() => validateProvenanceIntervals(view, intervals), id);
    } else {
      assert.throws(
        () => validateProvenanceIntervals(view, intervals),
        (error: unknown) => error instanceof Error && error.message.includes(wantError),
        id,
      );
    }
  }
  assert.throws(
    () => validateProvenanceIntervals(Buffer.from([0xff]), [[0n, 1n]]),
    /invalid UTF-8/u,
  );
});

test("dlp_normalize implements every profile confusable mapping and range", () => {
  const profilePath = resolve(corpusDir, "evidence-provenance-transform-v1.json");
  const profileJSON = JSON.parse(readFileSync(profilePath, "utf8")) as {
    normalization: {
      dlp_normalize: { confusable_to_ascii: { single_code_points: Record<string, string> } };
    };
  };
  const map = profileJSON.normalization.dlp_normalize.confusable_to_ascii.single_code_points;
  const singles = Object.entries(map);
  const input = [
    ...singles.map(([code]) => String.fromCodePoint(Number.parseInt(code.slice(2), 16))),
    ...Array.from({ length: 26 }, (_, index) => String.fromCodePoint(0x1f170 + index)),
    ...Array.from({ length: 26 }, (_, index) => String.fromCodePoint(0x1f1e6 + index)),
  ].join("");
  const want = `${singles.map(([, output]) => output).join("")}ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ`;
  const got = executeProvenanceRecipe(
    {
      transform_profile_digest: profileDigest,
      operations: [{ kind: "dlp_normalize", profile: "pipelock-dlp-v1" }],
    },
    Buffer.from(input, "utf8"),
  );
  assert.equal(got.toString("utf8"), want);
});

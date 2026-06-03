// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Corpus-driven conformance test: run the TS AARP verifier over EVERY fixture in
// the shared hostile corpus and assert appraise fixtures emit bytes equal to the
// committed <name>.appraisal.json (trimmed) and exit 0; fatal fixtures exit
// non-zero. This is the per-language arm of the four-language gate.

import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { comparableAppraisal } from "../src/aarp/appraise.js";
import {
  comparableChain,
  loadTrustFile,
  unmarshal,
  verify,
  verifyChain,
} from "../src/aarp/index.js";
import type { Envelope } from "../src/aarp/index.js";
import { appraiseWithSVID, loadSVIDFile } from "../src/aarp/svid.js";

// Paths are relative to the test CWD (sdk/verifiers/ts), matching the existing
// conformance-corpus.test.ts convention.
const corpus = "../../conformance/testdata/aarp-corpus";
const trustPath = `${corpus}/trust.json`;

interface ExpectFile {
  fixture_id: string;
  category: string;
  input_format: string;
  verdict: string;
}

// appraiseOne mirrors the CLI single-envelope path and returns either the
// comparable bytes (appraised) or the marker that it was fatal.
function appraiseOne(text: string): { fatal: boolean; bytes?: string } {
  let env: Envelope;
  try {
    env = unmarshal(text);
  } catch {
    return { fatal: true };
  }
  try {
    const opts = loadTrustFile(trustPath);
    const ap = verify(env, opts);
    return { fatal: false, bytes: comparableAppraisal(ap) };
  } catch {
    return { fatal: true };
  }
}

// appraiseChain mirrors the CLI --chain path. A fatal parse of any line, or a
// stream that does not link, is the fatal/non-zero outcome.
function appraiseChain(text: string): { fatal: boolean; bytes?: string } {
  const lines = text.trim().split("\n");
  const envs: Envelope[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "") continue;
    let env: Envelope;
    try {
      env = unmarshal(line);
    } catch {
      return { fatal: true };
    }
    envs.push(env);
  }
  const bytes = comparableChain(envs);
  if (!verifyChain(envs)) return { fatal: true };
  return { fatal: false, bytes };
}

for (const category of ["golden", "malicious", "edge", "chain"]) {
  const dir = `${corpus}/${category}`;
  const expectFiles = readdirSync(dir).filter((f) => f.endsWith(".expect.json"));
  for (const expectFile of expectFiles) {
    const base = expectFile.replace(/\.expect\.json$/u, "");
    const expect = JSON.parse(readFileSync(`${dir}/${expectFile}`, "utf8")) as ExpectFile;
    const isChain = expect.input_format === "chain";
    const fixturePath = `${dir}/${base}${isChain ? ".aarp.jsonl" : ".aarp.json"}`;

    test(`corpus ${category}/${base} (${expect.verdict})`, () => {
      const text = readFileSync(fixturePath, "utf8");
      const result = isChain ? appraiseChain(text) : appraiseOne(text);
      if (expect.verdict === "fatal") {
        assert.equal(result.fatal, true, `${base} should be fatal`);
        return;
      }
      assert.equal(result.fatal, false, `${base} should appraise`);
      const want = readFileSync(`${dir}/${base}.appraisal.json`, "utf8").trim();
      assert.equal(result.bytes, want, `${base} comparable bytes mismatch`);
    });
  }
}

// SVID arm: each fixture is appraised with its per-fixture --svid sidecar and
// must byte-match the committed .appraisal.json. A genuine baseline confirms the
// three workload-identity claims; every attack appraises WITHOUT them (no
// inflation). Mirrors the CLI single-envelope + --svid path.
{
  const dir = `${corpus}/svid`;
  const expectFiles = readdirSync(dir).filter((f) => f.endsWith(".expect.json"));
  for (const expectFile of expectFiles) {
    const base = expectFile.replace(/\.expect\.json$/u, "");
    const expect = JSON.parse(readFileSync(`${dir}/${expectFile}`, "utf8")) as ExpectFile;

    test(`corpus svid/${base} (${expect.verdict})`, () => {
      const env = unmarshal(readFileSync(`${dir}/${base}.aarp.json`, "utf8"));
      const opts = loadTrustFile(trustPath);
      const svid = loadSVIDFile(`${dir}/${base}.svid.json`);
      const ap = appraiseWithSVID(env, svid.evidence, opts, svid.opts);
      const bytes = comparableAppraisal(ap);
      const want = readFileSync(`${dir}/${base}.appraisal.json`, "utf8").trim();
      assert.equal(bytes, want, `${base} comparable bytes mismatch`);
    });
  }
}

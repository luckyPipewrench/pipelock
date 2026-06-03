// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// The `aarp` subcommand, ported from cmd/pipelock-verifier/aarp.go (+ the SVID
// arm from aarp_svid.go). Usage:
//
//   pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--svid SVID_JSON] [--chain] [--json]
//
// --svid attaches an X.509-SVID proof-of-possession appraisal to a single
// envelope (never with --chain); without it the output is the plain envelope
// appraisal, unchanged.
//
// Exit codes: 0 appraised (single) / linked (chain); 1 fatal (or chain not
// linked); 2 I/O or trust-file error; 64 usage. On fatal with --json the
// verifier prints {"envelope_fatal":true} and exits non-zero; the gate compares
// only the non-zero exit for fatal fixtures.

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { comparableAppraisal } from "./appraise.js";
import { canonicalize } from "./canonical.js";
import { comparableChain, loadTrustFile, unmarshal, verify, verifyChain } from "./index.js";
import type { Envelope } from "./index.js";
import { appraiseWithSVID, loadSVIDFile } from "./svid.js";

// CodedError is anything carrying a numeric exit `code`. Our module errors all do.
interface CodedError {
  code: number;
  message: string;
}

function isCodedError(err: unknown): err is CodedError {
  return (
    typeof err === "object" &&
    err !== null &&
    typeof (err as { code?: unknown }).code === "number" &&
    typeof (err as { message?: unknown }).message === "string"
  );
}

// AARPUsageError marks a usage error (exit 64).
export class AARPUsageError extends Error {
  readonly code = 64;
}

const USAGE =
  "Usage: pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--svid SVID_JSON] [--chain] [--json]";

// emitFatal prints the envelope-fatal marker (or human text) and returns 1.
function emitFatal(jsonMode: boolean, cause: string): number {
  if (jsonMode) {
    process.stdout.write(`${canonicalize({ envelope_fatal: true })}\n`);
  } else {
    process.stderr.write(`ENVELOPE FATAL: ${cause}\n`);
  }
  return 1;
}

// runAARPChain verifies a JSONL stream of envelopes for Rung-1 chain linkage.
function runAARPChain(data: string, jsonMode: boolean): number {
  const lines = data.trim().split("\n");
  const envs: Envelope[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] as string).trim();
    if (line === "") continue;
    let env: Envelope;
    try {
      env = unmarshal(line);
    } catch (err) {
      return emitFatal(
        jsonMode,
        `chain line ${i}: ${isCodedError(err) ? err.message : String(err)}`,
      );
    }
    envs.push(env);
  }

  if (jsonMode) {
    process.stdout.write(`${comparableChain(envs)}\n`);
  } else {
    process.stdout.write(`AARP chain: ${envs.length} envelopes\n`);
  }
  return verifyChain(envs) ? 0 : 1;
}

// runAARPCommand executes the aarp subcommand and returns its process exit code.
export function runAARPCommand(args: string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        trust: { type: "string", default: "" },
        svid: { type: "string", default: "" },
        json: { type: "boolean", default: false },
        chain: { type: "boolean", default: false },
      },
    });
  } catch (err) {
    throw new AARPUsageError(`${USAGE}\n${(err as Error).message}`);
  }
  if (parsed.positionals.length !== 1) {
    throw new AARPUsageError(`${USAGE}\naccepts 1 arg, received ${parsed.positionals.length}`);
  }
  const target = parsed.positionals[0] as string;
  const trustPath = parsed.values.trust ?? "";
  const svidPath = parsed.values.svid ?? "";
  const jsonMode = parsed.values.json === true;
  const chainMode = parsed.values.chain === true;

  // An SVID binding appraises a single envelope; the chain arm verifies stream
  // linkage and never attaches per-envelope SVID claims.
  if (svidPath !== "" && chainMode) {
    throw new AARPUsageError(
      `${USAGE}\n--svid is single-envelope only and cannot combine with --chain`,
    );
  }

  // Trust-file and envelope read errors are exit-2 (I/O), propagated as coded
  // errors so the top-level handler maps them.
  const opts = loadTrustFile(trustPath);

  let data: string;
  try {
    data = readFileSync(target, "utf8");
  } catch (err) {
    const e = new Error(`read envelope: ${(err as Error).message}`) as Error & { code: number };
    e.code = 2;
    throw e;
  }

  if (chainMode) {
    return runAARPChain(data, jsonMode);
  }

  // A malformed --svid sidecar (bad pinned-bundle DER, inverted window, empty
  // domain, unknown field) is an operator-config error (exit 2), propagated as a
  // coded error before any envelope appraisal -- never a fixture verdict.
  const svid = svidPath === "" ? null : loadSVIDFile(svidPath);

  let env: Envelope;
  try {
    env = unmarshal(data);
  } catch (err) {
    return emitFatal(jsonMode, isCodedError(err) ? err.message : String(err));
  }

  let appraisalBytes: string;
  try {
    const ap =
      svid === null ? verify(env, opts) : appraiseWithSVID(env, svid.evidence, opts, svid.opts);
    appraisalBytes = comparableAppraisal(ap);
  } catch (err) {
    return emitFatal(jsonMode, isCodedError(err) ? err.message : String(err));
  }

  if (jsonMode) {
    process.stdout.write(`${appraisalBytes}\n`);
  } else {
    process.stdout.write(`AARP appraisal (${env.profile})\n`);
  }
  return 0;
}

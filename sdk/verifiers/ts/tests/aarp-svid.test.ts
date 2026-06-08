// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Focused unit tests for the three SVID hardening findings:
//   - H1: strict SPIFFE-ID grammar (raw-string, no URL normalization) rejects a
//         dot-segment path (`spiffe://example.org/workload/../imposter`).
//   - M2: the signing CA's own validity window is checked at action_time, so a
//         CA expired-at-action inside an otherwise-covering pinned generation is
//         rejected.
//   - L4: addSVIDClaims fails closed on ANY error -- a non-binding error (e.g. a
//         TypeError from attacker-shaped evidence) withholds the three claims
//         with a warning and never rethrows / errors the envelope.
//
// The H1/M2 fixtures are driven through the real corpus sidecars so the test
// asserts the exact production behavior, not a hand-built approximation.

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

import { loadTrustFile, unmarshal } from "../src/aarp/index.js";
import type { Envelope } from "../src/aarp/index.js";
import {
  type SVIDEvidence,
  type SVIDVerifyOptions,
  addSVIDClaims,
  appraiseWithSVID,
  loadSVIDFile,
} from "../src/aarp/svid.js";
import { type Appraisal } from "../src/aarp/appraise.js";

const corpus = "../../conformance/testdata/aarp-corpus";
const trustPath = `${corpus}/trust.json`;

// withholdsSVIDClaims asserts the appraisal of a malicious svid fixture carries
// NONE of the three SVID claims (the producer's workload_identity_verified is
// reported claimed-unverified, not confirmed).
function assertWithholds(base: string): Appraisal {
  const env = unmarshal(readFileSync(`${corpus}/svid/${base}.aarp.json`, "utf8"));
  const opts = loadTrustFile(trustPath);
  const svid = loadSVIDFile(`${corpus}/svid/${base}.svid.json`);
  const ap = appraiseWithSVID(env, svid.evidence, opts, svid.opts);
  assert.ok(
    !ap.verified_claims.includes("signing_workload_svid_chain_validated"),
    `${base}: must not verify signing_workload_svid_chain_validated`,
  );
  assert.ok(
    !ap.verified_claims.includes("signing_workload_svid_bound"),
    `${base}: must not verify signing_workload_svid_bound`,
  );
  assert.ok(
    !ap.verified_claims.includes("signing_workload_svid_valid_at_action_time"),
    `${base}: must not verify signing_workload_svid_valid_at_action_time`,
  );
  // The producer's INPUT claim string is unchanged ("workload_identity_verified");
  // it is reported claimed-unverified when the binding does not verify.
  assert.ok(
    ap.claimed_unverified.includes("workload_identity_verified"),
    `${base}: workload_identity_verified must be claimed-unverified`,
  );
  return ap;
}

// H1: a SPIFFE ID whose URI SAN carries a dot-segment path is rejected at SAN
// parse (Go rejects it; a loose WHATWG-URL parse would normalize it to
// `/workload/imposter` and accept). All three claims are withheld.
test("svid H1: malformed SPIFFE-path (dot-segment) is rejected, claims withheld", () => {
  const ap = assertWithholds("s17-malformed-spiffe-path");
  assert.ok(
    ap.warnings.some((w) => w.includes("SVID attestation did not verify")),
    "s17 should record a verification warning",
  );
});

// M2: the signing CA is expired at action_time even though the pinned generation
// still covers it. The CA-window check rejects the chain; all three claims are
// withheld.
test("svid M2: CA expired at action_time is rejected, claims withheld", () => {
  const ap = assertWithholds("s18-ca-expired-at-action-time");
  assert.ok(
    ap.warnings.some((w) => w.includes("SVID attestation did not verify")),
    "s18 should record a verification warning",
  );
});

// Sub-second precision regression: issued_at one nanosecond past a whole-second
// leaf expiry must be rejected (Go uses time.RFC3339Nano; a millisecond Date
// comparison would equalize and spuriously accept).
test("svid: issued_at one nanosecond past leaf expiry is rejected", () => {
  const ap = assertWithholds("s19-issued-at-subsecond-past-expiry");
  assert.ok(
    ap.warnings.some((w) => w.includes("outside the SVID leaf validity window")),
    "s19 should warn about the leaf validity window",
  );
});

// L4: addSVIDClaims must absorb ANY error (not just SVIDBindingError). Here the
// evidence's nonce is shaped to make an inner helper throw a TypeError before
// the binding-specific failure path. Before the fix this propagated and made the
// envelope fatal; after the fix the three claims are simply withheld with a
// warning, and the call never throws.
test("svid L4: addSVIDClaims withholds (never rethrows) on an unexpected error", () => {
  const env = unmarshal(
    readFileSync(`${corpus}/svid/s01-valid-ecdsa-p256-baseline.aarp.json`, "utf8"),
  );
  const valid = loadSVIDFile(`${corpus}/svid/s01-valid-ecdsa-p256-baseline.svid.json`);

  // Force a non-string nonce: decodeNonceBase64Url -> Buffer.from(nonce,
  // "base64url") throws a TypeError, which is NOT an SVIDBindingError. The Type
  // checks in decodeEvidence are bypassed by constructing the evidence object
  // directly (an attacker-shaped value reaching the verify path).
  const ev: SVIDEvidence = {
    ...valid.evidence,
    nonce: 12345 as unknown as string,
  };

  // A pre-signed appraisal so addSVIDClaims runs the binding path (not the
  // unsigned short-circuit).
  const ap: Appraisal = {
    profile: "aarp/v0.1",
    assertion_signed: true,
    signatures: [],
    assurance_claimed: [],
    verified_claims: [],
    claimed_unverified: [],
    axes: {},
    does_not_assert: [],
    overclaim_risks: [],
    assurance: { axes_with_verified_claims: [] },
    warnings: [],
  };

  const opts: SVIDVerifyOptions = valid.opts;
  assert.doesNotThrow(() => addSVIDClaims(ap, env as Envelope, ev, opts));
  assert.ok(
    !ap.verified_claims.includes("signing_workload_svid_chain_validated"),
    "claim withheld",
  );
  assert.ok(!ap.verified_claims.includes("signing_workload_svid_bound"), "claim withheld");
  assert.ok(
    !ap.verified_claims.includes("signing_workload_svid_valid_at_action_time"),
    "claim withheld",
  );
  assert.ok(
    ap.warnings.some((w) => w.includes("SVID attestation did not verify")),
    "L4 should record a withholding warning",
  );
});

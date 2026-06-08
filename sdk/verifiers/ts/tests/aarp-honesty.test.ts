// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the appraiser honesty mechanics (overclaim_risks + assurance +
// paired negatives). The cross-language corpus gate proves parity on the live
// paths; these lock the branches the corpus cannot reach in v2.7 — chiefly the
// auto-suppression of a risk once its stronger sibling axis is populated (a v2.8
// transparency/deployment/authority claim), which no v2.7 fixture exercises.

import test from "node:test";
import assert from "node:assert/strict";

import {
  AXIS_AUTHORITY,
  AXIS_DEPLOYMENT,
  AXIS_IDENTITY,
  AXIS_INTEGRITY,
  AXIS_TRANSPARENCY,
  type Appraisal,
  CLAIM_RECEIPT_SIGNATURE_VALID,
  CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT,
  CLAIM_SIGNING_WORKLOAD_SVID_BOUND,
  RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
  RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
  RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
  addVerified,
  finalize,
} from "../src/aarp/appraise.js";

function emptyAppraisal(): Appraisal {
  return {
    profile: "aarp/v0.1",
    assertion_signed: false,
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
}

test("overclaim_risks: signature only fires the transparency risk", () => {
  const ap = emptyAppraisal();
  addVerified(ap, CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY);
  finalize(ap);
  assert.deepEqual(ap.overclaim_risks, [RISK_SIGNATURE_VALID_NOT_TRANSPARENCY]);
  assert.deepEqual(ap.assurance.axes_with_verified_claims, [AXIS_INTEGRITY]);
});

test("overclaim_risks: chain link and svid bound fire their risks, sorted", () => {
  const ap = emptyAppraisal();
  addVerified(ap, CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY);
  addVerified(ap, CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT, AXIS_INTEGRITY);
  addVerified(ap, CLAIM_SIGNING_WORKLOAD_SVID_BOUND, AXIS_IDENTITY);
  finalize(ap);
  assert.deepEqual(ap.overclaim_risks, [
    RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
    RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
    RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
  ]);
});

test("overclaim_risks: a populated transparency axis suppresses the transparency risk", () => {
  const ap = emptyAppraisal();
  addVerified(ap, CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY);
  // A future external-witness claim lands on the transparency axis.
  addVerified(ap, "external_witness_checkpoint_signature_valid", AXIS_TRANSPARENCY);
  finalize(ap);
  assert.ok(!ap.overclaim_risks.includes(RISK_SIGNATURE_VALID_NOT_TRANSPARENCY));
});

test("overclaim_risks: a populated deployment axis suppresses the svid deployment risk", () => {
  const ap = emptyAppraisal();
  addVerified(ap, CLAIM_SIGNING_WORKLOAD_SVID_BOUND, AXIS_IDENTITY);
  addVerified(ap, "k8s_pod_spec_proxy_injection_observed", AXIS_DEPLOYMENT);
  finalize(ap);
  assert.ok(!ap.overclaim_risks.includes(RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS));
});

test("overclaim_risks: a populated authority axis suppresses the chain continuity risk", () => {
  const ap = emptyAppraisal();
  addVerified(ap, CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT, AXIS_INTEGRITY);
  addVerified(ap, "receipt_timestamp_contiguous_chain_verified", AXIS_AUTHORITY);
  finalize(ap);
  assert.ok(!ap.overclaim_risks.includes(RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN));
});

test("overclaim_risks: no verified claims yields no risks and no covered axes", () => {
  const ap = emptyAppraisal();
  finalize(ap);
  assert.deepEqual(ap.overclaim_risks, []);
  assert.deepEqual(ap.assurance.axes_with_verified_claims, []);
});

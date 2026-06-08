# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the appraiser honesty mechanics (overclaim_risks + assurance).

The cross-language corpus gate proves parity on the live paths; these lock the
branches the corpus cannot reach in v2.7 — chiefly auto-suppression of a risk once
its stronger sibling axis is populated (a v2.8 transparency/deployment/authority
claim), which no v2.7 fixture exercises.
"""

from __future__ import annotations

from pipelock_aarp_verify.appraise import (
    AXIS_AUTHORITY,
    AXIS_DEPLOYMENT,
    AXIS_IDENTITY,
    AXIS_INTEGRITY,
    AXIS_TRANSPARENCY,
    CLAIM_RECEIPT_SIGNATURE_VALID,
    CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT,
    CLAIM_SIGNING_WORKLOAD_SVID_BOUND,
    RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
    RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
    RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
    Appraisal,
)


def test_signature_only_fires_transparency_risk():
    ap = Appraisal()
    ap.add_verified(CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY)
    ap.finalize()
    assert ap.overclaim_risks == [RISK_SIGNATURE_VALID_NOT_TRANSPARENCY]
    assert ap.assurance.axes_with_verified_claims == [AXIS_INTEGRITY]


def test_chain_and_svid_bound_fire_sorted():
    ap = Appraisal()
    ap.add_verified(CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY)
    ap.add_verified(CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT, AXIS_INTEGRITY)
    ap.add_verified(CLAIM_SIGNING_WORKLOAD_SVID_BOUND, AXIS_IDENTITY)
    ap.finalize()
    assert ap.overclaim_risks == [
        RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN,
        RISK_SIGNATURE_VALID_NOT_TRANSPARENCY,
        RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS,
    ]


def test_populated_transparency_axis_suppresses_risk():
    ap = Appraisal()
    ap.add_verified(CLAIM_RECEIPT_SIGNATURE_VALID, AXIS_INTEGRITY)
    ap.add_verified("external_witness_checkpoint_signature_valid", AXIS_TRANSPARENCY)
    ap.finalize()
    assert RISK_SIGNATURE_VALID_NOT_TRANSPARENCY not in ap.overclaim_risks


def test_populated_deployment_axis_suppresses_svid_risk():
    ap = Appraisal()
    ap.add_verified(CLAIM_SIGNING_WORKLOAD_SVID_BOUND, AXIS_IDENTITY)
    ap.add_verified("k8s_pod_spec_proxy_injection_observed", AXIS_DEPLOYMENT)
    ap.finalize()
    assert RISK_SVID_IDENTITY_NOT_DEPLOYMENT_NON_BYPASS not in ap.overclaim_risks


def test_populated_authority_axis_suppresses_chain_risk():
    ap = Appraisal()
    ap.add_verified(CLAIM_RECEIPT_TIMESTAMP_MONOTONIC_CHAIN_PRESENT, AXIS_INTEGRITY)
    ap.add_verified("receipt_timestamp_contiguous_chain_verified", AXIS_AUTHORITY)
    ap.finalize()
    assert RISK_CHAIN_LINK_NOT_CONTIGUOUS_CHAIN not in ap.overclaim_risks


def test_no_claims_yields_nothing():
    ap = Appraisal()
    ap.finalize()
    assert ap.overclaim_risks == []
    assert ap.assurance.axes_with_verified_claims == []

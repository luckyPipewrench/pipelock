// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecert

import (
	"strings"
	"testing"
)

// A coverage certificate's completeness_status and completeness_reason are a
// coupled pair: the status says how much of the window is accounted for and
// the reason says why. validateCompletenessCoupling is what stops a signed
// certificate from claiming a pair that is not in the vocabulary, for example
// LIMITED/chain_broken, which would understate a broken chain as a mere gap.
//
// This covers the whole invalid class rather than one instance: every status
// paired with a reason belonging to a different status, an out-of-vocabulary
// status, and both directions of the receipt_count coupling.
func TestValidateCompletenessCoupling(t *testing.T) {
	t.Parallel()

	// Reasons grouped by the status that may legitimately carry them.
	limitedReasons := []string{reasonBoundedClosed, reasonAbnormalEnd, reasonOpenAction, reasonHeartbeatGap}
	brokenReasons := []string{reasonChainBroken}
	unverifiedReasons := []string{reasonNoOpen, reasonNoLifecycle, reasonRecorderDisabled, reasonNoReceipts}

	// session returns a coupling-valid session so each case changes exactly
	// one thing. receipt_count is positive except where the case needs zero.
	session := func(status, reason string, receipts uint64) SessionCoverage {
		return SessionCoverage{
			ID:                 "session-001",
			ReceiptCount:       receipts,
			ChainIntact:        status != completenessBroken,
			Anchored:           "local",
			CompletenessStatus: status,
			CompletenessReason: reason,
		}
	}

	t.Run("valid pairs are accepted", func(t *testing.T) {
		t.Parallel()
		for status, reasons := range map[string][]string{
			completenessLimited:    limitedReasons,
			completenessBroken:     brokenReasons,
			completenessUnverified: {reasonNoOpen, reasonNoLifecycle, reasonRecorderDisabled},
		} {
			for _, reason := range reasons {
				if err := validateCompletenessCoupling(session(status, reason, 7)); err != nil {
					t.Errorf("validateCompletenessCoupling(%s/%s) = %v, want nil", status, reason, err)
				}
			}
		}
		// UNVERIFIED/no_receipts is only valid at zero receipts.
		if err := validateCompletenessCoupling(session(completenessUnverified, reasonNoReceipts, 0)); err != nil {
			t.Errorf("validateCompletenessCoupling(UNVERIFIED/no_receipts, 0 receipts) = %v, want nil", err)
		}
	})

	t.Run("a reason belonging to another status is rejected", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			status  string
			reasons []string
			wantErr string
		}{
			{completenessLimited, append(append([]string{}, brokenReasons...), unverifiedReasons...), "LIMITED completeness cannot use reason"},
			{completenessBroken, append(append([]string{}, limitedReasons...), unverifiedReasons...), "BROKEN completeness cannot use reason"},
			{completenessUnverified, append(append([]string{}, limitedReasons...), brokenReasons...), "UNVERIFIED completeness cannot use reason"},
		}
		for _, tc := range cases {
			for _, reason := range tc.reasons {
				err := validateCompletenessCoupling(session(tc.status, reason, 7))
				if err == nil {
					t.Errorf("validateCompletenessCoupling(%s/%s) = nil, want a coupling rejection", tc.status, reason)
					continue
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("validateCompletenessCoupling(%s/%s) = %v, want substring %q", tc.status, reason, err, tc.wantErr)
				}
			}
		}
	})

	t.Run("a status outside the vocabulary is rejected", func(t *testing.T) {
		t.Parallel()
		// Includes COMPLETE, which reads like it should be valid and is not
		// part of this certificate's vocabulary, and an injection-shaped value
		// to confirm the message quotes rather than interpolates it raw.
		for _, status := range []string{"", "COMPLETE", "limited", "OK", "LIMITED\nBROKEN"} {
			err := validateCompletenessCoupling(session(status, reasonBoundedClosed, 7))
			if err == nil {
				t.Errorf("validateCompletenessCoupling(status=%q) = nil, want rejection", status)
				continue
			}
			if !strings.Contains(err.Error(), "not in the coverage certificate vocabulary") {
				t.Errorf("validateCompletenessCoupling(status=%q) = %v, want a vocabulary rejection", status, err)
			}
		}
	})

	t.Run("receipt_count and no_receipts must agree in both directions", func(t *testing.T) {
		t.Parallel()

		// Zero receipts under any reason other than no_receipts: the
		// certificate would claim a verified-ish window it observed nothing in.
		for _, reason := range limitedReasons {
			err := validateCompletenessCoupling(session(completenessLimited, reason, 0))
			if err == nil || !strings.Contains(err.Error(), "zero receipt_count requires UNVERIFIED/no_receipts") {
				t.Errorf("validateCompletenessCoupling(LIMITED/%s, 0 receipts) = %v, want the zero-count rejection", reason, err)
			}
		}

		// The opposite direction: no_receipts while receipts exist would
		// understate evidence that is present.
		err := validateCompletenessCoupling(session(completenessUnverified, reasonNoReceipts, 1))
		if err == nil || !strings.Contains(err.Error(), "cannot have positive receipt_count") {
			t.Errorf("validateCompletenessCoupling(UNVERIFIED/no_receipts, 1 receipt) = %v, want the positive-count rejection", err)
		}
	})
}

// Sign refuses an ill-formed or over-claiming body, so a coupling violation
// must be unsignable end to end and not merely rejected by the internal
// helper. Naming the consumer is the point: a validator nothing calls on the
// signing path would prove nothing.
func TestSignRefusesCompletenessCouplingViolation(t *testing.T) {
	t.Parallel()

	pub, priv := genTestKey(t)

	// Control: the valid fixture signs, so a later refusal is attributable to
	// the coupling violation rather than to the fixture or the key.
	if _, err := Sign(validBody(pub), priv); err != nil {
		t.Fatalf("Sign(validBody) = %v, want a signed certificate", err)
	}

	body := validBody(pub)
	// LIMITED/chain_broken is the understatement that matters: it would
	// present a broken chain as a bounded gap in a signed artifact.
	body.Sessions[0].CompletenessStatus = completenessLimited
	body.Sessions[0].CompletenessReason = reasonChainBroken

	if _, err := Sign(body, priv); err == nil {
		t.Fatal("Sign accepted LIMITED/chain_broken; a signed certificate must not understate a broken chain")
	}
}

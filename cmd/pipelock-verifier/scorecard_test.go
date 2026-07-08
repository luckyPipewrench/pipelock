// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestScorecardCompletenessNeverRendersGreen(t *testing.T) {
	for _, status := range []completeness.Status{
		completeness.StatusLimited,
		completeness.StatusBroken,
		completeness.StatusUnverified,
	} {
		t.Run(string(status), func(t *testing.T) {
			sc := scorecard{
				Schema: scorecardSchema,
				Authentic: scorecardAuthentic{
					Status:              "PASS",
					SelfConsistentCount: 3,
				},
				Untampered: scorecardUntampered{Status: "PASS"},
				Anchored:   scorecardAnchored{Status: "PASS"},
				Completeness: scorecardCompletenessLine{
					Status:             status,
					Reason:             completeness.ReasonNoLifecycle,
					ReceiptCount:       3,
					GapCount:           1,
					CoveredWindowStart: 0,
					CoveredWindowEnd:   2,
					StandingExclusions: []string{
						"mediated evidence cannot prove unmediated egress did not occur",
					},
				},
			}
			var human bytes.Buffer
			emitScorecard(&human, sc)
			completenessLine := scorecardLine(t, human.String(), "Completeness:")
			for _, green := range []string{"COMPLETE", "PASS", " OK"} {
				if strings.Contains(completenessLine, green) {
					t.Fatalf("Completeness line rendered green token %q for status %s:\n%s", green, status, human.String())
				}
			}
			raw, err := json.Marshal(sc)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var decoded struct {
				Completeness struct {
					Status completeness.Status `json:"status"`
				} `json:"completeness"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if decoded.Completeness.Status != status {
				t.Fatalf("JSON completeness.status = %q, want %q", decoded.Completeness.Status, status)
			}
			if decoded.Completeness.Status == "COMPLETE" || decoded.Completeness.Status == "PASS" {
				t.Fatalf("JSON completeness.status rendered green: %q", decoded.Completeness.Status)
			}
		})
	}
}

func TestNewActionScorecardStatusMapping(t *testing.T) {
	report := completeness.Report{
		Status:       completeness.StatusLimited,
		Reason:       completeness.ReasonBoundedClosed,
		ReceiptCount: 3,
		FinalSeq:     2,
		Runs: []completeness.RunReport{
			{UnmatchedIntents: 2},
			{HeartbeatGapDetected: true},
		},
	}
	tests := []struct {
		name              string
		res               actionreceipt.ChainResult
		keyPinned         bool
		wantAuthentic     string
		wantAuthenticNote string
		wantUntampered    string
		wantBrokenSeq     uint64
		wantReason        string
	}{
		{
			name:           "valid_pinned",
			res:            actionreceipt.ChainResult{Valid: true, ReceiptCount: 3},
			keyPinned:      true,
			wantAuthentic:  "PASS",
			wantUntampered: "PASS",
		},
		{
			name:              "unpinned_is_authentic_unverified",
			res:               actionreceipt.ChainResult{Valid: true, ReceiptCount: 3},
			keyPinned:         false,
			wantAuthentic:     "UNVERIFIED",
			wantAuthenticNote: "no trusted signer key pinned",
			wantUntampered:    "PASS",
		},
		{
			name: "integrity_verified_lifecycle_failure_still_untampered",
			res: actionreceipt.ChainResult{
				IntegrityVerified: true,
				ReceiptCount:      3,
				Error:             "lifecycle incomplete",
			},
			keyPinned:      true,
			wantAuthentic:  "PASS",
			wantUntampered: "PASS",
		},
		{
			name: "broken_chain_fails_untampered",
			res: actionreceipt.ChainResult{
				ReceiptCount:  3,
				BrokenAtSeq:   2,
				Error:         "hash link mismatch",
				FailureKind:   actionreceipt.ChainFailureIntegrity,
				BrokenAtIndex: 2,
			},
			keyPinned:      true,
			wantAuthentic:  "FAIL",
			wantUntampered: "FAIL",
			wantBrokenSeq:  2,
			wantReason:     "hash link mismatch",
		},
		{
			name: "broken_chain_unpinned_authentic_unverified",
			res: actionreceipt.ChainResult{
				ReceiptCount:  3,
				BrokenAtSeq:   2,
				Error:         "hash link mismatch",
				FailureKind:   actionreceipt.ChainFailureIntegrity,
				BrokenAtIndex: 2,
			},
			keyPinned:         false,
			wantAuthentic:     "UNVERIFIED",
			wantAuthenticNote: "no trusted signer key pinned",
			wantUntampered:    "FAIL",
			wantBrokenSeq:     2,
			wantReason:        "hash link mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := newActionScorecard(tt.res, tt.keyPinned, report)
			if sc.Schema != scorecardSchema {
				t.Fatalf("schema = %q, want %q", sc.Schema, scorecardSchema)
			}
			if sc.Authentic.Status != tt.wantAuthentic {
				t.Fatalf("authentic status = %q, want %q", sc.Authentic.Status, tt.wantAuthentic)
			}
			if sc.Authentic.Detail != tt.wantAuthenticNote {
				t.Fatalf("authentic detail = %q, want %q", sc.Authentic.Detail, tt.wantAuthenticNote)
			}
			if sc.Untampered.Status != tt.wantUntampered {
				t.Fatalf("untampered status = %q, want %q", sc.Untampered.Status, tt.wantUntampered)
			}
			if sc.Untampered.BrokenAtSeq != tt.wantBrokenSeq || sc.Untampered.Reason != tt.wantReason {
				t.Fatalf("untampered detail = (%d, %q), want (%d, %q)",
					sc.Untampered.BrokenAtSeq,
					sc.Untampered.Reason,
					tt.wantBrokenSeq,
					tt.wantReason,
				)
			}
			if sc.Anchored.Status != "UNVERIFIED" || sc.Anchored.Detail != "no anchor bundle supplied" {
				t.Fatalf("anchored = %+v, want no-bundle UNVERIFIED", sc.Anchored)
			}
			if sc.Completeness.GapCount != 2 || sc.Completeness.HeartbeatContinuity != "gap_detected" {
				t.Fatalf("completeness = %+v, want gaps=2 heartbeat gap", sc.Completeness)
			}
		})
	}
}

func scorecardLine(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("scorecard output missing %q line:\n%s", prefix, out)
	return ""
}

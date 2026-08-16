// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestURLResultToFindingsAllowVsBlock(t *testing.T) {
	t.Parallel()

	if got := urlResultToFindings(scanner.Result{Allowed: true, Scanner: scanner.ScannerDLP}); got != nil {
		t.Fatalf("allowed result findings = %+v, want nil", got)
	}
	got := urlResultToFindings(scanner.Result{Allowed: false, Scanner: scanner.ScannerSSRF})
	if len(got) != 1 || got[0].Kind != capture.KindDLP || got[0].PatternName != scanner.ScannerSSRF || got[0].Action != config.ActionBlock {
		t.Fatalf("blocked findings = %+v", got)
	}
}

func TestCeeResultToFindingsEntropyAndFragment(t *testing.T) {
	t.Parallel()

	got := ceeResultToFindings(ceeResult{EntropyHit: true, FragmentHit: true})
	if len(got) != 2 || got[0].Kind != capture.KindCEE || got[1].Kind != capture.KindCEE {
		t.Fatalf("entropy+fragment findings = %+v, want two CEE blocks", got)
	}
	if got := ceeResultToFindings(ceeResult{Blocked: true}); len(got) != 0 {
		t.Fatalf("blocked-without-hit findings = %+v, want empty", got)
	}
}

func TestCaptureOutcomeActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action string
		clean  bool
		want   string
	}{
		{"clean ignores action", config.ActionBlock, true, capture.OutcomeClean},
		{"block", config.ActionBlock, false, capture.OutcomeBlocked},
		{"warn", config.ActionWarn, false, capture.OutcomeWarned},
		{"strip", config.ActionStrip, false, capture.OutcomeStripped},
		{"redirect", config.ActionRedirect, false, capture.OutcomeRedirected},
		{"allow", config.ActionAllow, false, capture.OutcomeClean},
		{"forward", config.ActionForward, false, capture.OutcomeClean},
		{"unknown fail closed", "not-an-action", false, capture.OutcomeBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := captureOutcome(tt.action, tt.clean); got != tt.want {
				t.Fatalf("captureOutcome(%q, %v) = %q, want %q", tt.action, tt.clean, got, tt.want)
			}
		})
	}
}

func TestResponseMatchesToFindingsEmptyAndMapped(t *testing.T) {
	t.Parallel()

	if got := responseMatchesToFindings(nil, config.ActionStrip); got != nil {
		t.Fatalf("empty matches = %+v, want nil", got)
	}
	got := responseMatchesToFindings([]scanner.ResponseMatch{{
		PatternName: "Prompt Injection",
		MatchText:   "ignore previous",
	}}, config.ActionStrip)
	if len(got) != 1 || got[0].Kind != capture.KindInjection || got[0].Action != config.ActionStrip || got[0].MatchText != "ignore previous" {
		t.Fatalf("mapped findings = %+v", got)
	}
}

func TestBodyScanToFindingsCleanAndMixed(t *testing.T) {
	t.Parallel()

	if got := bodyScanToFindings(BodyScanResult{Clean: true, DLPMatches: []scanner.TextDLPMatch{{PatternName: "x"}}}); got != nil {
		t.Fatalf("clean body findings = %+v, want nil", got)
	}
	got := bodyScanToFindings(BodyScanResult{
		Clean:            false,
		Action:           config.ActionBlock,
		DLPMatches:       []scanner.TextDLPMatch{{PatternName: "AWS Access ID", Severity: "high"}},
		InjectionMatches: []scanner.ResponseMatch{{PatternName: "Prompt Injection", MatchText: "ignore"}},
		EntropyFinding:   &ContentEntropyFinding{},
	})
	if len(got) != 3 {
		t.Fatalf("mixed findings = %+v, want 3", got)
	}
	if got[0].Kind != capture.KindDLP || got[1].Kind != capture.KindInjection || got[2].Kind != capture.KindContentEntropy {
		t.Fatalf("kinds = %+v", got)
	}
	if got[2].Action != config.ActionBlock || got[2].PatternName != scannerLabelBodyEntropy {
		t.Fatalf("entropy finding = %+v", got[2])
	}
}
